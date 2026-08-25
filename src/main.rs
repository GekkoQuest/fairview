use clap::Parser;
use fairview::{report, Config, Session};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(
    name = "fairview",
    version,
    about = "Interview monitoring agent: collect OS evidence and evaluate it against a session policy"
)]
struct Cli {
    /// Path to TOML config. Created with defaults if missing.
    #[arg(short, long, default_value = "fairview_config.toml")]
    config: PathBuf,

    /// Run a single scan and exit.
    #[arg(long)]
    once: bool,

    /// Write the report JSON to stdout instead of (or in addition to) a file.
    #[arg(long)]
    json: bool,

    /// Override output directory for JSON reports.
    #[arg(long)]
    output_dir: Option<PathBuf>,

    /// Override scan interval in seconds.
    #[arg(long)]
    interval: Option<u64>,

    /// Skip baseline capture (every process looks "new").
    #[arg(long)]
    no_baseline: bool,

    /// Do not treat a VM guest as unexpected.
    #[arg(long)]
    allow_vm: bool,

    /// Extra expected process image names (repeatable).
    #[arg(long = "expect")]
    expect: Vec<String>,
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_target(false)
        .init();

    let cli = Cli::parse();
    let mut config = load_config(&cli.config);

    if let Some(interval) = cli.interval {
        config.scan.interval_seconds = interval.max(1);
    }
    if cli.allow_vm {
        config.session.allow_vm_guest = true;
    }
    config.session.expected_processes.extend(cli.expect);
    if let Some(dir) = cli.output_dir {
        config.output.directory = dir.to_string_lossy().into_owned();
    }

    if let Err(e) = config.validate() {
        eprintln!("invalid config: {e}");
        std::process::exit(2);
    }

    let running = Arc::new(AtomicBool::new(true));
    {
        let running = running.clone();
        let _ = ctrlc::set_handler(move || {
            running.store(false, Ordering::SeqCst);
        });
    }

    let mut session = Session::new(config.clone());
    if !cli.no_baseline {
        session.collect_baseline();
    }

    loop {
        if !running.load(Ordering::SeqCst) {
            tracing::info!("stopping");
            break;
        }

        let report = session.scan();
        if cli.json {
            match serde_json::to_string_pretty(&report) {
                Ok(json) => println!("{json}"),
                Err(e) => tracing::error!("serialize report: {e}"),
            }
        } else {
            report::print_human(&report);
        }

        if config.output.write_json {
            match report.write_json(PathBuf::from(&config.output.directory).as_path()) {
                Ok(path) => tracing::info!("wrote {}", path.display()),
                Err(e) => tracing::warn!("failed to write report: {e}"),
            }
        }

        if cli.once {
            let code = if report.evaluation.alert { 1 } else { 0 };
            std::process::exit(code);
        }

        std::thread::sleep(Duration::from_secs(config.scan.interval_seconds));
    }
}

fn load_config(path: &PathBuf) -> Config {
    match Config::from_file(path) {
        Ok(cfg) => {
            tracing::info!("loaded config {}", path.display());
            cfg
        }
        Err(e) => {
            tracing::warn!(
                "no usable config ({e}); writing defaults to {}",
                path.display()
            );
            let cfg = Config::default();
            if let Err(e) = cfg.save_to_file(path) {
                tracing::warn!("could not write default config: {e}");
            }
            cfg
        }
    }
}
