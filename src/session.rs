use crate::config::Config;
use crate::detect::Collectors;
use crate::evidence::DisplayInfo;
use crate::policy;
use crate::process::ProcessBaseline;
use crate::report::Report;

pub struct Session {
    config: Config,
    collectors: Collectors,
    process_baseline: Option<ProcessBaseline>,
    display_baseline: Option<Vec<DisplayInfo>>,
    scan_number: u32,
}

impl Session {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            collectors: Collectors::new(),
            process_baseline: None,
            display_baseline: None,
            scan_number: 0,
        }
    }

    pub fn collect_baseline(&mut self) {
        tracing::info!("collecting baseline");
        let snap = self.collectors.collect(&self.config, None, None);
        self.process_baseline = Some(ProcessBaseline::from_snapshots(&snap.process_snapshots));
        self.display_baseline = Some(snap.inventory.displays.clone());
        tracing::info!(
            processes = snap.process_snapshots.len(),
            displays = snap.inventory.displays.len(),
            "baseline captured"
        );
    }

    pub fn scan(&mut self) -> Report {
        self.scan_number += 1;
        let snap = self.collectors.collect(
            &self.config,
            self.process_baseline.as_ref(),
            self.display_baseline.as_deref(),
        );

        let evaluation = policy::evaluate(&self.config, snap.findings);
        Report::new(
            self.scan_number,
            snap.inventory,
            snap.overlays,
            evaluation,
            snap.errors,
        )
    }

    pub fn config(&self) -> &Config {
        &self.config
    }
}
