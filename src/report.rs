use crate::evidence::{Finding, Inventory, OverlayWindow, Severity};
use crate::policy::Evaluation;
use chrono::{DateTime, Utc};
use serde::Serialize;
use std::path::Path;

#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub schema_version: u32,
    pub scan_number: u32,
    pub timestamp: DateTime<Utc>,
    pub inventory: Inventory,
    pub overlays: Vec<OverlayWindow>,
    pub findings: Vec<Finding>,
    pub evaluation: Evaluation,
    pub errors: Vec<String>,
}

impl Report {
    pub fn new(
        scan_number: u32,
        inventory: Inventory,
        overlays: Vec<OverlayWindow>,
        evaluation: Evaluation,
        errors: Vec<String>,
    ) -> Self {
        let mut findings = evaluation.unexpected.clone();
        findings.extend(evaluation.informational.clone());
        Self {
            schema_version: 1,
            scan_number,
            timestamp: Utc::now(),
            inventory,
            overlays,
            findings,
            evaluation,
            errors,
        }
    }

    pub fn write_json(&self, dir: &Path) -> crate::error::Result<std::path::PathBuf> {
        std::fs::create_dir_all(dir)?;
        let name = format!(
            "fairview_{}_{:04}.json",
            self.timestamp.format("%Y%m%d_%H%M%S"),
            self.scan_number
        );
        let path = dir.join(name);
        std::fs::write(&path, serde_json::to_string_pretty(self)?)?;
        Ok(path)
    }
}

pub fn print_human(report: &Report) {
    println!("{}", "=".repeat(64));
    println!(
        "FAIRVIEW  scan #{}  {}",
        report.scan_number,
        report.timestamp.format("%Y-%m-%d %H:%M:%S UTC")
    );
    println!("{}", "=".repeat(64));

    if let Some(env) = &report.inventory.environment {
        println!(
            "Environment: {:?}  hypervisor={:?}",
            env.kind, env.hypervisor_vendor
        );
    }
    println!("Displays: {}", report.inventory.displays.len());
    for d in &report.inventory.displays {
        let edid = d
            .edid
            .as_ref()
            .map(|e| format!("{} {:04X}", e.manufacturer, e.product_code))
            .unwrap_or_else(|| "no-edid".into());
        println!(
            "  - {}  {:?}  {}x{}  {}",
            d.name, d.connector, d.width, d.height, edid
        );
    }
    if report.inventory.remote_session {
        println!("Remote session: yes (this OS session is remoted)");
    }

    println!();
    println!("Evaluation: {}", report.evaluation.summary);
    if report.evaluation.alert {
        println!(
            "ALERT: threshold reached ({})",
            report.evaluation.highest_severity.as_str()
        );
    }

    if !report.errors.is_empty() {
        println!("\nCollector errors:");
        for e in &report.errors {
            println!("  ! {e}");
        }
    }

    print_group("UNEXPECTED", &report.evaluation.unexpected);
    print_group("INFORMATIONAL", &report.evaluation.informational);
    println!("{}\n", "=".repeat(64));
}

fn print_group(title: &str, findings: &[Finding]) {
    if findings.is_empty() {
        return;
    }
    println!("\n{title}:");
    for f in findings {
        let mark = match f.severity {
            Severity::Critical | Severity::High => "!",
            Severity::Medium => "*",
            Severity::Low | Severity::Info => "-",
        };
        println!(
            "  {mark} [{:>8}] {:<32}  {}",
            f.severity.as_str(),
            f.signal,
            f.summary
        );
        if let Some(p) = &f.process {
            println!("      process: {} pid {}", p.name, p.pid);
        }
    }
}
