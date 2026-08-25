use crate::config::Config;
use crate::evidence::{Finding, Severity};
use crate::known;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct Evaluation {
    pub highest_severity: Severity,
    pub alert: bool,
    pub unexpected: Vec<Finding>,
    pub informational: Vec<Finding>,
    pub summary: String,
}

pub fn evaluate(config: &Config, findings: Vec<Finding>) -> Evaluation {
    let mut unexpected = Vec::new();
    let mut informational = Vec::new();

    for f in findings {
        if is_expected(config, &f) {
            informational.push(f);
        } else {
            unexpected.push(f);
        }
    }

    unexpected.sort_by(|a, b| {
        b.severity.cmp(&a.severity).then(
            b.confidence
                .partial_cmp(&a.confidence)
                .unwrap_or(std::cmp::Ordering::Equal),
        )
    });

    let highest = unexpected
        .iter()
        .map(|f| f.severity)
        .max()
        .unwrap_or(Severity::Info);
    let alert = !unexpected.is_empty() && highest >= config.alert_level();

    let summary = if unexpected.is_empty() {
        "No unexpected findings.".into()
    } else {
        let n = unexpected.len();
        format!(
            "{n} unexpected finding{} (highest: {})",
            if n == 1 { "" } else { "s" },
            highest.as_str()
        )
    };

    Evaluation {
        highest_severity: highest,
        alert,
        unexpected,
        informational,
        summary,
    }
}

fn is_expected(config: &Config, finding: &Finding) -> bool {
    match finding.signal.as_str() {
        "environment.guest" => config.session.allow_vm_guest,
        "environment.root_hypervisor" | "environment.inventory" => true,
        "display.virtual" | "display.dummy_edid" => false,
        "camera.virtual" => config.session.allow_virtual_camera,
        "audio.capture" => audio_is_expected(config, finding),
        "process.behavior_cluster" => false,
        _ => false,
    }
}

fn audio_is_expected(config: &Config, finding: &Finding) -> bool {
    let Some(proc) = &finding.process else {
        return false;
    };
    if config.is_expected_name(&proc.name) {
        return true;
    }
    config.session.assume_meeting_apps && known::is_meeting_app(&proc.name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::{Detector, Finding, ProcessRef};

    #[test]
    fn zoom_mic_is_expected_by_default() {
        let cfg = Config::default();
        let f = Finding::new(Detector::Audio, "audio.capture", Severity::Low, 0.5, "mic")
            .with_process(ProcessRef {
                pid: 1,
                name: "zoom.exe".into(),
                path: None,
            });
        let ev = evaluate(&cfg, vec![f]);
        assert!(ev.unexpected.is_empty());
        assert_eq!(ev.informational.len(), 1);
        assert!(!ev.alert);
    }

    #[test]
    fn helper_mic_is_not_expected() {
        let cfg = Config::default();
        let f = Finding::new(
            Detector::Audio,
            "audio.capture",
            Severity::Medium,
            0.8,
            "mic",
        )
        .with_process(ProcessRef {
            pid: 9,
            name: "helper.exe".into(),
            path: None,
        });
        let ev = evaluate(&cfg, vec![f]);
        assert_eq!(ev.unexpected.len(), 1);
        assert!(ev.alert);
    }

    #[test]
    fn hyperv_root_is_informational() {
        let cfg = Config::default();
        let f = Finding::new(
            Detector::Environment,
            "environment.root_hypervisor",
            Severity::Info,
            1.0,
            "VBS",
        );
        let ev = evaluate(&cfg, vec![f]);
        assert!(ev.unexpected.is_empty());
    }

    #[test]
    fn guest_vm_unexpected_unless_allowed() {
        let mut cfg = Config::default();
        let f = Finding::new(
            Detector::Environment,
            "environment.guest",
            Severity::Medium,
            0.9,
            "guest",
        );
        assert!(!evaluate(&cfg, vec![f.clone()]).unexpected.is_empty());
        cfg.session.allow_vm_guest = true;
        assert!(evaluate(&cfg, vec![f]).unexpected.is_empty());
    }

    #[test]
    fn behavior_cluster_is_never_expected() {
        let cfg = Config::default();
        let f = Finding::new(
            Detector::Process,
            "process.behavior_cluster",
            Severity::High,
            0.8,
            "cluster",
        )
        .with_process(ProcessRef {
            pid: 9,
            name: "helper.exe".into(),
            path: None,
        });
        let ev = evaluate(&cfg, vec![f]);
        assert_eq!(ev.unexpected.len(), 1);
        assert!(ev.alert);
    }
}
