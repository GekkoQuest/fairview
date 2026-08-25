//! Correlate weak atoms that share a PID into a behavior cluster.
//!
//! EDR practice: isolated telemetry is noise; independent *classes* of
//! behavior on one process are the detection. Origin (unsigned / user path /
//! rename / new) is one class, stealth overlay another, unexpected capture a
//! third. Two origin atoms do not count as two classes.

use crate::config::Config;
use crate::evidence::{Detector, Finding, ProcessRef, Severity};
use crate::origin;
use std::collections::{BTreeSet, HashMap};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum BehaviorClass {
    Origin,
    Overlay,
    Capture,
}

fn class_of(signal: &str) -> Option<BehaviorClass> {
    match signal {
        "process.unsigned"
        | "process.untrusted_signature"
        | "process.user_writable_path"
        | "process.name_mismatch"
        | "process.started_after_baseline" => Some(BehaviorClass::Origin),
        "overlay.exclude_from_capture"
        | "overlay.click_through_topmost"
        | "overlay.layered_tool_window"
        | "overlay.high_layer_transparent" => Some(BehaviorClass::Overlay),
        "audio.capture" => Some(BehaviorClass::Capture),
        _ => None,
    }
}

fn stealth_overlay(signal: &str) -> bool {
    matches!(
        signal,
        "overlay.exclude_from_capture" | "overlay.click_through_topmost"
    )
}

fn skip_process(config: &Config, name: &str, has_stealth_overlay: bool) -> bool {
    if has_stealth_overlay {
        return false;
    }
    origin::is_routine(config, name)
}

/// Consume the current finding list and append at most one cluster per PID.
pub fn correlate(config: &Config, findings: &[Finding]) -> Vec<Finding> {
    if !config.monitoring.behavior {
        return Vec::new();
    }

    struct Bucket {
        pref: ProcessRef,
        signals: BTreeSet<String>,
        classes: BTreeSet<BehaviorClass>,
        stealth: bool,
    }

    let mut by_pid: HashMap<u32, Bucket> = HashMap::new();

    for f in findings {
        // Known-bad catalog hits are already high/critical; don't cluster them.
        if matches!(
            f.signal.as_str(),
            "process.interview_assistant" | "process.remote_tool" | "process.virtual_display_tool"
        ) {
            continue;
        }
        let Some(class) = class_of(&f.signal) else {
            continue;
        };
        let Some(pref) = f.process.clone() else {
            continue;
        };
        if class == BehaviorClass::Capture && origin::is_routine(config, &pref.name) {
            continue;
        }
        let bucket = by_pid.entry(pref.pid).or_insert_with(|| Bucket {
            pref: pref.clone(),
            signals: BTreeSet::new(),
            classes: BTreeSet::new(),
            stealth: false,
        });
        bucket.signals.insert(f.signal.clone());
        bucket.classes.insert(class);
        if stealth_overlay(&f.signal) {
            bucket.stealth = true;
        }
    }

    let mut out = Vec::new();
    for (_pid, bucket) in by_pid {
        if skip_process(config, &bucket.pref.name, bucket.stealth) {
            continue;
        }
        let n = bucket.classes.len();
        if n < 2 {
            continue;
        }

        let (severity, confidence) = if bucket.stealth && n >= 2 {
            (Severity::High, 0.82)
        } else if n >= 3 {
            (Severity::High, 0.78)
        } else if bucket.classes.contains(&BehaviorClass::Overlay)
            && bucket.classes.contains(&BehaviorClass::Origin)
        {
            (Severity::Medium, 0.65)
        } else if bucket.classes.contains(&BehaviorClass::Capture)
            && bucket.classes.contains(&BehaviorClass::Origin)
        {
            (Severity::Medium, 0.62)
        } else {
            (Severity::Medium, 0.55)
        };

        let class_list: Vec<&str> = bucket
            .classes
            .iter()
            .map(|c| match c {
                BehaviorClass::Origin => "origin",
                BehaviorClass::Overlay => "overlay",
                BehaviorClass::Capture => "capture",
            })
            .collect();
        let signals: Vec<&str> = bucket.signals.iter().map(|s| s.as_str()).collect();

        out.push(
            Finding::new(
                Detector::Process,
                "process.behavior_cluster",
                severity,
                confidence,
                format!(
                    "{} independent behavior classes on {} (pid {}): {}",
                    n,
                    bucket.pref.name,
                    bucket.pref.pid,
                    class_list.join("+")
                ),
            )
            .detail("classes", class_list.join(","))
            .detail("signals", signals.join(","))
            .with_process(bucket.pref),
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::ProcessRef;

    fn pref(pid: u32, name: &str) -> ProcessRef {
        ProcessRef {
            pid,
            name: name.into(),
            path: Some(format!(r"C:\Users\a\{name}")),
        }
    }

    fn atom(signal: &str, pid: u32, name: &str) -> Finding {
        Finding::new(Detector::Process, signal, Severity::Low, 0.4, signal)
            .with_process(pref(pid, name))
    }

    fn overlay(signal: &str, pid: u32, name: &str) -> Finding {
        Finding::new(Detector::Overlay, signal, Severity::High, 0.85, signal)
            .with_process(pref(pid, name))
    }

    fn audio(pid: u32, name: &str) -> Finding {
        Finding::new(Detector::Audio, "audio.capture", Severity::Low, 0.7, "mic")
            .with_process(pref(pid, name))
    }

    #[test]
    fn two_origin_atoms_are_one_class_no_cluster() {
        let cfg = Config::default();
        let f = vec![
            atom("process.unsigned", 9, "helper.exe"),
            atom("process.user_writable_path", 9, "helper.exe"),
            atom("process.started_after_baseline", 9, "helper.exe"),
        ];
        assert!(correlate(&cfg, &f).is_empty());
    }

    #[test]
    fn stealth_overlay_plus_origin_is_high() {
        let cfg = Config::default();
        let f = vec![
            overlay("overlay.click_through_topmost", 9, "helper.exe"),
            atom("process.unsigned", 9, "helper.exe"),
        ];
        let c = correlate(&cfg, &f);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].signal, "process.behavior_cluster");
        assert_eq!(c[0].severity, Severity::High);
        assert!(c[0].details.get("classes").unwrap().contains("overlay"));
        assert!(c[0].details.get("classes").unwrap().contains("origin"));
    }

    #[test]
    fn unexpected_mic_plus_unsigned_new_is_medium() {
        let cfg = Config::default();
        let f = vec![
            audio(11, "helper.exe"),
            atom("process.unsigned", 11, "helper.exe"),
            atom("process.started_after_baseline", 11, "helper.exe"),
        ];
        let c = correlate(&cfg, &f);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].severity, Severity::Medium);
    }

    #[test]
    fn zoom_mic_does_not_cluster() {
        let cfg = Config::default();
        let f = vec![
            audio(4, "zoom.exe"),
            atom("process.started_after_baseline", 4, "zoom.exe"),
        ];
        assert!(correlate(&cfg, &f).is_empty());
    }

    #[test]
    fn three_classes_high() {
        let cfg = Config::default();
        let f = vec![
            overlay("overlay.layered_tool_window", 3, "helper.exe"),
            audio(3, "helper.exe"),
            atom("process.user_writable_path", 3, "helper.exe"),
        ];
        let c = correlate(&cfg, &f);
        assert_eq!(c[0].severity, Severity::High);
    }

    #[test]
    fn catalog_hit_not_clustered() {
        let cfg = Config::default();
        let f = vec![
            Finding::new(
                Detector::Process,
                "process.interview_assistant",
                Severity::Critical,
                0.95,
                "cluely",
            )
            .with_process(pref(1, "cluely.exe")),
            overlay("overlay.click_through_topmost", 1, "cluely.exe"),
        ];
        // Overlay still clusters with... only overlay, assistant skipped, so no 2nd class
        // unless we also have origin. Overlay alone is not a cluster.
        assert!(correlate(&cfg, &f).is_empty());
    }

    #[test]
    fn disabled_in_config() {
        let mut cfg = Config::default();
        cfg.monitoring.behavior = false;
        let f = vec![
            overlay("overlay.click_through_topmost", 9, "helper.exe"),
            atom("process.unsigned", 9, "helper.exe"),
        ];
        assert!(correlate(&cfg, &f).is_empty());
    }
}
