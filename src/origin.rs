//! Process *origin* atoms: where the image lives, whether it is signed,
//! and whether the on-disk name matches OriginalFilename.
//!
//! These are weak alone (AV reputation). They become useful when a correlator
//! joins them with overlay/capture behavior on the same PID.

use crate::config::Config;
use crate::evidence::{Detector, Finding, ProcessRef, ProcessSnapshot, Severity};
use crate::known;
use crate::process::ProcessBaseline;
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PathZone {
    System,
    UserWritable,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureStatus {
    Trusted,
    Unsigned,
    Untrusted,
    Unknown,
}

pub fn classify_path(path: &str) -> PathZone {
    if path.is_empty() || path.eq_ignore_ascii_case("unknown") {
        return PathZone::Other;
    }
    let n = path.replace('/', "\\").to_ascii_lowercase();

    // Windows system / vendor install locations.
    if n.contains("\\windows\\")
        || n.contains("\\program files\\")
        || n.contains("\\program files (x86)\\")
        || n.starts_with("c:\\program files")
    {
        return PathZone::System;
    }
    // User-writable Windows locations (including Local\Temp under AppData).
    if n.contains("\\appdata\\")
        || n.contains("\\downloads\\")
        || n.contains("\\desktop\\")
        || n.contains("\\documents\\")
        || n.contains("\\temp\\")
        || n.contains("\\users\\") && n.contains("\\local\\")
    {
        return PathZone::UserWritable;
    }

    // POSIX
    let posix = path.replace('\\', "/").to_ascii_lowercase();
    if posix.starts_with("/usr/")
        || posix.starts_with("/bin/")
        || posix.starts_with("/sbin/")
        || posix.starts_with("/lib/")
        || posix.starts_with("/opt/")
        || posix.starts_with("/system/")
        || posix.starts_with("/applications/")
        || posix.starts_with("/library/")
    {
        return PathZone::System;
    }
    if posix.starts_with("/tmp/")
        || posix.starts_with("/var/tmp/")
        || posix.starts_with("/home/")
        || posix.starts_with("/users/")
        || posix.contains("/library/application support/")
        || posix.contains("/downloads/")
    {
        return PathZone::UserWritable;
    }

    PathZone::Other
}

pub fn name_mismatch(proc: &ProcessSnapshot) -> bool {
    let Some(orig) = proc.original_filename.as_deref() else {
        return false;
    };
    if orig.is_empty() {
        return false;
    }
    let have = known::normalize_image_name(&proc.name);
    let claimed = known::normalize_image_name(orig);
    if have.is_empty() || claimed.is_empty() {
        return false;
    }
    have != claimed
}

pub fn is_routine(config: &Config, name: &str) -> bool {
    known::is_os_noise(name)
        || known::is_browser(name)
        || known::is_editor(name)
        || known::is_meeting_app(name)
        || config.is_expected_name(name)
}

/// PIDs that already have a non-origin finding, plus images that appeared
/// after baseline. Signature checks are limited to this set.
pub fn candidate_pids(
    config: &Config,
    procs: &[ProcessSnapshot],
    baseline: Option<&ProcessBaseline>,
    findings: &[Finding],
) -> HashSet<u32> {
    let mut pids = HashSet::new();
    for f in findings {
        if let Some(p) = &f.process {
            if !is_routine(config, &p.name) || finding_is_stealth(f) {
                pids.insert(p.pid);
            }
        }
    }
    if let Some(base) = baseline {
        for proc in procs {
            if is_routine(config, &proc.name) {
                continue;
            }
            if base.is_new(proc) {
                pids.insert(proc.pid);
            }
        }
    }
    pids
}

fn finding_is_stealth(f: &Finding) -> bool {
    matches!(
        f.signal.as_str(),
        "overlay.exclude_from_capture"
            | "overlay.click_through_topmost"
            | "overlay.layered_tool_window"
            | "overlay.high_layer_transparent"
    )
}

pub fn analyze(
    config: &Config,
    procs: &[ProcessSnapshot],
    candidates: &HashSet<u32>,
    signatures: &HashMap<String, SignatureStatus>,
) -> Vec<Finding> {
    let mut out = Vec::new();
    for proc in procs {
        if !candidates.contains(&proc.pid) {
            continue;
        }
        if known::is_os_noise(&proc.name) {
            continue;
        }
        // Expected meeting/editor/browser images: only emit origin if they
        // were pulled in as stealth-overlay candidates.
        let routine = is_routine(config, &proc.name);

        let pref = ProcessRef {
            pid: proc.pid,
            name: proc.name.clone(),
            path: if proc.path.is_empty() {
                None
            } else {
                Some(proc.path.clone())
            },
        };

        let zone = classify_path(&proc.path);
        if zone == PathZone::UserWritable && !routine {
            out.push(
                Finding::new(
                    Detector::Process,
                    "process.user_writable_path",
                    Severity::Low,
                    0.45,
                    format!("{} is running from a user-writable location", proc.name),
                )
                .detail("path", proc.path.clone())
                .detail("zone", "user_writable")
                .with_process(pref.clone()),
            );
        }

        if name_mismatch(proc) {
            out.push(
                Finding::new(
                    Detector::Process,
                    "process.name_mismatch",
                    Severity::Medium,
                    0.7,
                    format!(
                        "{} on disk claims OriginalFilename {}",
                        proc.name,
                        proc.original_filename.as_deref().unwrap_or("?")
                    ),
                )
                .detail(
                    "original_filename",
                    proc.original_filename.clone().unwrap_or_default(),
                )
                .with_process(pref.clone()),
            );
        }

        if proc.path.is_empty() {
            continue;
        }
        let key = signature_key(&proc.path);
        match signatures
            .get(&key)
            .copied()
            .unwrap_or(SignatureStatus::Unknown)
        {
            SignatureStatus::Unsigned if !routine => {
                out.push(
                    Finding::new(
                        Detector::Process,
                        "process.unsigned",
                        Severity::Low,
                        0.5,
                        format!("{} has no Authenticode signature", proc.name),
                    )
                    .detail("path", proc.path.clone())
                    .with_process(pref.clone()),
                );
            }
            SignatureStatus::Untrusted if !routine && zone == PathZone::UserWritable => {
                out.push(
                    Finding::new(
                        Detector::Process,
                        "process.untrusted_signature",
                        Severity::Low,
                        0.4,
                        format!("{} is signed but the signature did not verify", proc.name),
                    )
                    .detail("path", proc.path.clone())
                    .with_process(pref),
                );
            }
            _ => {}
        }
    }
    out
}

pub fn signature_key(path: &str) -> String {
    path.replace('/', "\\").to_ascii_lowercase()
}

pub fn paths_needing_signature<'a>(
    procs: &'a [ProcessSnapshot],
    candidates: &HashSet<u32>,
) -> Vec<&'a Path> {
    procs
        .iter()
        .filter(|p| candidates.contains(&p.pid) && !p.path.is_empty())
        .map(|p| Path::new(p.path.as_str()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_system32_is_system() {
        assert_eq!(
            classify_path(r"C:\Windows\System32\svchost.exe"),
            PathZone::System
        );
        assert_eq!(
            classify_path(r"C:\Program Files\Google\Chrome\Application\chrome.exe"),
            PathZone::System
        );
    }

    #[test]
    fn appdata_and_downloads_are_user() {
        assert_eq!(
            classify_path(r"C:\Users\a\AppData\Local\Programs\helper\helper.exe"),
            PathZone::UserWritable
        );
        assert_eq!(
            classify_path(r"C:\Users\a\Downloads\tool.exe"),
            PathZone::UserWritable
        );
        assert_eq!(
            classify_path(r"C:\Users\a\AppData\Local\Temp\foo.exe"),
            PathZone::UserWritable
        );
    }

    #[test]
    fn posix_zones() {
        assert_eq!(classify_path("/usr/bin/zoom"), PathZone::System);
        assert_eq!(classify_path("/tmp/cluely"), PathZone::UserWritable);
        assert_eq!(
            classify_path("/home/ada/bin/helper"),
            PathZone::UserWritable
        );
        assert_eq!(
            classify_path("/Applications/Zoom.app/Contents/MacOS/zoom.us"),
            PathZone::System
        );
    }

    #[test]
    fn original_filename_mismatch() {
        let mut p = ProcessSnapshot {
            pid: 1,
            name: "svchost.exe".into(),
            path: r"C:\Users\a\svchost.exe".into(),
            original_filename: Some("cluely.exe".into()),
            parent_pid: None,
            start_time_unix: 0,
            command_line: String::new(),
        };
        assert!(name_mismatch(&p));
        p.original_filename = Some("SVCHOST.EXE".into());
        assert!(!name_mismatch(&p));
    }
}
