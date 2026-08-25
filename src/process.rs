use crate::config::Config;
use crate::evidence::{Detector, Finding, ProcessRef, ProcessSnapshot, Severity};
use crate::known::{self, ToolKind};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use sysinfo::{ProcessesToUpdate, System};

pub struct ProcessTable {
    system: System,
}

impl ProcessTable {
    pub fn new() -> Self {
        let mut system = System::new();
        system.refresh_processes(ProcessesToUpdate::All, true);
        Self { system }
    }

    pub fn refresh(&mut self) {
        self.system.refresh_processes(ProcessesToUpdate::All, true);
    }

    pub fn snapshot(&self) -> Vec<ProcessSnapshot> {
        self.system
            .processes()
            .iter()
            .map(|(pid, proc)| {
                let name = proc.name().to_string_lossy().into_owned();
                let path = proc
                    .exe()
                    .map(|p| p.to_string_lossy().into_owned())
                    .unwrap_or_default();
                let command_line = proc
                    .cmd()
                    .iter()
                    .map(|s| s.to_string_lossy().into_owned())
                    .collect::<Vec<_>>()
                    .join(" ");
                ProcessSnapshot {
                    pid: pid.as_u32(),
                    name,
                    path,
                    original_filename: None,
                    parent_pid: proc.parent().map(|p| p.as_u32()),
                    start_time_unix: proc.start_time(),
                    command_line,
                }
            })
            .collect()
    }
}

#[derive(Debug, Clone)]
pub struct ProcessBaseline {
    /// pid -> image path at baseline time.
    by_pid: HashMap<u32, String>,
    /// normalized image names that were already running.
    names: Vec<String>,
    pub collected_unix: u64,
}

impl ProcessBaseline {
    pub fn from_snapshots(procs: &[ProcessSnapshot]) -> Self {
        let collected_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let mut by_pid = HashMap::new();
        let mut names = Vec::new();
        for p in procs {
            by_pid.insert(p.pid, p.path.clone());
            names.push(known::normalize_image_name(&p.name));
            if !p.path.is_empty() {
                names.push(known::normalize_image_name(&p.path));
            }
        }
        names.sort();
        names.dedup();
        Self {
            by_pid,
            names,
            collected_unix,
        }
    }

    pub fn is_new(&self, proc: &ProcessSnapshot) -> bool {
        match self.by_pid.get(&proc.pid) {
            Some(old_path) => {
                // PID reused by a different image.
                !old_path.is_empty()
                    && !proc.path.is_empty()
                    && known::normalize_image_name(old_path)
                        != known::normalize_image_name(&proc.path)
            }
            None => {
                let n = known::normalize_image_name(&proc.name);
                !self.names.iter().any(|e| e == &n)
            }
        }
    }
}

pub fn analyze(
    config: &Config,
    procs: &[ProcessSnapshot],
    baseline: Option<&ProcessBaseline>,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    for proc in procs {
        if known::is_os_noise(&proc.name) {
            continue;
        }

        let pref = ProcessRef {
            pid: proc.pid,
            name: proc.name.clone(),
            path: if proc.path.is_empty() {
                None
            } else {
                Some(proc.path.clone())
            },
        };

        if let Some(tool) = known::match_tool(proc, known::INTERVIEW_ASSISTANTS) {
            findings.push(
                Finding::new(
                    Detector::Process,
                    "process.interview_assistant",
                    Severity::Critical,
                    0.95,
                    format!(
                        "Known interview assistant process: {} ({})",
                        tool.label, proc.name
                    ),
                )
                .detail("label", tool.label)
                .with_process(pref.clone()),
            );
            continue;
        }

        if let Some(tool) = known::match_tool(proc, known::REMOTE_ACCESS) {
            findings.push(
                Finding::new(
                    Detector::Process,
                    "process.remote_tool",
                    Severity::High,
                    0.9,
                    format!("Remote-access tool process: {} ({})", tool.label, proc.name),
                )
                .detail("label", tool.label)
                .with_process(pref.clone()),
            );
            continue;
        }

        if let Some(tool) = known::match_tool(proc, known::VIRTUAL_DISPLAY) {
            findings.push(
                Finding::new(
                    Detector::Process,
                    "process.virtual_display_tool",
                    Severity::High,
                    0.85,
                    format!(
                        "Virtual display driver/tool: {} ({})",
                        tool.label, proc.name
                    ),
                )
                .detail("label", tool.label)
                .with_process(pref.clone()),
            );
            continue;
        }

        let _ = ToolKind::ScreenCapture;

        if let Some(base) = baseline {
            if base.is_new(proc)
                && !config.is_expected_name(&proc.name)
                && !known::is_browser(&proc.name)
                && !known::is_editor(&proc.name)
                && !known::is_meeting_app(&proc.name)
            {
                findings.push(
                    Finding::new(
                        Detector::Process,
                        "process.started_after_baseline",
                        Severity::Low,
                        0.4,
                        format!(
                            "Process started after baseline: {} (pid {})",
                            proc.name, proc.pid
                        ),
                    )
                    .detail("path", proc.path.clone())
                    .with_process(pref),
                );
            }
        }
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snap(pid: u32, name: &str, path: &str) -> ProcessSnapshot {
        ProcessSnapshot {
            pid,
            name: name.into(),
            path: path.into(),
            original_filename: None,
            parent_pid: None,
            start_time_unix: 0,
            command_line: String::new(),
        }
    }

    #[test]
    fn pid_reuse_is_new() {
        let base =
            ProcessBaseline::from_snapshots(&[snap(10, "notepad.exe", r"C:\Windows\notepad.exe")]);
        let later = snap(10, "cluely.exe", r"C:\Users\a\cluely.exe");
        assert!(base.is_new(&later));
    }

    #[test]
    fn same_pid_same_image_is_not_new() {
        let p = snap(10, "chrome.exe", r"C:\chrome.exe");
        let base = ProcessBaseline::from_snapshots(&[p.clone()]);
        assert!(!base.is_new(&p));
    }

    #[test]
    fn cluely_is_critical() {
        let cfg = Config::default();
        let f = analyze(&cfg, &[snap(4, "cluely.exe", r"C:\cluely.exe")], None);
        assert!(f.iter().any(|x| x.signal == "process.interview_assistant"));
        assert_eq!(f[0].severity, Severity::Critical);
    }
}
