use serde::Serialize;
use std::time::{Duration, SystemTime};

mod audio_detector;
mod hardware_detector;
mod overlay_detector;
mod process_monitor;

use audio_detector::AudioCaptureDetector;
use hardware_detector::HardwareDetector;
use overlay_detector::OverlayDetector;
use process_monitor::ProcessMonitor;

#[derive(Debug, Clone)]
pub struct Process {
    pub pid: u32,
    pub name: String,
    pub path: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SuspiciousProcess {
    pub pid: u32,
    pub name: String,
    pub path: String,
    pub risk_score: f64,
    pub reasons: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct DetectionReport {
    pub timestamp: SystemTime,
    pub suspicious_processes: Vec<SuspiciousProcess>,
    pub hidden_overlays: Vec<OverlayWindow>,
    pub audio_monitoring_detected: bool,
    pub hardware_suspicion: Option<HardwareSuspicionReport>,
    pub overall_risk_score: f64,
}

#[derive(Debug, Serialize)]
pub struct HardwareSuspicionReport {
    pub risk_score: f64,
    pub display_count: usize,
    pub has_virtual_display: bool,
    pub has_hdmi_splitter: bool,
    pub remote_desktop_active: bool,
    pub flags: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct OverlayWindow {
    pub handle: usize,
    pub position: (i32, i32),
    pub size: (u32, u32),
    pub owner_pid: u32,
    pub is_transparent: bool,
    pub is_topmost: bool,
}

pub struct CluelyDetector {
    process_monitor: ProcessMonitor,
    audio_detector: AudioCaptureDetector,
    overlay_detector: OverlayDetector,
    hardware_detector: HardwareDetector,
}

impl CluelyDetector {
    pub fn new() -> Self {
        Self {
            process_monitor: ProcessMonitor::new(),
            audio_detector: AudioCaptureDetector::new(),
            overlay_detector: OverlayDetector::new(),
            hardware_detector: HardwareDetector::new(),
        }
    }

    pub fn scan(&self) -> DetectionReport {
        println!("[*] Starting Cluely detection scan...");

        let suspicious_processes = self.scan_for_suspicious_processes();
        println!("[+] Found {} suspicious processes", suspicious_processes.len());

        let hidden_overlays = self.overlay_detector.find_hidden_overlays();
        println!("[+] Found {} suspicious overlays", hidden_overlays.len());

        let audio_monitoring = self.audio_detector.detect_realtime_audio_processing();
        println!("[+] Audio monitoring detected: {}", audio_monitoring);

        let hardware_suspicion = self.hardware_detector.detect_hardware_cheating();
        println!("[+] Hardware risk score: {:.2}", hardware_suspicion.risk_score);

        let overall_risk = self.calculate_overall_risk(
            &suspicious_processes,
            &hidden_overlays,
            audio_monitoring,
            &hardware_suspicion,
        );

        println!("[!] Overall risk score: {:.2}/1.0", overall_risk);

        let (display_count, has_virtual_display, has_hdmi_splitter, remote_desktop_active) =
            Self::summarize_hardware(&hardware_suspicion);

        DetectionReport {
            timestamp: SystemTime::now(),
            suspicious_processes,
            hidden_overlays,
            audio_monitoring_detected: audio_monitoring,
            hardware_suspicion: Some(HardwareSuspicionReport {
                risk_score: hardware_suspicion.risk_score,
                display_count,
                has_virtual_display,
                has_hdmi_splitter,
                remote_desktop_active,
                flags: hardware_suspicion.flags.clone(),
            }),
            overall_risk_score: overall_risk,
        }
    }

    fn summarize_hardware(
        hardware_suspicion: &hardware_detector::HardwareSuspicion,
    ) -> (usize, bool, bool, bool) {
        let display_count = hardware_suspicion
            .details
            .get("display_count")
            .and_then(|s| s.parse().ok())
            .unwrap_or(1);

        let has_virtual_display = hardware_suspicion
            .flags
            .iter()
            .any(|f| f.to_lowercase().contains("virtual display"));

        let has_hdmi_splitter = hardware_suspicion
            .flags
            .iter()
            .any(|f| f.to_lowercase().contains("hdmi splitter"));

        let remote_desktop_active = hardware_suspicion
            .flags
            .iter()
            .any(|f| f.to_lowercase().contains("remote desktop"));

        (display_count, has_virtual_display, has_hdmi_splitter, remote_desktop_active)
    }

    fn scan_for_suspicious_processes(&self) -> Vec<SuspiciousProcess> {
        let mut suspicious = Vec::new();
        let processes = self.process_monitor.get_all_processes();

        for process in processes {
            let mut reasons = Vec::new();
            let mut risk_score: f64 = 0.0;

            let has_screen = self.process_monitor.has_screen_capture_permission(&process);
            let has_audio = self.process_monitor.has_audio_capture_permission(&process);
            let has_access = self.process_monitor.has_accessibility_permission(&process);
            let has_suspicious_name = self.is_suspicious_name(&process.name);
            let is_common_legit = self.is_common_legit_app(&process.name);

            if has_screen {
                reasons.push("Has screen capture permission".to_string());
                risk_score += 0.3;
            }

            if has_audio {
                reasons.push("Has audio capture permission".to_string());
                risk_score += 0.3;
            }

            if has_access {
                reasons.push("Has accessibility API access".to_string());
                risk_score += 0.2;
            }

            if has_suspicious_name {
                reasons.push("Suspicious process name".to_string());
                risk_score += 0.4;
            }

            let capability_count = [has_screen, has_audio, has_access]
                .iter()
                .filter(|&&b| b)
                .count();

            if is_common_legit && !has_suspicious_name {
                continue;
            }

            let path_lower = process.path.to_lowercase();
            let is_windows_core = path_lower.starts_with("c:\\windows\\system32")
                || path_lower.starts_with("c:\\windows\\syswow64");

            let should_flag = (has_suspicious_name && capability_count >= 1 && !is_common_legit)
                || (!has_suspicious_name && capability_count >= 3 && !is_common_legit && !is_windows_core);

            if should_flag && !reasons.is_empty() {
                suspicious.push(SuspiciousProcess {
                    pid: process.pid,
                    name: process.name.clone(),
                    path: process.path.clone(),
                    risk_score: risk_score.min(1.0),
                    reasons,
                });
            }
        }

        suspicious
    }

    fn is_suspicious_name(&self, name: &str) -> bool {
        let suspicious_patterns = [
            "cluely", "interview", "gpt", "chatgpt", "llm", "copilot",
            "aiassistant", "ai-assistant", "interview-bot", "interview-ai",
        ];

        let name_lower = name.to_lowercase();
        suspicious_patterns.iter().any(|&pattern| name_lower.contains(pattern))
    }

    fn is_common_legit_app(&self, name: &str) -> bool {
        let name_lower = name.to_lowercase();
        let whitelist = [
            // Browsers
            "explorer.exe", "chrome.exe", "firefox.exe", "msedge.exe", 
            "msedgewebview2.exe", "brave.exe", "opera.exe",
            // Communication apps
            "discord.exe", "slack.exe", "teams.exe", "zoom.exe",
            // Development tools
            "code.exe", "vscode.exe", "visual studio",
            // Screen capture/streaming (legitimate uses)
            "sharex.exe", "obs", "obs64.exe", "streamlabs",
            // Gaming
            "steam.exe", "steamwebhelper.exe",
            // Windows system
            "svchost.exe", "searchhost.exe", "applicationframehost.exe",
            "shellexperiencehost.exe", "systemsettings.exe",
            // Camera/peripherals
            "camera hub.exe", "elgato",
        ];
        whitelist.iter().any(|w| name_lower == *w || name_lower.contains(*w))
    }

    fn calculate_overall_risk(
        &self,
        suspicious_processes: &[SuspiciousProcess],
        hidden_overlays: &[OverlayWindow],
        audio_monitoring: bool,
        hardware_suspicion: &hardware_detector::HardwareSuspicion,
    ) -> f64 {
        let mut risk = 0.0;

        if !suspicious_processes.is_empty() {
            let max_process_risk = suspicious_processes
                .iter()
                .map(|p| p.risk_score)
                .max_by(|a, b| a.partial_cmp(b).unwrap())
                .unwrap_or(0.0);
            risk += max_process_risk * 0.4;
        }

        if !hidden_overlays.is_empty() {
            risk += 0.25;
        }

        if audio_monitoring {
            risk += 0.15;
        }

        risk += hardware_suspicion.risk_score * 0.2;
        risk.min(1.0)
    }
}

fn print_report(report: &DetectionReport) {
    println!("\n{}", "=".repeat(60));
    println!("CLUELY DETECTION REPORT");
    println!("{}", "=".repeat(60));
    println!("Timestamp: {:?}", report.timestamp);
    println!("Overall Risk Score: {:.2}/1.0", report.overall_risk_score);
    println!();

    if !report.suspicious_processes.is_empty() {
        println!("SUSPICIOUS PROCESSES:");
        for proc in &report.suspicious_processes {
            println!("  - {} (PID: {})", proc.name, proc.pid);
            println!("    Path: {}", proc.path);
            println!("    Risk Score: {:.2}", proc.risk_score);
            println!("    Reasons:");
            for reason in &proc.reasons {
                println!("      * {}", reason);
            }
            println!();
        }
    }

    if !report.hidden_overlays.is_empty() {
        println!("HIDDEN OVERLAYS DETECTED:");
        for overlay in &report.hidden_overlays {
            println!("  - Window Handle: {}", overlay.handle);
            println!("    Owner PID: {}", overlay.owner_pid);
            println!("    Position: {:?}", overlay.position);
            println!("    Size: {:?}", overlay.size);
            println!();
        }
    }

    if report.audio_monitoring_detected {
        println!("⚠️  AUDIO MONITORING DETECTED\n");
    }

    if let Some(ref hardware) = report.hardware_suspicion {
        if hardware.risk_score > 0.3 {
            println!("HARDWARE-BASED CHEATING DETECTED:");
        } else {
            println!("HARDWARE SUMMARY:");
        }
        println!("  Risk Score: {:.2}", hardware.risk_score);
        println!("  Display Count: {}", hardware.display_count);

        if !hardware.flags.is_empty() {
            println!("  Flags:");
            for flag in &hardware.flags {
                println!("    * {}", flag);
            }
        }
        println!();
    }

    println!("{}\n", "=".repeat(60));
}

#[tokio::main]
async fn main() {
    println!("Cluely Detector v0.1.0\n");

    let detector = CluelyDetector::new();

    loop {
        let report = detector.scan();
        print_report(&report);

        if let Ok(json) = serde_json::to_string_pretty(&report) {
            std::fs::write("detection_report.json", json).expect("Failed to write report");
        }

        println!("Waiting 30 seconds before next scan...\n");
        tokio::time::sleep(Duration::from_secs(30)).await;
    }
}