use serde::Serialize;
use std::time::{Duration, SystemTime};
use chrono::{DateTime, Utc};

mod audio_detector;
mod config;
mod hardware_detector;
mod overlay_detector;
mod process_monitor;
mod vm_detector;

use audio_detector::AudioCaptureDetector;
use config::Config;
use hardware_detector::HardwareDetector;
use overlay_detector::OverlayDetector;
use process_monitor::ProcessMonitor;
use vm_detector::VmDetector;

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
    pub started_during_interview: bool,
    pub is_whitelisted: bool,
}

#[derive(Debug, Serialize)]
pub struct DetectionReport {
    #[serde(with = "timestamp_format")]
    pub timestamp: SystemTime,
    pub scan_number: usize,
    pub suspicious_processes: Vec<SuspiciousProcess>,
    pub hidden_overlays: Vec<OverlayWindow>,
    pub audio_monitoring_detected: bool,
    pub hardware_suspicion: Option<HardwareSuspicionReport>,
    pub vm_detection: Option<vm_detector::VmCheckResult>,
    pub overall_risk_score: f64,
    pub exceeds_threshold: bool,
    pub module_failures: Vec<String>,
}

mod timestamp_format {
    use serde::{Serialize, Serializer};
    use std::time::SystemTime;
    use chrono::{DateTime, Utc};

    pub fn serialize<S>(time: &SystemTime, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let datetime: DateTime<Utc> = (*time).into();
        datetime.to_rfc3339().serialize(serializer)
    }
}

#[derive(Debug, Serialize)]
pub struct HardwareSuspicionReport {
    pub risk_score: f64,
    pub display_count: usize,
    pub has_virtual_display: bool,
    pub has_hdmi_splitter: bool,
    pub remote_desktop_active: bool,
    pub flags: Vec<String>,
    pub baseline_display_count: Option<usize>,
    pub display_changed: bool,
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

pub struct FairviewDetector {
    process_monitor: ProcessMonitor,
    audio_detector: AudioCaptureDetector,
    overlay_detector: OverlayDetector,
    hardware_detector: HardwareDetector,
    vm_detector: VmDetector,
    config: Config,
    scan_count: usize,
    baseline_collected: bool,
}

impl FairviewDetector {
    pub fn new(config: Config) -> Self {
        Self {
            process_monitor: ProcessMonitor::new(config.clone()),
            audio_detector: AudioCaptureDetector::new(),
            overlay_detector: OverlayDetector::new(),
            hardware_detector: HardwareDetector::new(),
            vm_detector: VmDetector::new(),
            config,
            scan_count: 0,
            baseline_collected: false,
        }
    }

    pub fn collect_baseline(&mut self) {
        if !self.config.monitoring.collect_baseline {
            println!("[*] Baseline collection disabled in config");
            return;
        }

        println!("\n{}", "=".repeat(60));
        println!("COLLECTING BASELINE");
        println!("{}", "=".repeat(60));
        println!("[*] Please ensure all necessary applications are running");
        println!("[*] Baseline collection will take {} seconds...\n", 
                 self.config.monitoring.baseline_duration_seconds);

        self.process_monitor.collect_baseline();

        if let Err(e) = self.hardware_detector.set_baseline() {
            println!("[!] Warning: Failed to collect hardware baseline: {}", e);
        } else {
            if let Some(baseline) = self.hardware_detector.get_baseline() {
                println!("[+] Hardware baseline: {} displays detected", baseline.display_count);
            }
        }

        println!("[+] Baseline collection complete\n");
        self.baseline_collected = true;
    }

    pub fn scan(&mut self) -> DetectionReport {
        self.scan_count += 1;
        println!("\n[*] Starting scan #{} at {:?}", self.scan_count, SystemTime::now());

        let mut module_failures = Vec::new();

        let vm_result = if self.config.monitoring.enable_vm_detection {
             match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                self.vm_detector.detect()
            })) {
                Ok(result) => {
                    if result.is_vm {
                         println!("[!] VM DETECTED! Confidence: {:.2}", result.confidence_score);
                    }
                    Some(result)
                },
                Err(_) => {
                    let error = "VM detection module failed";
                    module_failures.push(error.to_string());
                    None
                }
            }
        } else {
            None
        };

        let suspicious_processes = if self.config.monitoring.enable_process_monitoring {
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                self.scan_for_suspicious_processes()
            })) {
                Ok(procs) => {
                    println!("[+] Found {} suspicious processes", procs.len());
                    procs
                },
                Err(_) => {
                    let error = "Process monitoring module failed";
                    module_failures.push(error.to_string());
                    println!("[!] {}", error);
                    Vec::new()
                }
            }
        } else {
            Vec::new()
        };

        let hidden_overlays = if self.config.monitoring.enable_overlay_monitoring {
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                self.overlay_detector.find_hidden_overlays()
            })) {
                Ok(overlays) => {
                    println!("[+] Found {} suspicious overlays", overlays.len());
                    overlays
                },
                Err(_) => {
                    let error = "Overlay detection module failed";
                    module_failures.push(error.to_string());
                    Vec::new()
                }
            }
        } else {
            Vec::new()
        };

        let audio_monitoring = if self.config.monitoring.enable_audio_monitoring {
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                self.audio_detector.detect_realtime_audio_processing()
            })) {
                Ok(detected) => {
                    println!("[+] Audio monitoring detected: {}", detected);
                    detected
                },
                Err(_) => {
                    let error = "Audio detection module failed";
                    module_failures.push(error.to_string());
                    false
                }
            }
        } else {
            false
        };

        let hardware_suspicion = if self.config.monitoring.enable_hardware_monitoring {
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                self.hardware_detector.detect_hardware_cheating()
            })) {
                Ok(suspicion) => {
                    println!("[+] Hardware risk score: {:.2}", suspicion.risk_score);
                    Some(suspicion)
                },
                Err(_) => {
                    let error = "Hardware detection module failed";
                    module_failures.push(error.to_string());
                    None
                }
            }
        } else {
            None
        };

        let overall_risk = self.calculate_overall_risk(
            &suspicious_processes,
            &hidden_overlays,
            audio_monitoring,
            hardware_suspicion.as_ref(),
            vm_result.as_ref(),
        );

        let exceeds_threshold = overall_risk >= self.config.scan.risk_threshold;

        println!("[!] Overall risk score: {:.2}/1.0 {}", 
                 overall_risk,
                 if exceeds_threshold { "(EXCEEDS THRESHOLD)" } else { "" });

        let hardware_report = hardware_suspicion.map(|hs| {
            let (display_count, has_virtual_display, has_hdmi_splitter, remote_desktop_active) =
                Self::summarize_hardware(&hs);
            
            let baseline_count = self.hardware_detector.get_baseline()
                .map(|b| b.display_count);
            
            let display_changed = if let Some(baseline) = baseline_count {
                baseline != display_count
            } else {
                false
            };

            HardwareSuspicionReport {
                risk_score: hs.risk_score,
                display_count,
                has_virtual_display,
                has_hdmi_splitter,
                remote_desktop_active,
                flags: hs.flags.clone(),
                baseline_display_count: baseline_count,
                display_changed,
            }
        });

        DetectionReport {
            timestamp: SystemTime::now(),
            scan_number: self.scan_count,
            suspicious_processes,
            hidden_overlays,
            audio_monitoring_detected: audio_monitoring,
            hardware_suspicion: hardware_report,
            vm_detection: vm_result,
            overall_risk_score: overall_risk,
            exceeds_threshold,
            module_failures,
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

            let is_whitelisted = self.process_monitor.is_whitelisted(&process);
            let was_in_baseline = self.process_monitor.was_in_baseline(process.pid);
            let started_during = self.baseline_collected && !was_in_baseline;

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

            if started_during && !is_whitelisted {
                reasons.push("Started during interview".to_string());
                risk_score += 0.3;
            }

            let capability_count = [has_screen, has_audio, has_access]
                .iter()
                .filter(|&&b| b)
                .count();

            if (is_whitelisted || is_common_legit) && !has_suspicious_name {
                continue;
            }

            let path_lower = process.path.to_lowercase();
            let is_windows_core = path_lower.starts_with("c:\\windows\\system32")
                || path_lower.starts_with("c:\\windows\\syswow64");

            let should_flag = (has_suspicious_name && capability_count >= 1 && !is_common_legit)
                || (!has_suspicious_name && capability_count >= 3 && !is_common_legit && !is_windows_core)
                || (started_during && capability_count >= 2);

            if should_flag && !reasons.is_empty() && risk_score >= self.config.thresholds.process_threshold {
                suspicious.push(SuspiciousProcess {
                    pid: process.pid,
                    name: process.name.clone(),
                    path: process.path.clone(),
                    risk_score: risk_score.min(1.0),
                    reasons,
                    started_during_interview: started_during,
                    is_whitelisted,
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
            "explorer.exe", "chrome.exe", "firefox.exe", "msedge.exe", 
            "msedgewebview2.exe", "brave.exe", "opera.exe",
            "discord.exe", "slack.exe", "teams.exe", "zoom.exe",
            "code.exe", "vscode.exe", "visual studio",
            "sharex.exe", "obs", "obs64.exe", "streamlabs",
            "steam.exe", "steamwebhelper.exe",
            "svchost.exe", "searchhost.exe", "applicationframehost.exe",
            "shellexperiencehost.exe", "systemsettings.exe",
            "camera hub.exe", "elgato",
        ];
        whitelist.iter().any(|w| name_lower == *w || name_lower.contains(*w))
    }

    fn calculate_overall_risk(
        &self,
        suspicious_processes: &[SuspiciousProcess],
        hidden_overlays: &[OverlayWindow],
        audio_monitoring: bool,
        hardware_suspicion: Option<&hardware_detector::HardwareSuspicion>,
        vm_result: Option<&vm_detector::VmCheckResult>,
    ) -> f64 {
        let mut risk = 0.0;

        if !suspicious_processes.is_empty() {
            let max_process_risk = suspicious_processes
                .iter()
                .map(|p| p.risk_score)
                .max_by(|a, b| a.partial_cmp(b).unwrap())
                .unwrap_or(0.0);
            risk += max_process_risk * self.config.weights.process_risk;
        }

        if !hidden_overlays.is_empty() {
            risk += self.config.weights.overlay_risk;
        }

        if audio_monitoring {
            risk += self.config.weights.audio_risk;
        }

        if let Some(hardware) = hardware_suspicion {
            risk += hardware.risk_score * self.config.weights.hardware_risk;
        }

        if let Some(vm) = vm_result {
            if vm.is_vm {
                risk += vm.confidence_score * self.config.weights.vm_risk;
            }
        }

        risk.min(1.0)
    }
}

fn print_report(report: &DetectionReport, config: &Config) {
    let datetime: DateTime<Utc> = report.timestamp.into();
    
    println!("\n{}", "=".repeat(60));
    println!("FAIRVIEW DETECTION REPORT - Scan #{}", report.scan_number);
    println!("{}", "=".repeat(60));
    println!("Timestamp: {}", datetime.format("%Y-%m-%d %H:%M:%S UTC"));
    
    if let Some(ref vm) = report.vm_detection {
        if vm.is_vm {
            println!("\n🔴 🔴 CRITICAL: VIRTUAL MACHINE DETECTED 🔴 🔴");
            println!("Confidence Score: {:.2}", vm.confidence_score);
            for reason in &vm.reasons {
                println!("  - {}", reason);
            }
            println!();
        }
    }

    println!("Overall Risk Score: {:.2}/1.0", report.overall_risk_score);
    
    if report.exceeds_threshold {
        println!("⚠️  STATUS: RISK THRESHOLD EXCEEDED");
    } else {
        println!("✓ STATUS: Within acceptable risk levels");
    }
    println!();

    if !report.module_failures.is_empty() {
        println!("MODULE FAILURES:");
        for failure in &report.module_failures {
            println!("  ⚠️  {}", failure);
        }
        println!();
    }

    if !report.suspicious_processes.is_empty() {
        println!("SUSPICIOUS PROCESSES:");
        for proc in &report.suspicious_processes {
            println!("  - {} (PID: {})", proc.name, proc.pid);
            println!("    Risk Score: {:.2}", proc.risk_score);
            if proc.started_during_interview {
                println!("    ⚠️  Started during interview");
            }
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
            println!("    Size: {:?}", overlay.size);
            println!();
        }
    }

    if report.audio_monitoring_detected {
        println!("⚠️  AUDIO MONITORING DETECTED\n");
    }

    if let Some(ref hardware) = report.hardware_suspicion {
        if hardware.risk_score > config.thresholds.hardware_threshold {
            println!("⚠️  HARDWARE-BASED CHEATING DETECTED:");
        } else {
            println!("HARDWARE SUMMARY:");
        }
        println!("  Risk Score: {:.2}", hardware.risk_score);
        println!("  Display Count: {}", hardware.display_count);
        
        if let Some(baseline) = hardware.baseline_display_count {
            if hardware.display_changed {
                println!("  ⚠️  Display configuration changed (Baseline: {})", baseline);
            }
        }

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
    println!("Fairview v0.1.0 - Interview Monitoring System\n");

    let config = match Config::from_file("fairview_config.toml") {
        Ok(cfg) => {
            println!("[+] Loaded configuration from fairview_config.toml");
            cfg
        }
        Err(e) => {
            println!("[!] Failed to load config: {}", e);
            println!("[*] Using default configuration");
            let default_cfg = Config::default();
            
            if let Err(e) = default_cfg.save_to_file("fairview_config.toml") {
                println!("[!] Failed to save default config: {}", e);
            } else {
                println!("[+] Saved default configuration to fairview_config.toml");
            }
            
            default_cfg
        }
    };

    let mut detector = FairviewDetector::new(config.clone());

    if config.monitoring.collect_baseline {
        detector.collect_baseline();
        
        println!("Press Enter to start monitoring...");
        let mut input = String::new();
        std::io::stdin().read_line(&mut input).unwrap();
    }

    println!("\n{}", "=".repeat(60));
    println!("STARTING CONTINUOUS MONITORING");
    println!("Scan interval: {} seconds", config.scan.interval_seconds);
    println!("{}", "=".repeat(60));

    loop {
        let report = detector.scan();
        print_report(&report, &config);

        let datetime: DateTime<Utc> = report.timestamp.into();
        let filename = format!(
            "detection_report_{}.json",
            datetime.format("%Y%m%d_%H%M%S")
        );
        
        if let Ok(json) = serde_json::to_string_pretty(&report) {
            if let Err(e) = std::fs::write(&filename, json) {
                println!("[!] Failed to write report to {}: {}", filename, e);
            }
        }

        tokio::time::sleep(Duration::from_secs(config.scan.interval_seconds)).await;
    }
}