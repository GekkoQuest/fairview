pub struct AudioCaptureDetector;

impl AudioCaptureDetector {
    pub fn new() -> Self {
        Self
    }

    pub fn detect_realtime_audio_processing(&self) -> bool {
        #[cfg(target_os = "windows")]
        {
            self.detect_windows_audio()
        }

        #[cfg(target_os = "macos")]
        {
            self.detect_macos_audio()
        }

        #[cfg(target_os = "linux")]
        {
            self.detect_linux_audio()
        }
    }
}

#[cfg(target_os = "windows")]
impl AudioCaptureDetector {
    fn detect_windows_audio(&self) -> bool {
        use sysinfo::System;

        let mut system = System::new_all();
        system.refresh_all();

        for (_pid, process) in system.processes() {
            let cpu_usage = process.cpu_usage();
            let name = process.name().to_lowercase();

            if cpu_usage > 5.0 && self.is_audio_processing_app(&name) {
                return true;
            }
        }

        false
    }

    fn is_audio_processing_app(&self, name: &str) -> bool {
        let audio_apps = [
            "cluely", "obs", "audacity", "zoom", "teams",
            "discord", "slack", "recorder", "capture",
        ];
        audio_apps.iter().any(|&app| name.contains(app))
    }
}

#[cfg(target_os = "macos")]
impl AudioCaptureDetector {
    fn detect_macos_audio(&self) -> bool {
        use std::process::Command;

        let output = Command::new("system_profiler")
            .arg("SPAudioDataType")
            .output();

        if let Ok(output) = output {
            let result = String::from_utf8_lossy(&output.stdout);
            return result.contains("Input Source:") && 
                   (result.contains("Built-in") || result.contains("External"));
        }

        false
    }
}

#[cfg(target_os = "linux")]
impl AudioCaptureDetector {
    fn detect_linux_audio(&self) -> bool {
        self.check_pulseaudio() || self.check_pipewire()
    }

    fn check_pulseaudio(&self) -> bool {
        use std::process::Command;

        let output = Command::new("pactl")
            .arg("list")
            .arg("source-outputs")
            .output();

        if let Ok(output) = output {
            let stdout = String::from_utf8_lossy(&output.stdout);
            return stdout.contains("Source Output #");
        }

        false
    }

    fn check_pipewire(&self) -> bool {
        use std::process::Command;

        let output = Command::new("pw-cli")
            .arg("list-objects")
            .output();

        if let Ok(output) = output {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if stdout.contains("Stream") && stdout.contains("capture") {
                return true;
            }
        }

        false
    }
}