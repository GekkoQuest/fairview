use crate::error::{Error, Result};
use crate::evidence::Severity;
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub scan: ScanConfig,
    pub session: SessionConfig,
    pub monitoring: MonitoringConfig,
    pub output: OutputConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfig {
    pub interval_seconds: u64,
    /// Alert when a finding at this severity or above is unexpected.
    pub alert_level: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionConfig {
    /// Image names that belong to this interview (browser, IDE, meeting app).
    pub expected_processes: Vec<String>,
    /// Dual / extra physical monitors are normal for many candidates.
    pub allow_extra_displays: bool,
    pub allow_vm_guest: bool,
    pub allow_virtual_camera: bool,
    /// Zoom/Teams/Meet-class apps are expected mic users even if omitted above.
    pub assume_meeting_apps: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitoringConfig {
    pub process: bool,
    pub overlay: bool,
    pub audio: bool,
    pub display: bool,
    pub remote: bool,
    pub environment: bool,
    pub camera: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputConfig {
    pub directory: String,
    pub write_json: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            scan: ScanConfig {
                interval_seconds: 30,
                alert_level: "medium".into(),
            },
            session: SessionConfig {
                expected_processes: vec![
                    "chrome.exe".into(),
                    "msedge.exe".into(),
                    "firefox.exe".into(),
                    "code.exe".into(),
                    "zoom.exe".into(),
                    "ms-teams.exe".into(),
                    "Teams.exe".into(),
                ],
                allow_extra_displays: true,
                allow_vm_guest: false,
                allow_virtual_camera: false,
                assume_meeting_apps: true,
            },
            monitoring: MonitoringConfig {
                process: true,
                overlay: true,
                audio: true,
                display: true,
                remote: true,
                environment: true,
                camera: true,
            },
            output: OutputConfig {
                directory: "fairview-reports".into(),
                write_json: true,
            },
        }
    }
}

impl Config {
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self> {
        let contents = std::fs::read_to_string(path)?;
        let config: Config = toml::from_str(&contents).map_err(|e| Error::Config(e.to_string()))?;
        config.validate()?;
        Ok(config)
    }

    pub fn save_to_file(&self, path: impl AsRef<Path>) -> Result<()> {
        let toml = toml::to_string_pretty(self).map_err(|e| Error::Config(e.to_string()))?;
        std::fs::write(path, toml)?;
        Ok(())
    }

    pub fn validate(&self) -> Result<()> {
        if self.scan.interval_seconds == 0 {
            return Err(Error::Config("interval_seconds must be > 0".into()));
        }
        if Severity::from_name(&self.scan.alert_level).is_none() {
            return Err(Error::Config(format!(
                "alert_level must be info|low|medium|high|critical, got {}",
                self.scan.alert_level
            )));
        }
        Ok(())
    }

    pub fn alert_level(&self) -> Severity {
        Severity::from_name(&self.scan.alert_level).unwrap_or(Severity::Medium)
    }

    pub fn is_expected_name(&self, name: &str) -> bool {
        let n = crate::known::normalize_image_name(name);
        self.session
            .expected_processes
            .iter()
            .any(|e| crate::known::normalize_image_name(e) == n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_valid() {
        assert!(Config::default().validate().is_ok());
    }

    #[test]
    fn rejects_bad_alert_level() {
        let mut c = Config::default();
        c.scan.alert_level = "banana".into();
        assert!(c.validate().is_err());
    }

    #[test]
    fn expected_name_is_exact() {
        let c = Config::default();
        assert!(c.is_expected_name("chrome.exe"));
        assert!(c.is_expected_name("CHROME"));
        assert!(!c.is_expected_name("chrome-beta-helper"));
    }
}
