use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    pub scan: ScanConfig,
    pub weights: WeightsConfig,
    pub thresholds: ThresholdsConfig,
    pub whitelist: WhitelistConfig,
    pub monitoring: MonitoringConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ScanConfig {
    pub interval_seconds: u64,
    pub risk_threshold: f64,
    pub interview_type: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WeightsConfig {
    pub process_risk: f64,
    pub overlay_risk: f64,
    pub audio_risk: f64,
    pub hardware_risk: f64,
    pub vm_risk: f64, 
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ThresholdsConfig {
    pub process_threshold: f64,
    pub hardware_threshold: f64,
    pub audio_threshold: f64,
    pub overlay_threshold: f64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WhitelistConfig {
    pub processes: Vec<String>,
    pub directories: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MonitoringConfig {
    pub enable_process_monitoring: bool,
    pub enable_hardware_monitoring: bool,
    pub enable_audio_monitoring: bool,
    pub enable_overlay_monitoring: bool,
    pub enable_vm_detection: bool,
    pub collect_baseline: bool,
    pub baseline_duration_seconds: u64,
    pub continue_on_module_failure: bool,
}

impl Config {
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, String> {
        let contents = fs::read_to_string(path)
            .map_err(|e| format!("Failed to read config file: {}", e))?;
        
        let config: Config = toml::from_str(&contents)
            .map_err(|e| format!("Failed to parse config file: {}", e))?;
        
        config.validate()?;
        
        Ok(config)
    }

    pub fn default() -> Self {
        Self {
            scan: ScanConfig {
                interval_seconds: 30,
                risk_threshold: 0.5,
                interview_type: "coding".to_string(),
            },
            weights: WeightsConfig {
                process_risk: 0.30,
                overlay_risk: 0.20,
                audio_risk: 0.10,
                hardware_risk: 0.15,
                vm_risk: 0.25,
            },
            thresholds: ThresholdsConfig {
                process_threshold: 0.6,
                hardware_threshold: 0.5,
                audio_threshold: 0.3,
                overlay_threshold: 0.4,
            },
            whitelist: WhitelistConfig {
                processes: vec![
                    "code.exe".to_string(),
                    "vscode.exe".to_string(),
                    "chrome.exe".to_string(),
                    "firefox.exe".to_string(),
                    "msedge.exe".to_string(),
                ],
                directories: vec![
                    "C:\\Program Files\\Git".to_string(),
                    "C:\\Windows\\System32".to_string(),
                    "/usr/bin".to_string(),
                    "/Applications".to_string(),
                ],
            },
            monitoring: MonitoringConfig {
                enable_process_monitoring: true,
                enable_hardware_monitoring: true,
                enable_audio_monitoring: true,
                enable_overlay_monitoring: true,
                enable_vm_detection: true,
                collect_baseline: true,
                baseline_duration_seconds: 10,
                continue_on_module_failure: true,
            },
        }
    }

    fn validate(&self) -> Result<(), String> {
        let weight_sum = self.weights.process_risk 
            + self.weights.overlay_risk 
            + self.weights.audio_risk 
            + self.weights.hardware_risk
            + self.weights.vm_risk;
        
        if (weight_sum - 1.0).abs() > 0.01 {
            return Err(format!(
                "Weights must sum to 1.0, got {:.2}",
                weight_sum
            ));
        }

        if self.weights.process_risk < 0.0 
            || self.weights.overlay_risk < 0.0 
            || self.weights.audio_risk < 0.0 
            || self.weights.hardware_risk < 0.0 
            || self.weights.vm_risk < 0.0 {
            return Err("All weights must be positive".to_string());
        }

        if self.scan.risk_threshold < 0.0 || self.scan.risk_threshold > 1.0 {
            return Err("risk_threshold must be between 0.0 and 1.0".to_string());
        }

        Ok(())
    }

    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<(), String> {
        let toml_string = toml::to_string_pretty(self)
            .map_err(|e| format!("Failed to serialize config: {}", e))?;
        
        fs::write(path, toml_string)
            .map_err(|e| format!("Failed to write config file: {}", e))?;
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config_is_valid() {
        let config = Config::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_invalid_weights() {
        let mut config = Config::default();
        config.weights.process_risk = 0.5;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_invalid_threshold() {
        let mut config = Config::default();
        config.scan.risk_threshold = 1.5;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_invalid_interview_type() {
        let mut config = Config::default();
        config.scan.interview_type = "invalid".to_string();
        assert!(config.validate().is_err());
    }
}