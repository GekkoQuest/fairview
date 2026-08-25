use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        match name.trim().to_ascii_lowercase().as_str() {
            "info" => Some(Self::Info),
            "low" => Some(Self::Low),
            "medium" => Some(Self::Medium),
            "high" => Some(Self::High),
            "critical" => Some(Self::Critical),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Detector {
    Process,
    Overlay,
    Audio,
    Display,
    Remote,
    Environment,
    Camera,
}

impl Detector {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Process => "process",
            Self::Overlay => "overlay",
            Self::Audio => "audio",
            Self::Display => "display",
            Self::Remote => "remote",
            Self::Environment => "environment",
            Self::Camera => "camera",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ProcessRef {
    pub pid: u32,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub detector: Detector,
    /// Stable machine id, e.g. `overlay.exclude_from_capture`.
    pub signal: String,
    pub severity: Severity,
    /// 0.0–1.0 confidence in the *observation*, not in "this is cheating".
    pub confidence: f32,
    pub summary: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub details: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process: Option<ProcessRef>,
}

impl Finding {
    pub fn new(
        detector: Detector,
        signal: impl Into<String>,
        severity: Severity,
        confidence: f32,
        summary: impl Into<String>,
    ) -> Self {
        Self {
            detector,
            signal: signal.into(),
            severity,
            confidence: confidence.clamp(0.0, 1.0),
            summary: summary.into(),
            details: BTreeMap::new(),
            process: None,
        }
    }

    pub fn detail(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.details.insert(key.into(), value.into());
        self
    }

    pub fn with_process(mut self, process: ProcessRef) -> Self {
        self.process = Some(process);
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectorKind {
    Internal,
    Hdmi,
    DisplayPort,
    Dvi,
    Vga,
    Wireless,
    IndirectWired,
    IndirectWireless,
    IndirectVirtual,
    Other,
    Unknown,
}

impl ConnectorKind {
    pub fn is_virtual(self) -> bool {
        matches!(
            self,
            Self::IndirectWired | Self::IndirectWireless | Self::IndirectVirtual
        )
    }

    pub fn is_wireless(self) -> bool {
        matches!(self, Self::Wireless | Self::IndirectWireless)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct DisplayInfo {
    pub id: String,
    pub name: String,
    pub connector: ConnectorKind,
    pub is_builtin: bool,
    pub is_primary: bool,
    pub width: u32,
    pub height: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub adapter: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub edid: Option<crate::edid::EdidInfo>,
    /// Same number => cloned (mirrored) source.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub clone_group: Option<u32>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProcessSnapshot {
    pub pid: u32,
    pub name: String,
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub original_filename: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_pid: Option<u32>,
    pub start_time_unix: u64,
    pub command_line: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AudioSession {
    pub pid: u32,
    pub name: String,
    pub device: String,
    pub capture: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct CameraDevice {
    pub id: String,
    pub name: String,
    pub virtual_device: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct OverlayWindow {
    pub handle: u64,
    pub pid: u32,
    pub exe: Option<String>,
    pub title: String,
    pub class_name: String,
    pub width: u32,
    pub height: u32,
    pub layered: bool,
    pub click_through: bool,
    pub topmost: bool,
    pub tool_window: bool,
    pub no_activate: bool,
    pub alpha: Option<u8>,
    pub exclude_from_capture: bool,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Inventory {
    pub hostname: Option<String>,
    pub os: Option<String>,
    pub os_version: Option<String>,
    pub environment: Option<crate::smbios::EnvironmentClassification>,
    pub displays: Vec<DisplayInfo>,
    pub audio_sessions: Vec<AudioSession>,
    pub cameras: Vec<CameraDevice>,
    pub remote_session: bool,
}
