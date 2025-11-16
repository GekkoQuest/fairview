use std::collections::HashMap;

pub struct HardwareDetector {
    baseline_displays: Option<DisplayConfiguration>,
}

#[derive(Debug, Clone)]
pub struct DisplayConfiguration {
    pub display_count: usize,
    pub displays: Vec<DisplayInfo>,
    pub has_virtual_display: bool,
    pub has_hdmi_splitter_signature: bool,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct DisplayInfo {
    pub id: String,
    pub name: String,
    pub width: u32,
    pub height: u32,
    pub is_primary: bool,
    pub connection_type: ConnectionType,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ConnectionType {
    HDMI,
    DisplayPort,
    USB,
    Virtual,
    Wireless,
    Unknown,
}

#[derive(Debug)]
pub struct HardwareSuspicion {
    pub risk_score: f64,
    pub flags: Vec<String>,
    pub details: HashMap<String, String>,
}

impl HardwareDetector {
    pub fn new() -> Self {
        Self {
            baseline_displays: None,
        }
    }

    pub fn set_baseline(&mut self) -> Result<(), String> {
        let config = self.get_current_display_configuration()?;
        self.baseline_displays = Some(config);
        Ok(())
    }

    pub fn get_baseline(&self) -> Option<&DisplayConfiguration> {
        self.baseline_displays.as_ref()
    }

    pub fn detect_hardware_cheating(&self) -> HardwareSuspicion {
        let mut suspicion = HardwareSuspicion {
            risk_score: 0.0,
            flags: Vec::new(),
            details: HashMap::new(),
        };

        let current_config = match self.get_current_display_configuration() {
            Ok(config) => config,
            Err(e) => {
                suspicion.flags.push(format!("Unable to detect display configuration: {}", e));
                suspicion.details.insert("error".to_string(), "display_detection_failed".to_string());
                return suspicion;
            }
        };

        suspicion.details.insert("display_count".to_string(), current_config.display_count.to_string());

        if current_config.has_hdmi_splitter_signature {
            suspicion.flags.push("HDMI splitter signature detected".to_string());
            suspicion.risk_score += 0.7;
        }

        if current_config.has_virtual_display {
            suspicion.flags.push("Virtual display detected".to_string());
            suspicion.risk_score += 0.5;
        }

        if current_config.display_count > 1 {
            suspicion.flags.push(format!("Multiple displays detected: {} displays", current_config.display_count));
            suspicion.risk_score += if current_config.display_count == 2 { 0.05 } else { 0.15 };
        }

        if let Some(ref baseline) = self.baseline_displays {
            if baseline.display_count != current_config.display_count {
                suspicion.flags.push(format!(
                    "Display configuration changed during interview (baseline: {}, current: {})",
                    baseline.display_count,
                    current_config.display_count
                ));
                suspicion.risk_score += 0.4;
            }

            let baseline_ids: Vec<_> = baseline.displays.iter().map(|d| &d.id).collect();
            for display in &current_config.displays {
                if !baseline_ids.contains(&&display.id) {
                    suspicion.flags.push(format!("New display connected during interview: {}", display.name));
                    suspicion.risk_score += 0.3;
                }
            }
        }

        for display in &current_config.displays {
            if display.connection_type == ConnectionType::USB {
                suspicion.flags.push(format!("USB display detected: {}", display.name));
                suspicion.risk_score += 0.2;
            }

            if display.connection_type == ConnectionType::Wireless {
                suspicion.flags.push(format!("Wireless display detected: {}", display.name));
                suspicion.risk_score += 0.25;
            }
        }

        if self.detect_remote_desktop_active() {
            suspicion.flags.push("Remote desktop connection detected".to_string());
            suspicion.risk_score += 0.8;
        }

        suspicion.risk_score = suspicion.risk_score.clamp(0.0, 1.0);
        suspicion
    }

    fn get_current_display_configuration(&self) -> Result<DisplayConfiguration, String> {
        #[cfg(target_os = "windows")]
        {
            self.get_windows_displays()
        }

        #[cfg(target_os = "macos")]
        {
            self.get_macos_displays()
        }

        #[cfg(target_os = "linux")]
        {
            self.get_linux_displays()
        }
    }

    fn detect_remote_desktop_active(&self) -> bool {
        #[cfg(target_os = "windows")]
        {
            self.check_windows_rdp()
        }

        #[cfg(target_os = "macos")]
        {
            self.check_macos_screen_sharing()
        }

        #[cfg(target_os = "linux")]
        {
            self.check_linux_remote_desktop()
        }
    }
}

#[cfg(target_os = "windows")]
impl HardwareDetector {
    fn get_windows_displays(&self) -> Result<DisplayConfiguration, String> {
        use std::mem;
        use windows::Win32::Graphics::Gdi::*;

        let mut displays = Vec::new();
        let mut has_virtual = false;
        let mut has_hdmi_splitter = false;

        unsafe {
            let mut device_num = 0u32;
            loop {
                let mut display_device: DISPLAY_DEVICEW = mem::zeroed();
                display_device.cb = mem::size_of::<DISPLAY_DEVICEW>() as u32;

                if EnumDisplayDevicesW(None, device_num, &mut display_device, 0).as_bool() {
                    let device_name = String::from_utf16_lossy(
                        &display_device.DeviceName.iter().take_while(|&&c| c != 0).copied().collect::<Vec<u16>>(),
                    );

                    let device_string = String::from_utf16_lossy(
                        &display_device.DeviceString.iter().take_while(|&&c| c != 0).copied().collect::<Vec<u16>>(),
                    );

                    if display_device.StateFlags & DISPLAY_DEVICE_ACTIVE != 0 {
                        let mut dev_mode: DEVMODEW = mem::zeroed();
                        dev_mode.dmSize = mem::size_of::<DEVMODEW>() as u16;

                        if EnumDisplaySettingsW(
                            windows::core::PCWSTR(display_device.DeviceName.as_ptr()),
                            ENUM_CURRENT_SETTINGS,
                            &mut dev_mode,
                        ).as_bool() {
                            let connection_type = self.detect_connection_type(&device_string);
                            let lower = device_string.to_lowercase();
                            
                            if lower.contains("virtual") || lower.contains("dummy") || 
                               (lower.contains("usb") && lower.contains("display")) {
                                has_virtual = true;
                            }

                            if device_string.contains("Generic PnP") || device_string.contains("Generic Non-PnP") {
                                has_hdmi_splitter = true;
                            }

                            displays.push(DisplayInfo {
                                id: device_name,
                                name: device_string,
                                width: dev_mode.dmPelsWidth,
                                height: dev_mode.dmPelsHeight,
                                is_primary: display_device.StateFlags & DISPLAY_DEVICE_PRIMARY_DEVICE != 0,
                                connection_type,
                            });
                        }
                    }
                    device_num += 1;
                } else {
                    break;
                }
            }
        }

        Ok(DisplayConfiguration {
            display_count: displays.len(),
            displays,
            has_virtual_display: has_virtual,
            has_hdmi_splitter_signature: has_hdmi_splitter,
        })
    }

    fn detect_connection_type(&self, device_string: &str) -> ConnectionType {
        let device_lower = device_string.to_lowercase();

        if device_lower.contains("hdmi") {
            ConnectionType::HDMI
        } else if device_lower.contains("displayport") || device_lower.contains("dp") {
            ConnectionType::DisplayPort
        } else if device_lower.contains("usb") {
            ConnectionType::USB
        } else if device_lower.contains("virtual") || device_lower.contains("dummy") {
            ConnectionType::Virtual
        } else if device_lower.contains("miracast") || device_lower.contains("wireless") {
            ConnectionType::Wireless
        } else {
            ConnectionType::Unknown
        }
    }

    fn check_windows_rdp(&self) -> bool {
        use std::process::Command;

        if let Ok(output) = Command::new("qwinsta").output() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                if line.contains("rdp-") && line.contains("Active") {
                    return true;
                }
            }
        }

        if let Ok(session_name) = std::env::var("SESSIONNAME") {
            if session_name.starts_with("RDP-") {
                return true;
            }
        }

        false
    }
}

#[cfg(target_os = "macos")]
impl HardwareDetector {
    fn get_macos_displays(&self) -> Result<DisplayConfiguration, String> {
        use std::process::Command;

        let mut displays = Vec::new();
        let mut has_virtual = false;

        if let Ok(output) = Command::new("system_profiler").arg("SPDisplaysDataType").output() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let mut current_display: Option<DisplayInfo> = None;

            for line in stdout.lines() {
                let line = line.trim();

                if line.starts_with("Display Type:") {
                    if let Some(display) = current_display.take() {
                        displays.push(display);
                    }

                    let display_type = line.split(':').nth(1).unwrap_or("").trim();

                    current_display = Some(DisplayInfo {
                        id: format!("display_{}", displays.len()),
                        name: display_type.to_string(),
                        width: 0,
                        height: 0,
                        is_primary: displays.is_empty(),
                        connection_type: self.parse_macos_connection(display_type),
                    });

                    if display_type.to_lowercase().contains("virtual") {
                        has_virtual = true;
                    }
                }

                if let Some(ref mut display) = current_display {
                    if line.starts_with("Resolution:") {
                        let res_str = line.split(':').nth(1).unwrap_or("").trim();
                        let parts: Vec<&str> = res_str.split('x').collect();
                        if parts.len() == 2 {
                            display.width = parts[0].trim().parse().unwrap_or(0);
                            display.height = parts[1].split('+').next()
                                .and_then(|s| s.trim().parse().ok()).unwrap_or(0);
                        }
                    }
                }
            }

            if let Some(display) = current_display {
                displays.push(display);
            }
        }

        Ok(DisplayConfiguration {
            display_count: displays.len(),
            displays,
            has_virtual_display: has_virtual,
            has_hdmi_splitter_signature: false,
        })
    }

    fn parse_macos_connection(&self, display_type: &str) -> ConnectionType {
        let type_lower = display_type.to_lowercase();

        if type_lower.contains("hdmi") {
            ConnectionType::HDMI
        } else if type_lower.contains("displayport") {
            ConnectionType::DisplayPort
        } else if type_lower.contains("usb-c") {
            ConnectionType::USB
        } else if type_lower.contains("wireless") {
            ConnectionType::Wireless
        } else if type_lower.contains("virtual") {
            ConnectionType::Virtual
        } else {
            ConnectionType::Unknown
        }
    }

    fn check_macos_screen_sharing(&self) -> bool {
        use std::process::Command;

        if let Ok(output) = Command::new("lsof").args(&["-i", ":5900"]).output() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if stdout.lines().count() > 1 {
                return true;
            }
        }

        false
    }
}

#[cfg(target_os = "linux")]
impl HardwareDetector {
    fn get_linux_displays(&self) -> Result<DisplayConfiguration, String> {
        use std::process::Command;

        let mut displays = Vec::new();
        let mut has_virtual = false;

        if let Ok(output) = Command::new("xrandr").arg("--query").output() {
            let stdout = String::from_utf8_lossy(&output.stdout);

            for line in stdout.lines() {
                if line.contains(" connected") {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 3 {
                        let name = parts[0].to_string();
                        let is_primary = line.contains("primary");

                        let mut width = 0;
                        let mut height = 0;
                        if let Some(res_part) = parts.iter().find(|p| p.contains('x')) {
                            let res: Vec<&str> = res_part.split('x').collect();
                            if res.len() == 2 {
                                width = res[0].parse().unwrap_or(0);
                                height = res[1].split('+').next()
                                    .and_then(|s| s.parse().ok()).unwrap_or(0);
                            }
                        }

                        let connection_type = self.parse_linux_connection(&name);

                        if name.to_lowercase().contains("virtual") {
                            has_virtual = true;
                        }

                        displays.push(DisplayInfo {
                            id: name.clone(),
                            name,
                            width,
                            height,
                            is_primary,
                            connection_type,
                        });
                    }
                }
            }
        }

        Ok(DisplayConfiguration {
            display_count: displays.len(),
            displays,
            has_virtual_display: has_virtual,
            has_hdmi_splitter_signature: false,
        })
    }

    fn parse_linux_connection(&self, output_name: &str) -> ConnectionType {
        let name_lower = output_name.to_lowercase();

        if name_lower.starts_with("hdmi") {
            ConnectionType::HDMI
        } else if name_lower.starts_with("dp") || name_lower.starts_with("displayport") {
            ConnectionType::DisplayPort
        } else if name_lower.contains("virtual") {
            ConnectionType::Virtual
        } else {
            ConnectionType::Unknown
        }
    }

    fn check_linux_remote_desktop(&self) -> bool {
        use std::process::Command;

        if let Ok(output) = Command::new("netstat").args(&["-tuln"]).output() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                if line.contains(":590") && line.contains("LISTEN") {
                    return true;
                }
            }
        }

        false
    }
}