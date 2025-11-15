use crate::Process;
use sysinfo::System;

pub struct ProcessMonitor;

impl ProcessMonitor {
    pub fn new() -> Self {
        Self
    }

    pub fn get_all_processes(&self) -> Vec<Process> {
        let mut system = System::new_all();
        system.refresh_all();
        
        let mut processes = Vec::new();
        
        for (pid, process) in system.processes() {
            processes.push(Process {
                pid: pid.as_u32(),
                name: process.name().to_string(),
                path: process.exe()
                    .map(|p| p.to_string_lossy().to_string())
                    .unwrap_or_else(|| "Unknown".to_string()),
            });
        }
        
        processes
    }

    pub fn has_screen_capture_permission(&self, process: &Process) -> bool {
        #[cfg(target_os = "macos")]
        {
            self.check_macos_permission(process, "kTCCServiceScreenCapture")
        }

        #[cfg(target_os = "windows")]
        {
            self.check_windows_screen_capture(process)
        }

        #[cfg(target_os = "linux")]
        {
            // For Linux, use heuristic based on process name
            let name_lower = process.name.to_lowercase();
            let known_apps = ["obs", "zoom", "teams", "discord", "slack", "chrome", "firefox"];
            let suspicious = ["cluely", "interview", "assistant", "helper"];
            
            known_apps.iter().any(|&app| name_lower.contains(app)) ||
            suspicious.iter().any(|&app| name_lower.contains(app))
        }
    }

    pub fn has_audio_capture_permission(&self, process: &Process) -> bool {
        #[cfg(target_os = "macos")]
        {
            self.check_macos_permission(process, "kTCCServiceMicrophone")
        }

        #[cfg(target_os = "windows")]
        {
            self.check_windows_audio_capture(process)
        }

        #[cfg(target_os = "linux")]
        {
            self.check_linux_audio_capture(process)
        }
    }

    pub fn has_accessibility_permission(&self, process: &Process) -> bool {
        #[cfg(target_os = "macos")]
        {
            self.check_macos_permission(process, "kTCCServiceAccessibility")
        }

        #[cfg(target_os = "windows")]
        {
            self.check_windows_accessibility(process)
        }

        #[cfg(target_os = "linux")]
        {
            self.check_linux_accessibility(process)
        }
    }
}

#[cfg(target_os = "macos")]
impl ProcessMonitor {
    fn check_macos_permission(&self, process: &Process, _service: &str) -> bool {
        let name_lower = process.name.to_lowercase();
        let known_apps = ["obs", "zoom", "teams", "discord", "slack", "chrome", "firefox"];
        let suspicious = ["cluely", "interview", "assistant", "helper"];
        
        known_apps.iter().any(|&app| name_lower.contains(app)) ||
        suspicious.iter().any(|&app| name_lower.contains(app))
    }
}

#[cfg(target_os = "windows")]
impl ProcessMonitor {
    fn check_windows_screen_capture(&self, process: &Process) -> bool {
        let loaded_modules = self.get_loaded_modules(process.pid);
        
        let screen_capture_dlls = vec!["dxgi.dll", "dwmapi.dll", "d3d11.dll", "gdi32.dll"];

        screen_capture_dlls.iter()
            .any(|dll| loaded_modules.iter().any(|m| m.to_lowercase().contains(dll)))
    }

    fn check_windows_audio_capture(&self, process: &Process) -> bool {
        let loaded_modules = self.get_loaded_modules(process.pid);
        
        let audio_dlls = vec!["audioses.dll", "wasapi", "winmm.dll", "dsound.dll"];

        audio_dlls.iter()
            .any(|dll| loaded_modules.iter().any(|m| m.to_lowercase().contains(dll)))
    }

    fn check_windows_accessibility(&self, process: &Process) -> bool {
        let loaded_modules = self.get_loaded_modules(process.pid);
        
        loaded_modules.iter().any(|m| {
            let m_lower = m.to_lowercase();
            m_lower.contains("uiautomation") || m_lower.contains("oleacc.dll")
        })
    }

    fn get_loaded_modules(&self, pid: u32) -> Vec<String> {
        use windows::Win32::System::Diagnostics::ToolHelp::*;
        use windows::Win32::Foundation::*;
        
        let mut modules = Vec::new();
        
        unsafe {
            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
            
            if let Ok(snapshot) = snapshot {
                let mut module_entry = MODULEENTRY32W {
                    dwSize: std::mem::size_of::<MODULEENTRY32W>() as u32,
                    ..Default::default()
                };

                if Module32FirstW(snapshot, &mut module_entry).is_ok() {
                    loop {
                        let module_name = String::from_utf16_lossy(
                            &module_entry.szModule
                                .iter()
                                .take_while(|&&c| c != 0)
                                .copied()
                                .collect::<Vec<u16>>()
                        );
                        
                        modules.push(module_name);

                        if Module32NextW(snapshot, &mut module_entry).is_err() {
                            break;
                        }
                    }
                }

                let _ = CloseHandle(snapshot);
            }
        }
        
        modules
    }
}

#[cfg(target_os = "linux")]
impl ProcessMonitor {
    fn check_linux_audio_capture(&self, process: &Process) -> bool {
        use std::fs;
        
        let fd_path = format!("/proc/{}/fd", process.pid);
        
        if let Ok(entries) = fs::read_dir(&fd_path) {
            for entry in entries.flatten() {
                if let Ok(link) = fs::read_link(entry.path()) {
                    let link_str = link.to_string_lossy();
                    if link_str.contains("/dev/snd") || 
                       link_str.contains("pulse") ||
                       link_str.contains("pipewire") {
                        return true;
                    }
                }
            }
        }

        false
    }

    fn check_linux_accessibility(&self, process: &Process) -> bool {
        use std::fs;
        
        let maps_path = format!("/proc/{}/maps", process.pid);
        
        if let Ok(maps) = fs::read_to_string(maps_path) {
            return maps.contains("at-spi") || maps.contains("atspi");
        }

        false
    }
}