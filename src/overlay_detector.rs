use crate::OverlayWindow;

pub struct OverlayDetector;

impl OverlayDetector {
    pub fn new() -> Self {
        Self
    }

    pub fn find_hidden_overlays(&self) -> Vec<OverlayWindow> {
        #[cfg(target_os = "windows")]
        {
            return self.find_windows_overlays();
        }

        #[cfg(not(target_os = "windows"))]
        {
            Vec::new()
        }
    }
}

#[cfg(target_os = "windows")]
impl OverlayDetector {
    fn find_windows_overlays(&self) -> Vec<OverlayWindow> {
        use std::sync::{Arc, Mutex};
        use windows::Win32::UI::WindowsAndMessaging::*;
        use windows::Win32::Foundation::*;

        let overlays = Arc::new(Mutex::new(Vec::new()));
        let overlays_clone = Arc::clone(&overlays);

        unsafe {
            let ptr = Arc::as_ptr(&overlays_clone) as isize;
            let _ = EnumWindows(Some(Self::enum_window_callback), LPARAM(ptr));
        }

        let mut guard = overlays.lock().unwrap();
        std::mem::take(&mut *guard)
    }

    unsafe extern "system" fn enum_window_callback(
        hwnd: windows::Win32::Foundation::HWND, 
        lparam: windows::Win32::Foundation::LPARAM
    ) -> windows::Win32::Foundation::BOOL {
        use std::sync::Mutex;
        use windows::Win32::UI::WindowsAndMessaging::*;
        use windows::Win32::Foundation::*;

        let overlays: &Mutex<Vec<OverlayWindow>> =
            &*(lparam.0 as *const Mutex<Vec<OverlayWindow>>);

        let ex_style = GetWindowLongW(hwnd, GWL_EXSTYLE) as u32;
        let is_layered = (ex_style & WS_EX_LAYERED.0) != 0;
        let is_transparent = (ex_style & WS_EX_TRANSPARENT.0) != 0;
        let is_topmost = (ex_style & WS_EX_TOPMOST.0) != 0;

        if is_layered && (is_transparent || is_topmost) {
            let mut rect = RECT::default();

            if GetWindowRect(hwnd, &mut rect).is_ok() {
                let width = (rect.right - rect.left) as u32;
                let height = (rect.bottom - rect.top) as u32;

                if width > 50 && height > 50 {
                    let mut pid: u32 = 0;
                    GetWindowThreadProcessId(hwnd, Some(&mut pid));

                    let is_visible = IsWindowVisible(hwnd).as_bool();

                    if is_visible || is_topmost {
                        if let Ok(mut overlays_guard) = overlays.lock() {
                            overlays_guard.push(OverlayWindow {
                                handle: hwnd.0 as usize,
                                position: (rect.left, rect.top),
                                size: (width, height),
                                owner_pid: pid,
                                is_transparent,
                                is_topmost,
                            });
                        }
                    }
                }
            }
        }

        BOOL(1)
    }
}