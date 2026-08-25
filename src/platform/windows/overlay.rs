use crate::error::Result;
use crate::overlay::OverlayObservation;
use crate::platform::windows::util::{decode_wide, hwnd_to_u64};
use windows::Win32::Foundation::{BOOL, HWND, LPARAM, RECT};
use windows::Win32::Graphics::Dwm::{DwmGetWindowAttribute, DWMWA_CLOAKED};
use windows::Win32::UI::WindowsAndMessaging::{
    EnumWindows, GetClassNameW, GetLayeredWindowAttributes, GetWindowDisplayAffinity,
    GetWindowLongW, GetWindowRect, GetWindowTextW, GetWindowThreadProcessId, IsWindowVisible,
    GWL_EXSTYLE, WS_EX_LAYERED, WS_EX_NOACTIVATE, WS_EX_TOOLWINDOW, WS_EX_TOPMOST,
    WS_EX_TRANSPARENT,
};

const WDA_EXCLUDEFROMCAPTURE: u32 = 0x11;

struct Acc {
    windows: Vec<OverlayObservation>,
}

pub fn collect_overlays() -> Result<Vec<OverlayObservation>> {
    let mut acc = Acc {
        windows: Vec::new(),
    };
    unsafe {
        // EnumWindows is synchronous; `acc` lives for the whole walk.
        let _ = EnumWindows(Some(enum_proc), LPARAM(&mut acc as *mut Acc as isize));
    }
    Ok(acc.windows)
}

unsafe extern "system" fn enum_proc(hwnd: HWND, lparam: LPARAM) -> BOOL {
    let acc = &mut *(lparam.0 as *mut Acc);
    if let Some(obs) = inspect(hwnd) {
        acc.windows.push(obs);
    }
    BOOL(1)
}

unsafe fn inspect(hwnd: HWND) -> Option<OverlayObservation> {
    let visible = IsWindowVisible(hwnd).as_bool();
    let mut cloaked: u32 = 0;
    let _ = DwmGetWindowAttribute(
        hwnd,
        DWMWA_CLOAKED,
        &mut cloaked as *mut u32 as *mut _,
        std::mem::size_of::<u32>() as u32,
    );
    let cloaked = cloaked != 0;

    let mut rect = RECT::default();
    GetWindowRect(hwnd, &mut rect).ok()?;
    let width = rect.right.saturating_sub(rect.left).max(0) as u32;
    let height = rect.bottom.saturating_sub(rect.top).max(0) as u32;
    if width < 2 && height < 2 {
        return None;
    }

    let ex = GetWindowLongW(hwnd, GWL_EXSTYLE) as u32;
    let layered = ex & WS_EX_LAYERED.0 != 0;
    let click_through = ex & WS_EX_TRANSPARENT.0 != 0;
    let topmost = ex & WS_EX_TOPMOST.0 != 0;
    let tool_window = ex & WS_EX_TOOLWINDOW.0 != 0;
    let no_activate = ex & WS_EX_NOACTIVATE.0 != 0;

    let mut affinity: u32 = 0;
    let exclude_from_capture =
        GetWindowDisplayAffinity(hwnd, &mut affinity).is_ok() && affinity == WDA_EXCLUDEFROMCAPTURE;

    // Skip boring visible windows early: no overlay-ish styles and not excluded.
    if !layered && !topmost && !exclude_from_capture && !click_through {
        return None;
    }

    let mut title_buf = [0u16; 256];
    let tlen = GetWindowTextW(hwnd, &mut title_buf);
    let title = if tlen > 0 {
        decode_wide(&title_buf[..tlen as usize])
    } else {
        String::new()
    };

    let mut class_buf = [0u16; 256];
    let clen = GetClassNameW(hwnd, &mut class_buf);
    let class_name = if clen > 0 {
        decode_wide(&class_buf[..clen as usize])
    } else {
        String::new()
    };

    let mut pid: u32 = 0;
    GetWindowThreadProcessId(hwnd, Some(&mut pid));

    let mut alpha: Option<u8> = None;
    if layered {
        let mut key = windows::Win32::Foundation::COLORREF(0);
        let mut a: u8 = 0;
        let mut flags = windows::Win32::UI::WindowsAndMessaging::LAYERED_WINDOW_ATTRIBUTES_FLAGS(0);
        if GetLayeredWindowAttributes(hwnd, Some(&mut key), Some(&mut a), Some(&mut flags)).is_ok()
        {
            alpha = Some(a);
        }
    }

    let exe = super::process::path_for_pid(pid);

    Some(OverlayObservation {
        handle: hwnd_to_u64(hwnd),
        pid,
        exe,
        title,
        class_name,
        width,
        height,
        visible,
        cloaked,
        layered,
        click_through,
        topmost,
        tool_window,
        no_activate,
        alpha,
        exclude_from_capture,
        sharing_none: false,
        window_layer: 0,
    })
}
