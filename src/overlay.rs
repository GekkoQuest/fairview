//! Overlay classification from observed window attributes.
//! Platform code fills [`OverlayObservation`]; this module decides what it means.

use crate::evidence::{Detector, Finding, OverlayWindow, ProcessRef, Severity};
use crate::known;

#[derive(Debug, Clone)]
pub struct OverlayObservation {
    pub handle: u64,
    pub pid: u32,
    pub exe: Option<String>,
    pub title: String,
    pub class_name: String,
    pub width: u32,
    pub height: u32,
    pub visible: bool,
    pub cloaked: bool,
    pub layered: bool,
    pub click_through: bool,
    pub topmost: bool,
    pub tool_window: bool,
    pub no_activate: bool,
    pub alpha: Option<u8>,
    pub exclude_from_capture: bool,
    /// macOS window sharing state: 0 = none (hidden from capture).
    pub sharing_none: bool,
    pub window_layer: i32,
}

impl OverlayObservation {
    pub fn to_window(&self) -> OverlayWindow {
        OverlayWindow {
            handle: self.handle,
            pid: self.pid,
            exe: self.exe.clone(),
            title: self.title.clone(),
            class_name: self.class_name.clone(),
            width: self.width,
            height: self.height,
            layered: self.layered,
            click_through: self.click_through,
            topmost: self.topmost,
            tool_window: self.tool_window,
            no_activate: self.no_activate,
            alpha: self.alpha,
            exclude_from_capture: self.exclude_from_capture,
        }
    }

    fn exe_name(&self) -> String {
        self.exe
            .as_deref()
            .map(known::normalize_image_name)
            .unwrap_or_default()
    }

    fn sizable(&self) -> bool {
        self.width >= 80 && self.height >= 40
    }

    pub fn is_reportable(&self) -> bool {
        if self.cloaked || !self.sizable() {
            return false;
        }
        if known::is_system_window_class(&self.class_name) {
            return false;
        }
        let exe = self.exe_name();
        if !exe.is_empty()
            && (known::is_known_overlay_owner(&exe, &self.class_name) || known::is_os_noise(&exe))
        {
            return self.exclude_from_capture || self.sharing_none;
        }
        self.exclude_from_capture
            || self.sharing_none
            || (self.layered && self.click_through)
            || (self.layered && self.topmost && self.tool_window && self.no_activate)
    }
}

pub fn classify(
    obs: &OverlayObservation,
    is_expected_owner: impl Fn(&str) -> bool,
) -> Option<Finding> {
    if obs.cloaked || (!obs.visible && !obs.exclude_from_capture && !obs.sharing_none) {
        return None;
    }
    if known::is_system_window_class(&obs.class_name) {
        return None;
    }
    let exe = obs.exe_name();
    if !exe.is_empty() && known::is_known_overlay_owner(&exe, &obs.class_name) {
        return None;
    }
    if !exe.is_empty() && (is_expected_owner(&exe) || known::is_os_noise(&exe)) {
        // Meeting apps and the OS still should not exclude themselves from capture
        // with a click-through overlay. Only skip the mild overlay shapes.
        if !obs.exclude_from_capture && !obs.sharing_none {
            return None;
        }
    }
    if !obs.sizable() {
        return None;
    }

    let proc = ProcessRef {
        pid: obs.pid,
        name: exe.clone(),
        path: obs.exe.clone(),
    };

    if obs.exclude_from_capture || obs.sharing_none {
        return Some(
            Finding::new(
                Detector::Overlay,
                "overlay.exclude_from_capture",
                Severity::High,
                0.9,
                format!(
                    "Window from pid {} is marked hidden from screen capture ({}x{})",
                    obs.pid, obs.width, obs.height
                ),
            )
            .detail("class", obs.class_name.clone())
            .detail("title", obs.title.clone())
            .detail("handle", obs.handle.to_string())
            .with_process(proc),
        );
    }

    let stealth = obs.click_through && (obs.topmost || obs.no_activate) && obs.layered;
    if stealth {
        return Some(
            Finding::new(
                Detector::Overlay,
                "overlay.click_through_topmost",
                Severity::High,
                0.85,
                format!(
                    "Click-through layered topmost window from pid {} ({}x{})",
                    obs.pid, obs.width, obs.height
                ),
            )
            .detail("class", obs.class_name.clone())
            .detail("title", obs.title.clone())
            .detail("alpha", format!("{:?}", obs.alpha))
            .detail("handle", obs.handle.to_string())
            .with_process(proc),
        );
    }

    let helper = obs.layered
        && obs.topmost
        && obs.tool_window
        && obs.no_activate
        && obs.alpha.is_some_and(|a| a < 255);
    if helper {
        return Some(
            Finding::new(
                Detector::Overlay,
                "overlay.layered_tool_window",
                Severity::Medium,
                0.6,
                format!(
                    "Transparent tool window from pid {} ({}x{}, alpha={:?})",
                    obs.pid, obs.width, obs.height, obs.alpha
                ),
            )
            .detail("class", obs.class_name.clone())
            .detail("handle", obs.handle.to_string())
            .with_process(proc),
        );
    }

    // Floating high-layer windows on macOS (layer >> 0) from unexpected owners.
    if obs.window_layer >= 3 && obs.alpha.is_some_and(|a| a < 230) && !exe.is_empty() {
        return Some(
            Finding::new(
                Detector::Overlay,
                "overlay.high_layer_transparent",
                Severity::Medium,
                0.55,
                format!(
                    "Transparent high-layer window from pid {} (layer {})",
                    obs.pid, obs.window_layer
                ),
            )
            .detail("class", obs.class_name.clone())
            .with_process(proc),
        );
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> OverlayObservation {
        OverlayObservation {
            handle: 1,
            pid: 42,
            exe: Some(r"C:\Users\a\helper.exe".into()),
            title: String::new(),
            class_name: "TransparentOverlay".into(),
            width: 1920,
            height: 1080,
            visible: true,
            cloaked: false,
            layered: true,
            click_through: true,
            topmost: true,
            tool_window: true,
            no_activate: true,
            alpha: Some(1),
            exclude_from_capture: false,
            sharing_none: false,
            window_layer: 0,
        }
    }

    #[test]
    fn click_through_overlay_is_high() {
        let f = classify(&base(), |_| false).unwrap();
        assert_eq!(f.signal, "overlay.click_through_topmost");
        assert_eq!(f.severity, Severity::High);
    }

    #[test]
    fn exclude_from_capture_is_high() {
        let mut o = base();
        o.click_through = false;
        o.exclude_from_capture = true;
        let f = classify(&o, |_| false).unwrap();
        assert_eq!(f.signal, "overlay.exclude_from_capture");
    }

    #[test]
    fn discord_overlay_ignored() {
        let mut o = base();
        o.exe = Some(r"C:\Users\a\AppData\Discord\Discord.exe".into());
        assert!(classify(&o, |_| false).is_none());
        assert!(!o.is_reportable());
    }

    #[test]
    fn unknown_click_through_is_reportable() {
        assert!(base().is_reportable());
    }

    #[test]
    fn expected_owner_without_stealth_capture_flag_ignored() {
        let mut o = base();
        o.click_through = false;
        o.topmost = false;
        o.layered = false;
        o.exe = Some("zoom.exe".into());
        assert!(classify(&o, |n| n == "zoom").is_none());
    }

    #[test]
    fn taskbar_class_ignored() {
        let mut o = base();
        o.class_name = "Shell_TrayWnd".into();
        assert!(classify(&o, |_| false).is_none());
    }
}
