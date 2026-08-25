//! Named-tool catalogs. Names are a *supporting* signal, never the only one
//! for overlays/audio/displays. Process matching uses exact image names and
//! OriginalFilename, not `contains("gpt")`.

use crate::evidence::ProcessSnapshot;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolKind {
    InterviewAssistant,
    RemoteAccess,
    VirtualDisplay,
    VirtualCamera,
    ScreenCapture,
}

#[derive(Debug, Clone, Copy)]
pub struct KnownTool {
    pub kind: ToolKind,
    pub label: &'static str,
    /// Lowercase image names, with or without .exe.
    pub names: &'static [&'static str],
}

pub const INTERVIEW_ASSISTANTS: &[KnownTool] = &[
    KnownTool {
        kind: ToolKind::InterviewAssistant,
        label: "Cluely",
        names: &["cluely", "cluely.exe", "cluelyhelper", "cluely-helper"],
    },
    KnownTool {
        kind: ToolKind::InterviewAssistant,
        label: "Interview Coder",
        names: &["interviewcoder", "interview-coder", "interview_coder"],
    },
    KnownTool {
        kind: ToolKind::InterviewAssistant,
        label: "Final Round AI",
        names: &["finalround", "finalroundai", "final-round"],
    },
    KnownTool {
        kind: ToolKind::InterviewAssistant,
        label: "LockedIn AI",
        names: &["lockedin", "lockedinai"],
    },
    KnownTool {
        kind: ToolKind::InterviewAssistant,
        label: "Ultra",
        names: &["ultrai", "ultra-interview"],
    },
];

pub const REMOTE_ACCESS: &[KnownTool] = &[
    KnownTool {
        kind: ToolKind::RemoteAccess,
        label: "AnyDesk",
        names: &["anydesk"],
    },
    KnownTool {
        kind: ToolKind::RemoteAccess,
        label: "TeamViewer",
        names: &["teamviewer", "tv_w32", "tv_x64"],
    },
    KnownTool {
        kind: ToolKind::RemoteAccess,
        label: "RustDesk",
        names: &["rustdesk"],
    },
    KnownTool {
        kind: ToolKind::RemoteAccess,
        label: "Splashtop",
        names: &["splashtop", "srserver", "strwinclt"],
    },
    KnownTool {
        kind: ToolKind::RemoteAccess,
        label: "Parsec",
        names: &["parsecd", "parsec"],
    },
    KnownTool {
        kind: ToolKind::RemoteAccess,
        label: "Sunshine",
        names: &["sunshine"],
    },
    KnownTool {
        kind: ToolKind::RemoteAccess,
        label: "Moonlight",
        names: &["moonlight"],
    },
    KnownTool {
        kind: ToolKind::RemoteAccess,
        label: "Chrome Remote Desktop",
        names: &["remoting_host", "chromoting"],
    },
    KnownTool {
        kind: ToolKind::RemoteAccess,
        label: "ToDesk",
        names: &["todesk"],
    },
    KnownTool {
        kind: ToolKind::RemoteAccess,
        label: "TightVNC",
        names: &["tvnserver", "tightvnc"],
    },
    KnownTool {
        kind: ToolKind::RemoteAccess,
        label: "UltraVNC",
        names: &["winvnc", "ultravnc"],
    },
    KnownTool {
        kind: ToolKind::RemoteAccess,
        label: "RealVNC",
        names: &["vncserver", "winvnc4"],
    },
    KnownTool {
        kind: ToolKind::RemoteAccess,
        label: "AweSun",
        names: &["awesun"],
    },
    KnownTool {
        kind: ToolKind::RemoteAccess,
        label: "DWAgent",
        names: &["dwagent", "dwagsvc"],
    },
    KnownTool {
        kind: ToolKind::RemoteAccess,
        label: "Apple Screen Sharing",
        names: &["screensharingd", "applevncserver", "ardagent"],
    },
];

pub const VIRTUAL_DISPLAY: &[KnownTool] = &[
    KnownTool {
        kind: ToolKind::VirtualDisplay,
        label: "spacedesk",
        names: &["spacedesk", "spacedeskserver", "spacedeskwindows"],
    },
    KnownTool {
        kind: ToolKind::VirtualDisplay,
        label: "USB Mobile Monitor",
        names: &["usbmmidd"],
    },
    KnownTool {
        kind: ToolKind::VirtualDisplay,
        label: "IddSampleDriver",
        names: &["iddsampledriver"],
    },
    KnownTool {
        kind: ToolKind::VirtualDisplay,
        label: "Virtual Display Driver",
        names: &["virtualdisplaydriver", "nefariusvirtualdisplay"],
    },
];

pub const MEETING_APPS: &[&str] = &[
    "zoom",
    "zoom.exe",
    "teams",
    "ms-teams",
    "msteams",
    "slack",
    "webex",
    "ciscowebexstart",
    "skype",
    "discord",
    "element",
    "signal",
];

pub const BROWSERS: &[&str] = &[
    "chrome", "msedge", "firefox", "brave", "opera", "vivaldi", "safari", "chromium", "arc",
];

pub const EDITORS: &[&str] = &[
    "code",
    "code - insiders",
    "cursor",
    "windsurf",
    "zed",
    "subl",
    "sublime_text",
    "idea64",
    "pycharm64",
    "webstorm64",
    "devenv",
    "rider64",
    "nvim",
    "vim",
    "emacs",
];

pub const OS_NOISE: &[&str] = &[
    "system",
    "idle",
    "registry",
    "smss",
    "csrss",
    "wininit",
    "winlogon",
    "services",
    "lsass",
    "svchost",
    "dwm",
    "explorer",
    "fontdrvhost",
    "sihost",
    "taskhostw",
    "runtimebroker",
    "searchhost",
    "shellexperiencehost",
    "startmenuexperiencehost",
    "securityhealthsystray",
    "conhost",
    "csrss.exe",
    "windowserver",
    "kernel_task",
    "launchd",
    "systemd",
    "init",
    "kthreadd",
];

pub fn normalize_image_name(name: &str) -> String {
    let n = name.rsplit(['/', '\\']).next().unwrap_or(name);
    let n = n.strip_suffix(".exe").unwrap_or(n);
    n.trim().to_ascii_lowercase()
}

pub fn match_tool(
    proc: &ProcessSnapshot,
    catalog: &'static [KnownTool],
) -> Option<&'static KnownTool> {
    let names = candidate_names(proc);
    catalog.iter().find(|tool| {
        tool.names.iter().any(|needle| {
            let n = normalize_image_name(needle);
            names.iter().any(|have| have == &n)
        })
    })
}

pub fn candidate_names(proc: &ProcessSnapshot) -> Vec<String> {
    let mut out = Vec::new();
    out.push(normalize_image_name(&proc.name));
    if !proc.path.is_empty() {
        out.push(normalize_image_name(&proc.path));
    }
    if let Some(orig) = &proc.original_filename {
        out.push(normalize_image_name(orig));
    }
    out.sort();
    out.dedup();
    out
}

pub fn is_meeting_app(name: &str) -> bool {
    let n = normalize_image_name(name);
    MEETING_APPS.iter().any(|m| n == normalize_image_name(m))
}

pub fn is_os_noise(name: &str) -> bool {
    let n = normalize_image_name(name);
    OS_NOISE.iter().any(|m| n == normalize_image_name(m))
}

pub fn is_browser(name: &str) -> bool {
    let n = normalize_image_name(name);
    BROWSERS.iter().any(|m| n == normalize_image_name(m))
}

pub fn is_editor(name: &str) -> bool {
    let n = normalize_image_name(name);
    EDITORS.iter().any(|m| n == normalize_image_name(m))
}

pub fn virtual_camera_name(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    const NEEDLES: &[&str] = &[
        "obs virtual",
        "obs-camera",
        "virtual camera",
        "virtualcam",
        "manycam",
        "snap camera",
        "xsplit vcam",
        "iriun",
        "droidcam",
        "epoccam",
        "unity video capture",
        "ndi video",
    ];
    NEEDLES.iter().any(|k| n.contains(k))
}

pub fn capture_card_name(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    const NEEDLES: &[&str] = &[
        "cam link",
        "elgato",
        "magewell",
        "avermedia",
        "live gamer",
        "intensity",
        "hdmi capture",
        "usb video",
        "uvc camera",
    ];
    NEEDLES.iter().any(|k| n.contains(k))
}

/// Window classes that are OS chrome, IME, or well-known game overlays.
pub fn is_system_window_class(class: &str) -> bool {
    matches!(
        class,
        "Shell_TrayWnd"
            | "Shell_SecondaryTrayWnd"
            | "Progman"
            | "WorkerW"
            | "ForegroundStaging"
            | "ApplicationFrameWindow"
            | "Windows.UI.Core.CoreWindow"
            | "XamlExplorerHostIslandWindow"
            | "tooltips_class32"
            | "IME"
            | "MSCTFIME UI"
            | "GDI+ Hook Window Class"
            | "Auto-Suggest Dropdown"
            | "CiceroUIWndFrame"
            | "DummyDWMListenerWindow"
            | "Dwm"
            | "Windows.Internal.Shell.TabProxyWindow"
            | "Xaml_WindowedPopupClass"
            | "SystemTray_Main"
            | "NotifyIconOverflowWindow"
            | "TopLevelWindowForOverflowXamlIsland"
    )
}

pub fn is_known_overlay_owner(exe_name: &str, class: &str) -> bool {
    let n = normalize_image_name(exe_name);
    if matches!(
        n.as_str(),
        "nvidia share"
            | "nvcontainer"
            | "nvidia overlay"
            | "textinputhost"
            | "gamebar"
            | "gamebarftw"
            | "steam"
            | "steamwebhelper"
            | "discord"
            | "powertoys"
            | "powertoys.alwaysontop"
            | "sharex"
            | "rainmeter"
            | "translucenttb"
            | "explorer"
            | "dwm"
            | "searchhost"
            | "startmenuexperiencehost"
            | "shellexperiencehost"
            | "logioptionsplus"
            | "lghub"
            | "msedgewebview2"
    ) {
        return true;
    }
    class.contains("CEF-OSC-WIDGET") || class.contains("NVIDIA") || class.contains("UnityWndClass")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proc(name: &str, path: &str, orig: Option<&str>) -> ProcessSnapshot {
        ProcessSnapshot {
            pid: 1,
            name: name.into(),
            path: path.into(),
            original_filename: orig.map(|s| s.into()),
            parent_pid: None,
            start_time_unix: 0,
            command_line: String::new(),
        }
    }

    #[test]
    fn renamed_cluely_caught_via_original_filename() {
        let p = proc("svchost.exe", r"C:\Users\a\svchost.exe", Some("cluely.exe"));
        let tool = match_tool(&p, INTERVIEW_ASSISTANTS).expect("cluely");
        assert_eq!(tool.label, "Cluely");
    }

    #[test]
    fn chatgpt_in_chrome_is_not_a_process_match() {
        let p = proc(
            "chrome.exe",
            r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            None,
        );
        assert!(match_tool(&p, INTERVIEW_ASSISTANTS).is_none());
    }

    #[test]
    fn exact_name_not_substring() {
        assert!(!is_meeting_app("zoom-helper-not-a-real-app-extra"));
        assert!(is_meeting_app("Zoom.exe"));
        assert!(is_meeting_app("ms-teams"));
    }
}
