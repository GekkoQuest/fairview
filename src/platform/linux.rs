use crate::edid;
use crate::error::Result;
use crate::evidence::{
    AudioSession, CameraDevice, ConnectorKind, Detector, DisplayInfo, Finding, ProcessSnapshot,
    Severity,
};
use crate::known;
use crate::overlay::OverlayObservation;
use crate::platform::RemoteStatus;
use crate::smbios::{EnvironmentFacts, FirmwareIdentity};
use serde_json::Value;
use std::fs;
use std::path::Path;
use std::process::Command;

pub fn enrich_processes(_procs: &mut [ProcessSnapshot]) {}

pub fn verify_signature(_path: &Path) -> crate::origin::SignatureStatus {
    crate::origin::SignatureStatus::Unknown
}

pub fn collect_displays() -> Result<Vec<DisplayInfo>> {
    let mut displays = Vec::new();
    let Ok(entries) = fs::read_dir("/sys/class/drm") else {
        return Ok(displays);
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        if !name.contains('-') {
            continue;
        }
        let status = fs::read_to_string(path.join("status")).unwrap_or_default();
        if !status.trim().eq_ignore_ascii_case("connected") {
            continue;
        }
        let edid_bytes = fs::read(path.join("edid")).ok();
        let parsed = edid_bytes.as_deref().and_then(edid::parse);
        let connector = linux_connector(&name);
        let (width, height) = modesize(path.join("modes"));
        let pretty = parsed
            .as_ref()
            .and_then(|e| e.name.clone())
            .unwrap_or_else(|| name.clone());
        displays.push(DisplayInfo {
            id: name.clone(),
            name: pretty,
            connector,
            is_builtin: matches!(connector, ConnectorKind::Internal),
            is_primary: displays.is_empty(),
            width,
            height,
            adapter: None,
            edid: parsed,
            clone_group: None,
        });
    }
    Ok(displays)
}

fn linux_connector(card_name: &str) -> ConnectorKind {
    let n = card_name.to_ascii_lowercase();
    if n.contains("edp") || n.contains("lvds") || n.contains("dsi") {
        ConnectorKind::Internal
    } else if n.contains("hdmi") {
        ConnectorKind::Hdmi
    } else if n.contains("displayport") || n.contains("-dp-") || n.contains("dp-") {
        ConnectorKind::DisplayPort
    } else if n.contains("dvi") {
        ConnectorKind::Dvi
    } else if n.contains("vga") {
        ConnectorKind::Vga
    } else if n.contains("virtual") || n.contains("vvirt") {
        ConnectorKind::IndirectVirtual
    } else {
        ConnectorKind::Unknown
    }
}

fn modesize(path: std::path::PathBuf) -> (u32, u32) {
    let Ok(text) = fs::read_to_string(path) else {
        return (0, 0);
    };
    let Some(first) = text.lines().next() else {
        return (0, 0);
    };
    let mut parts = first.split('x');
    let w = parts
        .next()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0);
    let h = parts
        .next()
        .and_then(|s| {
            s.trim()
                .trim_end_matches(|c: char| !c.is_ascii_digit())
                .parse()
                .ok()
        })
        .unwrap_or(0);
    (w, h)
}

pub fn collect_overlays() -> Result<Vec<OverlayObservation>> {
    // Wayland does not give unprivileged clients a global window list.
    // Returning an empty set is honest; we do not scrape xrandr/xwininfo.
    Ok(Vec::new())
}

pub fn collect_audio() -> Result<Vec<AudioSession>> {
    if let Some(sessions) = pipewire_capture_sessions() {
        return Ok(sessions);
    }
    Ok(alsa_capture_sessions())
}

fn pipewire_capture_sessions() -> Option<Vec<AudioSession>> {
    let output = Command::new("pw-dump").output().ok()?;
    if !output.status.success() {
        return None;
    }
    let value: Value = serde_json::from_slice(&output.stdout).ok()?;
    let arr = value.as_array()?;
    let mut sessions = Vec::new();
    for obj in arr {
        let props = obj
            .pointer("/info/props")
            .or_else(|| obj.get("info")?.get("props"))?;
        let class = props
            .get("media.class")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if class != "Stream/Input/Audio" && class != "Audio/Source" {
            continue;
        }
        if class == "Audio/Source" {
            continue; // device node, not a client capture stream
        }
        let pid = props
            .get("application.process.id")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32;
        if pid == 0 {
            continue;
        }
        let name = props
            .get("application.process.binary")
            .or_else(|| props.get("application.name"))
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();
        let device = props
            .get("node.name")
            .and_then(|v| v.as_str())
            .unwrap_or("pipewire")
            .to_string();
        sessions.push(AudioSession {
            pid,
            name,
            device,
            capture: true,
        });
    }
    Some(sessions)
}

fn alsa_capture_sessions() -> Vec<AudioSession> {
    let mut sessions = Vec::new();
    let Ok(cards) = fs::read_dir("/proc/asound") else {
        return sessions;
    };
    for card in cards.flatten() {
        let name = card.file_name().to_string_lossy().into_owned();
        if !name.starts_with("card") {
            continue;
        }
        let Ok(pcms) = fs::read_dir(card.path()) else {
            continue;
        };
        for pcm in pcms.flatten() {
            let pcm_name = pcm.file_name().to_string_lossy().into_owned();
            if !pcm_name.starts_with("pcm") || !pcm_name.contains('c') {
                continue;
            }
            let status_path = pcm.path().join("sub0/status");
            let Ok(status) = fs::read_to_string(status_path) else {
                continue;
            };
            if !status.contains("RUNNING") && !status.contains("state: RUNNING") {
                continue;
            }
            let owner_pid = status
                .lines()
                .find_map(|l| l.trim().strip_prefix("owner_pid"))
                .and_then(|s| s.split(':').last())
                .and_then(|s| s.trim().parse().ok())
                .unwrap_or(0);
            sessions.push(AudioSession {
                pid: owner_pid,
                name: String::new(),
                device: format!("{name}/{pcm_name}"),
                capture: true,
            });
        }
    }
    sessions
}

pub fn collect_cameras() -> Result<Vec<CameraDevice>> {
    let mut devices = Vec::new();
    let Ok(entries) = fs::read_dir("/sys/class/video4linux") else {
        return Ok(devices);
    };
    for entry in entries.flatten() {
        let id = entry.file_name().to_string_lossy().into_owned();
        let name = fs::read_to_string(entry.path().join("name"))
            .unwrap_or_else(|_| id.clone())
            .trim()
            .to_string();
        let virtual_device = known::virtual_camera_name(&name)
            || name.to_ascii_lowercase().contains("dummy")
            || name.to_ascii_lowercase().contains("v4l2loopback");
        devices.push(CameraDevice {
            id,
            name,
            virtual_device,
        });
    }
    Ok(devices)
}

pub fn collect_remote() -> Result<RemoteStatus> {
    let mut status = RemoteStatus::default();
    if let Some(n) = established_listeners(&[3389, 5900, 5901, 5902, 4172, 7070]) {
        if n > 0 {
            status.active_session = true;
            status.findings.push(
                Finding::new(
                    Detector::Remote,
                    "remote.established",
                    Severity::High,
                    0.8,
                    format!("{n} established connection(s) on remote-desktop ports"),
                )
                .detail("ports", "3389,5900-5902,4172,7070"),
            );
        }
    }
    Ok(status)
}

fn established_listeners(ports: &[u16]) -> Option<usize> {
    let mut n = 0;
    for path in ["/proc/net/tcp", "/proc/net/tcp6"] {
        let Ok(text) = fs::read_to_string(path) else {
            continue;
        };
        for line in text.lines().skip(1) {
            let cols: Vec<&str> = line.split_whitespace().collect();
            if cols.len() < 4 {
                continue;
            }
            // local_address remote_address st
            let Some(local_port) = cols[1]
                .split(':')
                .nth(1)
                .and_then(|h| u16::from_str_radix(h, 16).ok())
            else {
                continue;
            };
            if !ports.contains(&local_port) {
                continue;
            }
            if cols[3] == "01" {
                n += 1;
            }
        }
    }
    Some(n)
}

pub fn fill_environment(facts: &mut EnvironmentFacts) -> Result<()> {
    let (present, vendor) = crate::platform::cpuid_hypervisor();
    facts.cpuid_hypervisor = present;
    facts.cpuid_vendor = vendor;
    facts.mac_vm_vendors = crate::platform::mac_vm_vendors();
    facts.firmware = FirmwareIdentity {
        manufacturer: read_trim("/sys/class/dmi/id/sys_vendor"),
        product: read_trim("/sys/class/dmi/id/product_name"),
        version: read_trim("/sys/class/dmi/id/product_version"),
        bios_vendor: read_trim("/sys/class/dmi/id/bios_vendor"),
        strings: Vec::new(),
    };
    if let Some(hv) = read_trim("/sys/hypervisor/type") {
        facts.firmware.strings.push(format!("hypervisor_type={hv}"));
        if !facts.cpuid_hypervisor {
            facts.cpuid_hypervisor = true;
            if facts.cpuid_vendor.is_none() {
                facts.cpuid_vendor = Some(hv);
            }
        }
    }
    if cpuinfo_has_hypervisor() && !facts.cpuid_hypervisor {
        facts.cpuid_hypervisor = true;
    }
    Ok(())
}

fn read_trim(path: &str) -> Option<String> {
    fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty() && s != "None")
}

fn cpuinfo_has_hypervisor() -> bool {
    fs::read_to_string("/proc/cpuinfo")
        .ok()
        .is_some_and(|t| t.contains("hypervisor"))
}

#[allow(dead_code)]
fn _path_exists(p: &str) -> bool {
    Path::new(p).exists()
}
