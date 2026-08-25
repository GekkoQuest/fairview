#[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
use crate::error::Result;
use crate::evidence::{AudioSession, CameraDevice, DisplayInfo, Finding, ProcessSnapshot};
use crate::overlay::OverlayObservation;
use crate::smbios::EnvironmentFacts;

#[derive(Debug, Default)]
pub struct RemoteStatus {
    pub active_session: bool,
    pub findings: Vec<Finding>,
}

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::{
    collect_audio, collect_cameras, collect_displays, collect_overlays, collect_remote,
    enrich_processes, fill_environment, verify_signature,
};

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub use macos::{
    collect_audio, collect_cameras, collect_displays, collect_overlays, collect_remote,
    enrich_processes, fill_environment, verify_signature,
};

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::{
    collect_audio, collect_cameras, collect_displays, collect_overlays, collect_remote,
    enrich_processes, fill_environment, verify_signature,
};

#[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
pub fn collect_displays() -> Result<Vec<DisplayInfo>> {
    Ok(Vec::new())
}

#[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
pub fn collect_overlays() -> Result<Vec<OverlayObservation>> {
    Ok(Vec::new())
}

#[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
pub fn collect_audio() -> Result<Vec<AudioSession>> {
    Ok(Vec::new())
}

#[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
pub fn collect_cameras() -> Result<Vec<CameraDevice>> {
    Ok(Vec::new())
}

#[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
pub fn collect_remote() -> Result<RemoteStatus> {
    Ok(RemoteStatus::default())
}

#[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
pub fn fill_environment(_facts: &mut EnvironmentFacts) -> Result<()> {
    Ok(())
}

#[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
pub fn enrich_processes(_procs: &mut [ProcessSnapshot]) {}

#[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
pub fn verify_signature(_path: &std::path::Path) -> crate::origin::SignatureStatus {
    crate::origin::SignatureStatus::Unknown
}

pub fn cpuid_hypervisor() -> (bool, Option<String>) {
    #[cfg(target_arch = "x86_64")]
    {
        let cpuid = raw_cpuid::CpuId::new();
        let present = cpuid
            .get_feature_info()
            .map(|i| i.has_hypervisor())
            .unwrap_or(false);
        if !present {
            return (false, None);
        }
        let leaf = raw_cpuid::cpuid!(0x4000_0000);
        let mut raw = [0u8; 12];
        raw[0..4].copy_from_slice(&leaf.ebx.to_le_bytes());
        raw[4..8].copy_from_slice(&leaf.ecx.to_le_bytes());
        raw[8..12].copy_from_slice(&leaf.edx.to_le_bytes());
        let vendor = String::from_utf8_lossy(&raw)
            .trim_matches('\0')
            .trim()
            .to_string();
        (
            true,
            if vendor.is_empty() {
                None
            } else {
                Some(vendor)
            },
        )
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        (false, None)
    }
}

pub fn mac_vm_vendors() -> Vec<String> {
    use sysinfo::Networks;
    let networks = Networks::new_with_refreshed_list();
    let ouis = [
        ("00:05:69", "VMware"),
        ("00:0C:29", "VMware"),
        ("00:1C:14", "VMware"),
        ("00:50:56", "VMware"),
        ("08:00:27", "VirtualBox"),
        ("0A:00:27", "VirtualBox"),
        ("52:54:00", "QEMU/KVM"),
        ("00:16:3E", "Xen"),
        ("00:1C:42", "Parallels"),
    ];
    let mut found = Vec::new();
    for (name, data) in &networks {
        let mac = data.mac_address().to_string().to_ascii_uppercase();
        for (prefix, vendor) in ouis {
            if mac.starts_with(prefix) {
                found.push(format!("{vendor} on {name}"));
            }
        }
    }
    found
}

// Keep types referenced on every OS for rustc unused-import hygiene in this module.
#[allow(dead_code)]
fn _type_anchors(
    _: DisplayInfo,
    _: OverlayObservation,
    _: AudioSession,
    _: CameraDevice,
    _: Finding,
    _: ProcessSnapshot,
    _: EnvironmentFacts,
) {
}
