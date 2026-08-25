use crate::error::Result;
use crate::evidence::{AudioSession, CameraDevice, ConnectorKind, DisplayInfo, ProcessSnapshot};
use crate::known;
use crate::overlay::OverlayObservation;
use crate::platform::RemoteStatus;
use crate::smbios::{EnvironmentFacts, FirmwareIdentity};
use core_foundation::base::{CFType, TCFType};
use core_foundation::dictionary::CFDictionary;
use core_foundation::number::CFNumber;
use core_foundation::string::CFString;
use core_graphics::display::{
    kCGNullWindowID, kCGWindowListExcludeDesktopElements, kCGWindowListOptionOnScreenOnly,
    CGDisplay, CGWindowListCopyWindowInfo,
};
use serde_json::Value;
use std::ffi::CString;
use std::path::Path;
use std::process::Command;

pub fn enrich_processes(_procs: &mut [ProcessSnapshot]) {}

pub fn verify_signature(_path: &Path) -> crate::origin::SignatureStatus {
    crate::origin::SignatureStatus::Unknown
}

pub fn collect_displays() -> Result<Vec<DisplayInfo>> {
    let ids = CGDisplay::active_displays().unwrap_or_default();
    let mut displays = Vec::new();
    for (i, id) in ids.into_iter().enumerate() {
        let display = CGDisplay::new(id);
        let bounds = display.bounds();
        let builtin = display.is_builtin();
        let name = display_name(id).unwrap_or_else(|| format!("display-{id}"));
        displays.push(DisplayInfo {
            id: id.to_string(),
            name,
            connector: if builtin {
                ConnectorKind::Internal
            } else {
                ConnectorKind::Unknown
            },
            is_builtin: builtin,
            is_primary: i == 0,
            width: bounds.size.width.max(0.0) as u32,
            height: bounds.size.height.max(0.0) as u32,
            adapter: None,
            edid: None,
            clone_group: None,
        });
    }
    Ok(displays)
}

fn display_name(_id: u32) -> Option<String> {
    // IODisplayCreateInfoDictionary is not wrapped in core-graphics 0.24.
    None
}

pub fn collect_overlays() -> Result<Vec<OverlayObservation>> {
    let options = kCGWindowListOptionOnScreenOnly | kCGWindowListExcludeDesktopElements;
    let info = unsafe { CGWindowListCopyWindowInfo(options, kCGNullWindowID) };
    if info.is_null() {
        return Ok(Vec::new());
    }
    let array: core_foundation::array::CFArray<CFDictionary<CFString, CFType>> =
        unsafe { core_foundation::array::CFArray::wrap_under_create_rule(info) };

    let mut out = Vec::new();
    for i in 0..array.len() {
        let Some(dict) = array.get(i as isize) else {
            continue;
        };
        let pid = cf_i64(&dict, "kCGWindowOwnerPID").unwrap_or(0) as u32;
        let layer = cf_i64(&dict, "kCGWindowLayer").unwrap_or(0) as i32;
        let alpha = cf_f64(&dict, "kCGWindowAlpha").unwrap_or(1.0);
        let sharing = cf_i64(&dict, "kCGWindowSharingState").unwrap_or(2);
        let owner = cf_string(&dict, "kCGWindowOwnerName").unwrap_or_default();
        let title = cf_string(&dict, "kCGWindowName").unwrap_or_default();
        let (x, y, w, h) = cf_bounds(&dict);
        let _ = (x, y);
        if w < 40.0 || h < 40.0 {
            continue;
        }
        // Normal app windows sit on layer 0 with alpha 1 and sharing read-write.
        let interesting = sharing == 0 || (layer >= 3 && alpha < 0.99) || alpha < 0.2;
        if !interesting {
            continue;
        }
        out.push(OverlayObservation {
            handle: cf_i64(&dict, "kCGWindowNumber").unwrap_or(0) as u64,
            pid,
            exe: if owner.is_empty() {
                None
            } else {
                Some(owner.clone())
            },
            title,
            class_name: owner,
            width: w.max(0.0) as u32,
            height: h.max(0.0) as u32,
            visible: true,
            cloaked: false,
            layered: alpha < 1.0,
            click_through: false,
            topmost: layer > 0,
            tool_window: layer > 0,
            no_activate: false,
            alpha: Some((alpha * 255.0).clamp(0.0, 255.0) as u8),
            exclude_from_capture: false,
            sharing_none: sharing == 0,
            window_layer: layer,
        });
    }
    Ok(out)
}

fn cf_i64(dict: &CFDictionary<CFString, CFType>, key: &str) -> Option<i64> {
    let k = CFString::new(key);
    let v = dict.find(&k)?;
    v.downcast::<CFNumber>().and_then(|n| n.to_i64())
}

fn cf_f64(dict: &CFDictionary<CFString, CFType>, key: &str) -> Option<f64> {
    let k = CFString::new(key);
    let v = dict.find(&k)?;
    v.downcast::<CFNumber>().and_then(|n| n.to_f64())
}

fn cf_string(dict: &CFDictionary<CFString, CFType>, key: &str) -> Option<String> {
    let k = CFString::new(key);
    let v = dict.find(&k)?;
    v.downcast::<CFString>().map(|s| s.to_string())
}

fn cf_bounds(dict: &CFDictionary<CFString, CFType>) -> (f64, f64, f64, f64) {
    let k = CFString::new("kCGWindowBounds");
    let Some(v) = dict.find(&k) else {
        return (0.0, 0.0, 0.0, 0.0);
    };
    let Some(bounds) = v.downcast::<CFDictionary<CFString, CFType>>() else {
        return (0.0, 0.0, 0.0, 0.0);
    };
    let num = |key: &str| {
        bounds
            .find(&CFString::new(key))
            .and_then(|n| n.downcast::<CFNumber>())
            .and_then(|n| n.to_f64())
            .unwrap_or(0.0)
    };
    (num("X"), num("Y"), num("Width"), num("Height"))
}

pub fn collect_audio() -> Result<Vec<AudioSession>> {
    // Core Audio has no public "who holds the input device" API. Do not pretend
    // that the existence of a built-in microphone is a finding.
    Ok(Vec::new())
}

pub fn collect_cameras() -> Result<Vec<CameraDevice>> {
    let output = Command::new("system_profiler")
        .args(["SPCameraDataType", "-json"])
        .output();
    let Ok(output) = output else {
        return Ok(Vec::new());
    };
    let value: Value = serde_json::from_slice(&output.stdout).unwrap_or(Value::Null);
    let mut devices = Vec::new();
    if let Some(arr) = value.get("SPCameraDataType").and_then(|v| v.as_array()) {
        for (i, cam) in arr.iter().enumerate() {
            let name = cam
                .get("_name")
                .and_then(|v| v.as_str())
                .unwrap_or("camera")
                .to_string();
            devices.push(CameraDevice {
                id: format!("camera-{i}"),
                name: name.clone(),
                virtual_device: known::virtual_camera_name(&name),
            });
        }
    }
    Ok(devices)
}

pub fn collect_remote() -> Result<RemoteStatus> {
    Ok(RemoteStatus::default())
}

pub fn fill_environment(facts: &mut EnvironmentFacts) -> Result<()> {
    let (present, vendor) = crate::platform::cpuid_hypervisor();
    facts.cpuid_hypervisor = present;
    facts.cpuid_vendor = vendor;
    facts.mac_vm_vendors = crate::platform::mac_vm_vendors();
    let model = sysctl_string("hw.model");
    facts.hw_model = model.clone();
    facts.firmware = FirmwareIdentity {
        manufacturer: Some("Apple".into()),
        product: model,
        ..Default::default()
    };
    if sysctl_int("kern.hv_vmm_present") == Some(1) {
        facts.cpuid_hypervisor = true;
        if facts.cpuid_vendor.is_none() {
            facts.cpuid_vendor = Some("Apple Virtualization".into());
        }
    }
    Ok(())
}

fn sysctl_string(name: &str) -> Option<String> {
    let cname = CString::new(name).ok()?;
    let mut size = 0usize;
    unsafe {
        if libc::sysctlbyname(
            cname.as_ptr(),
            std::ptr::null_mut(),
            &mut size,
            std::ptr::null_mut(),
            0,
        ) != 0
            || size == 0
        {
            return None;
        }
        let mut buf = vec![0u8; size];
        if libc::sysctlbyname(
            cname.as_ptr(),
            buf.as_mut_ptr() as *mut _,
            &mut size,
            std::ptr::null_mut(),
            0,
        ) != 0
        {
            return None;
        }
        if size > 0 && buf[size - 1] == 0 {
            size -= 1;
        }
        Some(String::from_utf8_lossy(&buf[..size]).into_owned())
    }
}

fn sysctl_int(name: &str) -> Option<i32> {
    let cname = CString::new(name).ok()?;
    let mut val: i32 = 0;
    let mut size = std::mem::size_of::<i32>();
    unsafe {
        if libc::sysctlbyname(
            cname.as_ptr(),
            &mut val as *mut i32 as *mut _,
            &mut size,
            std::ptr::null_mut(),
            0,
        ) != 0
        {
            return None;
        }
    }
    Some(val)
}
