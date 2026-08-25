use crate::edid;
use crate::error::{Error, Result};
use crate::evidence::{ConnectorKind, DisplayInfo};
use crate::platform::windows::util::decode_wide;
use std::mem::size_of;
use windows::core::PCWSTR;
use windows::Win32::Devices::Display::{
    DisplayConfigGetDeviceInfo, GetDisplayConfigBufferSizes, QueryDisplayConfig,
    DISPLAYCONFIG_DEVICE_INFO_GET_ADAPTER_NAME, DISPLAYCONFIG_DEVICE_INFO_GET_TARGET_NAME,
    DISPLAYCONFIG_DEVICE_INFO_HEADER, DISPLAYCONFIG_MODE_INFO, DISPLAYCONFIG_MODE_INFO_TYPE_SOURCE,
    DISPLAYCONFIG_PATH_INFO, DISPLAYCONFIG_TARGET_DEVICE_NAME, QDC_ONLY_ACTIVE_PATHS,
};
use windows::Win32::Devices::Display::{
    DISPLAYCONFIG_ADAPTER_NAME, DISPLAYCONFIG_OUTPUT_TECHNOLOGY_DISPLAYPORT_EMBEDDED,
    DISPLAYCONFIG_OUTPUT_TECHNOLOGY_DISPLAYPORT_EXTERNAL, DISPLAYCONFIG_OUTPUT_TECHNOLOGY_DVI,
    DISPLAYCONFIG_OUTPUT_TECHNOLOGY_HD15, DISPLAYCONFIG_OUTPUT_TECHNOLOGY_HDMI,
    DISPLAYCONFIG_OUTPUT_TECHNOLOGY_INDIRECT_VIRTUAL,
    DISPLAYCONFIG_OUTPUT_TECHNOLOGY_INDIRECT_WIRED, DISPLAYCONFIG_OUTPUT_TECHNOLOGY_INTERNAL,
    DISPLAYCONFIG_OUTPUT_TECHNOLOGY_LVDS, DISPLAYCONFIG_OUTPUT_TECHNOLOGY_MIRACAST,
    DISPLAYCONFIG_VIDEO_OUTPUT_TECHNOLOGY,
};
use windows::Win32::Foundation::{ERROR_SUCCESS, WIN32_ERROR};
use windows::Win32::System::Registry::{
    RegGetValueW, HKEY_LOCAL_MACHINE, REG_VALUE_TYPE, RRF_RT_REG_BINARY,
};

pub fn collect_displays() -> Result<Vec<DisplayInfo>> {
    unsafe { collect_displays_inner() }
}

unsafe fn collect_displays_inner() -> Result<Vec<DisplayInfo>> {
    let mut n_path: u32 = 0;
    let mut n_mode: u32 = 0;
    GetDisplayConfigBufferSizes(QDC_ONLY_ACTIVE_PATHS, &mut n_path, &mut n_mode)
        .ok()
        .map_err(|e| Error::msg(format!("GetDisplayConfigBufferSizes: {e}")))?;

    let mut paths = vec![DISPLAYCONFIG_PATH_INFO::default(); n_path as usize];
    let mut modes = vec![DISPLAYCONFIG_MODE_INFO::default(); n_mode as usize];
    QueryDisplayConfig(
        QDC_ONLY_ACTIVE_PATHS,
        &mut n_path,
        paths.as_mut_ptr(),
        &mut n_mode,
        modes.as_mut_ptr(),
        None,
    )
    .ok()
    .map_err(|e| Error::msg(format!("QueryDisplayConfig: {e}")))?;
    paths.truncate(n_path as usize);
    modes.truncate(n_mode as usize);

    let mut displays = Vec::new();
    for (idx, path) in paths.iter().enumerate() {
        let mut target = DISPLAYCONFIG_TARGET_DEVICE_NAME::default();
        target.header = DISPLAYCONFIG_DEVICE_INFO_HEADER {
            r#type: DISPLAYCONFIG_DEVICE_INFO_GET_TARGET_NAME,
            size: size_of::<DISPLAYCONFIG_TARGET_DEVICE_NAME>() as u32,
            adapterId: path.targetInfo.adapterId,
            id: path.targetInfo.id,
        };
        let err = DisplayConfigGetDeviceInfo(&mut target.header as *mut _);
        if WIN32_ERROR(err as u32) != ERROR_SUCCESS {
            continue;
        }

        let name = decode_wide(&target.monitorFriendlyDeviceName);
        let path_str = decode_wide(&target.monitorDevicePath);
        let adapter = adapter_name(path);
        let connector = map_connector(target.outputTechnology);
        let (width, height, is_primary, clone_group) = path_geometry(&modes, path);

        let mut parsed_edid = edid_from_device_path(&path_str);
        if parsed_edid.is_none() {
            // Fall back to the IDs CCD already extracted from EDID.
            let flags = target.flags.Anonymous.value;
            let edid_ids_valid = flags & 0x4 != 0;
            if edid_ids_valid {
                parsed_edid = Some(edid::EdidInfo {
                    manufacturer: mfg_from_edid_id(target.edidManufactureId)
                        .unwrap_or_else(|| format!("{:04X}", target.edidManufactureId)),
                    product_code: target.edidProductCodeId,
                    serial: 0,
                    serial_string: None,
                    name: if name.is_empty() {
                        None
                    } else {
                        Some(name.clone())
                    },
                    year: 0,
                    week: 0,
                    checksum_ok: true,
                });
            }
        }

        let is_builtin = connector == ConnectorKind::Internal
            || name.to_ascii_lowercase().contains("internal")
            || path_str.to_ascii_uppercase().contains("LGD")
                && connector == ConnectorKind::Internal;

        displays.push(DisplayInfo {
            id: if path_str.is_empty() {
                format!("path-{idx}")
            } else {
                path_str.clone()
            },
            name: if name.is_empty() {
                path_str.clone()
            } else {
                name
            },
            connector,
            is_builtin,
            is_primary,
            width,
            height,
            adapter,
            edid: parsed_edid,
            clone_group,
        });
    }

    Ok(displays)
}

unsafe fn adapter_name(path: &DISPLAYCONFIG_PATH_INFO) -> Option<String> {
    let mut adapter = DISPLAYCONFIG_ADAPTER_NAME::default();
    adapter.header = DISPLAYCONFIG_DEVICE_INFO_HEADER {
        r#type: DISPLAYCONFIG_DEVICE_INFO_GET_ADAPTER_NAME,
        size: size_of::<DISPLAYCONFIG_ADAPTER_NAME>() as u32,
        adapterId: path.targetInfo.adapterId,
        id: path.targetInfo.id,
    };
    let err = DisplayConfigGetDeviceInfo(&mut adapter.header as *mut _);
    if WIN32_ERROR(err as u32) != ERROR_SUCCESS {
        return None;
    }
    let name = decode_wide(&adapter.adapterDevicePath);
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

const PATH_SUPPORT_VIRTUAL_MODE: u32 = 0x8;
const MODE_IDX_INVALID: u32 = 0xffff;

fn path_geometry(
    modes: &[DISPLAYCONFIG_MODE_INFO],
    path: &DISPLAYCONFIG_PATH_INFO,
) -> (u32, u32, bool, Option<u32>) {
    let virtual_mode = path.flags & PATH_SUPPORT_VIRTUAL_MODE != 0;
    let packed = unsafe { path.sourceInfo.Anonymous.modeInfoIdx };
    let (src_idx, clone_group) = if virtual_mode {
        let clone = packed & 0xffff;
        let src = packed >> 16;
        (
            src,
            if clone == MODE_IDX_INVALID {
                None
            } else {
                Some(clone)
            },
        )
    } else {
        (packed, Some(path.sourceInfo.id))
    };

    if src_idx != MODE_IDX_INVALID && src_idx != u32::MAX {
        if let Some(m) = modes.get(src_idx as usize) {
            if m.infoType == DISPLAYCONFIG_MODE_INFO_TYPE_SOURCE {
                unsafe {
                    let src = m.Anonymous.sourceMode;
                    if src.width > 0 && src.width < 16_384 {
                        let primary = src.position.x == 0 && src.position.y == 0;
                        return (src.width, src.height, primary, clone_group);
                    }
                }
            }
        }
    }
    (0, 0, false, clone_group)
}

fn map_connector(tech: DISPLAYCONFIG_VIDEO_OUTPUT_TECHNOLOGY) -> ConnectorKind {
    let v = tech.0;
    if v == DISPLAYCONFIG_OUTPUT_TECHNOLOGY_HDMI.0 {
        ConnectorKind::Hdmi
    } else if v == DISPLAYCONFIG_OUTPUT_TECHNOLOGY_DISPLAYPORT_EXTERNAL.0
        || v == DISPLAYCONFIG_OUTPUT_TECHNOLOGY_DISPLAYPORT_EMBEDDED.0
    {
        ConnectorKind::DisplayPort
    } else if v == DISPLAYCONFIG_OUTPUT_TECHNOLOGY_DVI.0 {
        ConnectorKind::Dvi
    } else if v == DISPLAYCONFIG_OUTPUT_TECHNOLOGY_HD15.0 {
        ConnectorKind::Vga
    } else if v == DISPLAYCONFIG_OUTPUT_TECHNOLOGY_INTERNAL.0
        || v == DISPLAYCONFIG_OUTPUT_TECHNOLOGY_LVDS.0
    {
        ConnectorKind::Internal
    } else if v == DISPLAYCONFIG_OUTPUT_TECHNOLOGY_MIRACAST.0 {
        ConnectorKind::Wireless
    } else if v == DISPLAYCONFIG_OUTPUT_TECHNOLOGY_INDIRECT_WIRED.0 {
        ConnectorKind::IndirectWired
    } else if v == DISPLAYCONFIG_OUTPUT_TECHNOLOGY_INDIRECT_VIRTUAL.0 {
        ConnectorKind::IndirectVirtual
    } else {
        ConnectorKind::Other
    }
}

fn mfg_from_edid_id(id: u16) -> Option<String> {
    // CCD stores the 15-bit big-endian manufacturer word.
    let c1 = (((id >> 10) & 0x1f) as u8).wrapping_add(b'@');
    let c2 = (((id >> 5) & 0x1f) as u8).wrapping_add(b'@');
    let c3 = ((id & 0x1f) as u8).wrapping_add(b'@');
    if c1.is_ascii_uppercase() && c2.is_ascii_uppercase() && c3.is_ascii_uppercase() {
        Some(format!("{}{}{}", c1 as char, c2 as char, c3 as char))
    } else {
        None
    }
}

/// Map `\\?\DISPLAY#DEL404C#instance#{guid}` to the monitor's Device Parameters\EDID value.
fn edid_from_device_path(path: &str) -> Option<edid::EdidInfo> {
    let rest = path
        .trim_start_matches("\\\\?\\")
        .trim_start_matches("\\\\.\\");
    let before_guid = rest.split('{').next()?;
    let mut parts = before_guid.split('#');
    let class = parts.next()?;
    let mfg = parts.next()?;
    let inst = parts.next()?.trim_end_matches('\\');
    if class.is_empty() || mfg.is_empty() || inst.is_empty() {
        return None;
    }
    let key = format!(r"SYSTEM\CurrentControlSet\Enum\{class}\{mfg}\{inst}\Device Parameters");
    let bytes = read_reg_binary(&key, "EDID")?;
    edid::parse(&bytes)
}

fn read_reg_binary(subkey: &str, value: &str) -> Option<Vec<u8>> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;

    fn wide(s: &str) -> Vec<u16> {
        OsStr::new(s)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    let key_w = wide(subkey);
    let val_w = wide(value);
    let mut data_type = REG_VALUE_TYPE(0);
    let mut size = 0u32;
    unsafe {
        let st = RegGetValueW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(key_w.as_ptr()),
            PCWSTR(val_w.as_ptr()),
            RRF_RT_REG_BINARY,
            Some(&mut data_type as *mut REG_VALUE_TYPE),
            None,
            Some(&mut size),
        );
        if st != ERROR_SUCCESS || size < 128 {
            return None;
        }
        let mut buf = vec![0u8; size as usize];
        let st = RegGetValueW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(key_w.as_ptr()),
            PCWSTR(val_w.as_ptr()),
            RRF_RT_REG_BINARY,
            Some(&mut data_type as *mut REG_VALUE_TYPE),
            Some(buf.as_mut_ptr() as *mut _),
            Some(&mut size),
        );
        if st != ERROR_SUCCESS {
            return None;
        }
        buf.truncate(size as usize);
        Some(buf)
    }
}
