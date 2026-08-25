use crate::error::Result;
use crate::evidence::CameraDevice;
use crate::known;
use crate::platform::windows::util::decode_wide;
use windows::core::GUID;
use windows::Win32::Devices::DeviceAndDriverInstallation::{
    SetupDiDestroyDeviceInfoList, SetupDiEnumDeviceInfo, SetupDiGetClassDevsW,
    SetupDiGetDeviceRegistryPropertyW, DIGCF_PRESENT, SPDRP_DEVICEDESC, SPDRP_FRIENDLYNAME,
    SP_DEVINFO_DATA,
};
use windows::Win32::Foundation::ERROR_NO_MORE_ITEMS;

// GUID_DEVCLASS_CAMERA (Windows 10 1903+)
const GUID_DEVCLASS_CAMERA: GUID = GUID::from_u128(0xca3e7ab9_b4c3_4ae6_8251_579df9331718);
// GUID_DEVCLASS_IMAGE (still used for many webcams)
const GUID_DEVCLASS_IMAGE: GUID = GUID::from_u128(0x6bdd1fc6_810f_11d0_bec7_08002be2092f);

pub fn collect_cameras() -> Result<Vec<CameraDevice>> {
    let mut devices = Vec::new();
    devices.extend(enumerate_class(&GUID_DEVCLASS_CAMERA));
    for d in enumerate_class(&GUID_DEVCLASS_IMAGE) {
        if !devices.iter().any(|e| e.id == d.id || e.name == d.name) {
            devices.push(d);
        }
    }
    Ok(devices)
}

fn enumerate_class(guid: &GUID) -> Vec<CameraDevice> {
    let mut out = Vec::new();
    unsafe {
        let set = match SetupDiGetClassDevsW(Some(guid), None, None, DIGCF_PRESENT) {
            Ok(h) => h,
            Err(_) => return out,
        };
        let mut i = 0u32;
        loop {
            let mut info = SP_DEVINFO_DATA {
                cbSize: std::mem::size_of::<SP_DEVINFO_DATA>() as u32,
                ..Default::default()
            };
            match SetupDiEnumDeviceInfo(set, i, &mut info) {
                Ok(_) => {}
                Err(e) => {
                    if e.code().0 as u32 == ERROR_NO_MORE_ITEMS.0 {
                        break;
                    }
                    break;
                }
            }
            let name = property_string(set, &info, SPDRP_FRIENDLYNAME)
                .or_else(|| property_string(set, &info, SPDRP_DEVICEDESC))
                .unwrap_or_else(|| format!("camera-{i}"));
            let virtual_device = known::virtual_camera_name(&name);
            out.push(CameraDevice {
                id: format!("{:?}-{}", guid, i),
                name,
                virtual_device,
            });
            i += 1;
        }
        let _ = SetupDiDestroyDeviceInfoList(set);
    }
    out
}

unsafe fn property_string(
    set: windows::Win32::Devices::DeviceAndDriverInstallation::HDEVINFO,
    info: &SP_DEVINFO_DATA,
    prop: windows::Win32::Devices::DeviceAndDriverInstallation::SETUP_DI_REGISTRY_PROPERTY,
) -> Option<String> {
    let mut ty = 0u32;
    let mut size = 0u32;
    let _ =
        SetupDiGetDeviceRegistryPropertyW(set, info, prop, Some(&mut ty), None, Some(&mut size));
    if size == 0 {
        return None;
    }
    let mut buf = vec![0u8; size as usize];
    SetupDiGetDeviceRegistryPropertyW(
        set,
        info,
        prop,
        Some(&mut ty),
        Some(&mut buf),
        Some(&mut size),
    )
    .ok()?;
    let u16_len = (size as usize) / 2;
    let words = std::slice::from_raw_parts(buf.as_ptr() as *const u16, u16_len);
    let s = decode_wide(words);
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}
