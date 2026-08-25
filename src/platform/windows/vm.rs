use crate::error::Result;
use crate::smbios::{self, EnvironmentFacts};
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use windows::core::PCWSTR;
use windows::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_SUCCESS};
use windows::Win32::System::Registry::{
    RegCloseKey, RegOpenKeyExW, HKEY_LOCAL_MACHINE, KEY_READ, REG_SAM_FLAGS,
};
use windows::Win32::System::SystemInformation::{GetSystemFirmwareTable, RSMB};

pub fn fill_environment(facts: &mut EnvironmentFacts) -> Result<()> {
    let (present, vendor) = crate::platform::cpuid_hypervisor();
    facts.cpuid_hypervisor = present;
    facts.cpuid_vendor = vendor;
    facts.mac_vm_vendors = crate::platform::mac_vm_vendors();
    facts.hyperv_guest_parameters = hyperv_guest_parameters_present();
    if let Some(blob) = read_rsmb() {
        facts.firmware = smbios::parse_windows_rsmb(&blob);
    }
    Ok(())
}

fn read_rsmb() -> Option<Vec<u8>> {
    unsafe {
        let size = GetSystemFirmwareTable(RSMB, 0, None);
        if size == 0 {
            return None;
        }
        let mut buf = vec![0u8; size as usize];
        let written = GetSystemFirmwareTable(RSMB, 0, Some(buf.as_mut_slice()));
        if written == 0 {
            return None;
        }
        buf.truncate(written as usize);
        Some(buf)
    }
}

fn hyperv_guest_parameters_present() -> bool {
    let key: Vec<u16> = OsStr::new(r"SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters")
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    unsafe {
        let mut hkey = Default::default();
        let st = RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(key.as_ptr()),
            0,
            REG_SAM_FLAGS(KEY_READ.0),
            &mut hkey,
        );
        if st == ERROR_SUCCESS {
            let _ = RegCloseKey(hkey);
            true
        } else {
            debug_assert!(st == ERROR_FILE_NOT_FOUND || st != ERROR_SUCCESS);
            false
        }
    }
}
