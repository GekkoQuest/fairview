use crate::origin::SignatureStatus;
use std::mem::size_of;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use windows::core::PCWSTR;
use windows::Win32::Foundation::{HWND, TRUST_E_NOSIGNATURE};
use windows::Win32::Security::WinTrust::{
    WinVerifyTrustEx, WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_FILE_INFO,
    WTD_CACHE_ONLY_URL_RETRIEVAL, WTD_CHOICE_FILE, WTD_REVOCATION_CHECK_NONE, WTD_REVOKE_NONE,
    WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UI_NONE,
};

/// Authenticode check with no UI and no network revocation.
/// Catalog-signed Windows binaries are covered; embedded-only PKCS7 is not required.
pub fn verify(path: &Path) -> SignatureStatus {
    let wide: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    unsafe {
        let mut file = WINTRUST_FILE_INFO {
            cbStruct: size_of::<WINTRUST_FILE_INFO>() as u32,
            pcwszFilePath: PCWSTR(wide.as_ptr()),
            ..Default::default()
        };
        let mut data = WINTRUST_DATA {
            cbStruct: size_of::<WINTRUST_DATA>() as u32,
            dwUIChoice: WTD_UI_NONE,
            fdwRevocationChecks: WTD_REVOKE_NONE,
            dwUnionChoice: WTD_CHOICE_FILE,
            dwStateAction: WTD_STATEACTION_VERIFY,
            dwProvFlags: windows::Win32::Security::WinTrust::WINTRUST_DATA_PROVIDER_FLAGS(
                WTD_CACHE_ONLY_URL_RETRIEVAL.0 | WTD_REVOCATION_CHECK_NONE.0,
            ),
            ..Default::default()
        };
        data.Anonymous.pFile = &mut file;

        let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        let hwnd = HWND(-1isize as *mut core::ffi::c_void);
        let status = WinVerifyTrustEx(hwnd, &mut action, &mut data);

        data.dwStateAction = WTD_STATEACTION_CLOSE;
        let _ = WinVerifyTrustEx(hwnd, &mut action, &mut data);

        if status == 0 {
            SignatureStatus::Trusted
        } else if status == TRUST_E_NOSIGNATURE.0 {
            SignatureStatus::Unsigned
        } else {
            SignatureStatus::Untrusted
        }
    }
}
