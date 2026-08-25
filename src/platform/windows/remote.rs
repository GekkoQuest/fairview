use crate::error::Result;
use crate::evidence::{Detector, Finding, Severity};
use crate::platform::RemoteStatus;
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::ERROR_SUCCESS;
use windows::Win32::System::Registry::{
    RegGetValueW, HKEY_LOCAL_MACHINE, REG_VALUE_TYPE, RRF_RT_REG_DWORD,
};
use windows::Win32::System::RemoteDesktop::{
    ProcessIdToSessionId, WTSActive, WTSClientProtocolType, WTSEnumerateSessionsW, WTSFreeMemory,
    WTSQuerySessionInformationW, WTS_CURRENT_SERVER_HANDLE, WTS_CURRENT_SESSION,
};
use windows::Win32::System::Threading::GetCurrentProcessId;
use windows::Win32::UI::WindowsAndMessaging::{GetSystemMetrics, SM_REMOTESESSION};

const WTS_PROTOCOL_TYPE_RDP: u16 = 2;
const GLASS_KEY: &str = r"SYSTEM\CurrentControlSet\Control\Terminal Server";

pub fn collect_remote() -> Result<RemoteStatus> {
    let mut status = RemoteStatus::default();
    let sm_remote = unsafe { GetSystemMetrics(SM_REMOTESESSION) } != 0;
    let glass_mismatch = glass_session_is_remote();
    let protocol_rdp = current_session_rdp();
    let other_active_rdp = other_sessions_rdp();

    status.active_session = sm_remote || glass_mismatch || protocol_rdp;

    if status.active_session {
        status.findings.push(
            Finding::new(
                Detector::Remote,
                "remote.session",
                Severity::High,
                0.95,
                "This logon session is a remote desktop session",
            )
            .detail("SM_REMOTESESSION", sm_remote.to_string())
            .detail("glass_session_mismatch", glass_mismatch.to_string())
            .detail("wts_protocol_rdp", protocol_rdp.to_string()),
        );
    } else if other_active_rdp {
        status.findings.push(Finding::new(
            Detector::Remote,
            "remote.other_session",
            Severity::Medium,
            0.7,
            "Another active RDP session exists on this machine",
        ));
    }

    Ok(status)
}

fn glass_session_is_remote() -> bool {
    let mut session_id = 0u32;
    unsafe {
        if ProcessIdToSessionId(GetCurrentProcessId(), &mut session_id).is_err() {
            return false;
        }
    }
    let key: Vec<u16> = OsStr::new(GLASS_KEY)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let value: Vec<u16> = OsStr::new("GlassSessionId")
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let mut ty = REG_VALUE_TYPE(0);
    let mut size = 4u32;
    let mut glass = 0u32;
    unsafe {
        let st = RegGetValueW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(key.as_ptr()),
            PCWSTR(value.as_ptr()),
            RRF_RT_REG_DWORD,
            Some(&mut ty as *mut REG_VALUE_TYPE),
            Some(&mut glass as *mut u32 as *mut _),
            Some(&mut size),
        );
        if st != ERROR_SUCCESS {
            return false;
        }
    }
    session_id != glass
}

fn current_session_rdp() -> bool {
    unsafe {
        let mut buf = PWSTR::null();
        let mut bytes = 0u32;
        if WTSQuerySessionInformationW(
            WTS_CURRENT_SERVER_HANDLE,
            WTS_CURRENT_SESSION,
            WTSClientProtocolType,
            &mut buf,
            &mut bytes,
        )
        .is_err()
            || buf.is_null()
        {
            return false;
        }
        let proto = *(buf.0 as *const u16);
        WTSFreeMemory(buf.0 as *mut _);
        proto == WTS_PROTOCOL_TYPE_RDP
    }
}

fn other_sessions_rdp() -> bool {
    unsafe {
        let mut info = std::ptr::null_mut();
        let mut count = 0u32;
        if WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &mut info, &mut count).is_err()
            || info.is_null()
        {
            return false;
        }
        let mut current = 0u32;
        let _ = ProcessIdToSessionId(GetCurrentProcessId(), &mut current);
        let slice = std::slice::from_raw_parts(info, count as usize);
        let mut found = false;
        for s in slice {
            if s.State == WTSActive && s.SessionId != current {
                let mut buf = PWSTR::null();
                let mut bytes = 0u32;
                if WTSQuerySessionInformationW(
                    WTS_CURRENT_SERVER_HANDLE,
                    s.SessionId,
                    WTSClientProtocolType,
                    &mut buf,
                    &mut bytes,
                )
                .is_ok()
                    && !buf.is_null()
                {
                    let proto = *(buf.0 as *const u16);
                    WTSFreeMemory(buf.0 as *mut _);
                    if proto == WTS_PROTOCOL_TYPE_RDP {
                        found = true;
                    }
                }
            }
        }
        WTSFreeMemory(info as *mut _);
        found
    }
}
