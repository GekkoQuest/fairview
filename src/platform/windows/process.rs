use crate::evidence::ProcessSnapshot;
use crate::platform::windows::util::decode_wide;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use windows::core::PCWSTR;
use windows::Win32::Foundation::CloseHandle;
use windows::Win32::Storage::FileSystem::{
    GetFileVersionInfoSizeW, GetFileVersionInfoW, VerQueryValueW,
};
use windows::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
};

pub fn enrich_processes(procs: &mut [ProcessSnapshot]) {
    for p in procs {
        if p.path.is_empty() {
            if let Some(path) = path_for_pid(p.pid) {
                p.path = path;
            }
        }
        if p.original_filename.is_none() && !p.path.is_empty() {
            p.original_filename = original_filename(Path::new(&p.path));
        }
    }
}

pub fn path_for_pid(pid: u32) -> Option<String> {
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;
        let mut buf = [0u16; 512];
        let mut size = buf.len() as u32;
        let ok = QueryFullProcessImageNameW(
            handle,
            PROCESS_NAME_WIN32,
            windows::core::PWSTR(buf.as_mut_ptr()),
            &mut size,
        );
        let _ = CloseHandle(handle);
        if ok.is_err() || size == 0 {
            return None;
        }
        Some(decode_wide(&buf[..size as usize]))
    }
}

fn original_filename(path: &Path) -> Option<String> {
    let wide: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    unsafe {
        let mut dummy = 0u32;
        let size = GetFileVersionInfoSizeW(PCWSTR(wide.as_ptr()), Some(&mut dummy));
        if size == 0 {
            return None;
        }
        let mut buf = vec![0u8; size as usize];
        GetFileVersionInfoW(PCWSTR(wide.as_ptr()), 0, size, buf.as_mut_ptr() as *mut _).ok()?;

        #[repr(C)]
        #[derive(Clone, Copy)]
        struct LangCodePage {
            lang: u16,
            codepage: u16,
        }
        let mut trans_ptr: *mut core::ffi::c_void = std::ptr::null_mut();
        let mut trans_len = 0u32;
        let path_trans: Vec<u16> = "\\VarFileInfo\\Translation"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        if !VerQueryValueW(
            buf.as_ptr() as *const _,
            PCWSTR(path_trans.as_ptr()),
            &mut trans_ptr,
            &mut trans_len,
        )
        .as_bool()
            || trans_ptr.is_null()
            || trans_len < 4
        {
            return None;
        }
        let lc = *(trans_ptr as *const LangCodePage);
        let sub = format!(
            "\\StringFileInfo\\{:04x}{:04x}\\OriginalFilename",
            lc.lang, lc.codepage
        );
        let sub_w: Vec<u16> = sub.encode_utf16().chain(std::iter::once(0)).collect();
        let mut val_ptr: *mut core::ffi::c_void = std::ptr::null_mut();
        let mut val_len = 0u32;
        if !VerQueryValueW(
            buf.as_ptr() as *const _,
            PCWSTR(sub_w.as_ptr()),
            &mut val_ptr,
            &mut val_len,
        )
        .as_bool()
            || val_ptr.is_null()
            || val_len == 0
        {
            return None;
        }
        let words = std::slice::from_raw_parts(val_ptr as *const u16, val_len as usize);
        let s = decode_wide(words);
        if s.is_empty() {
            None
        } else {
            Some(s)
        }
    }
}
