use windows::Win32::Foundation::HWND;

pub fn decode_wide(buf: &[u16]) -> String {
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..end])
}

pub fn hwnd_to_u64(hwnd: HWND) -> u64 {
    hwnd.0 as usize as u64
}
