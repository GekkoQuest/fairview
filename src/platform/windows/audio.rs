use crate::error::{Error, Result};
use crate::evidence::AudioSession;
use windows::core::Interface;
use windows::Win32::Media::Audio::{
    eCapture, AudioSessionStateActive, IAudioSessionControl2, IAudioSessionManager2,
    IMMDeviceEnumerator, MMDeviceEnumerator, DEVICE_STATE_ACTIVE,
};
use windows::Win32::System::Com::{
    CoCreateInstance, CoInitializeEx, CLSCTX_ALL, COINIT_MULTITHREADED,
};

pub fn collect_audio() -> Result<Vec<AudioSession>> {
    unsafe { collect_audio_inner() }
}

unsafe fn collect_audio_inner() -> Result<Vec<AudioSession>> {
    // Ignore "already initialized" — we just need COM available on this thread.
    let _ = CoInitializeEx(None, COINIT_MULTITHREADED);

    let enumerator: IMMDeviceEnumerator =
        CoCreateInstance(&MMDeviceEnumerator, None, CLSCTX_ALL)
            .map_err(|e| Error::msg(format!("MMDeviceEnumerator: {e}")))?;
    let collection = enumerator
        .EnumAudioEndpoints(eCapture, DEVICE_STATE_ACTIVE)
        .map_err(|e| Error::msg(format!("EnumAudioEndpoints: {e}")))?;
    let count = collection.GetCount().unwrap_or(0);

    let mut sessions = Vec::new();
    for i in 0..count {
        let device = match collection.Item(i) {
            Ok(d) => d,
            Err(_) => continue,
        };
        let device_name = device
            .GetId()
            .ok()
            .and_then(|s| s.to_string().ok())
            .unwrap_or_else(|| format!("capture-{i}"));
        let manager: IAudioSessionManager2 = match device.Activate(CLSCTX_ALL, None) {
            Ok(m) => m,
            Err(_) => continue,
        };
        let session_enum = match manager.GetSessionEnumerator() {
            Ok(e) => e,
            Err(_) => continue,
        };
        let n = session_enum.GetCount().unwrap_or(0);
        for s in 0..n {
            let control = match session_enum.GetSession(s) {
                Ok(c) => c,
                Err(_) => continue,
            };
            let state = control.GetState().unwrap_or_default();
            if state != AudioSessionStateActive {
                continue;
            }
            let control2: IAudioSessionControl2 = match control.cast() {
                Ok(c) => c,
                Err(_) => continue,
            };
            // S_OK => this is the system-sounds session (skip). S_FALSE is Err in windows-rs.
            if control2.IsSystemSoundsSession().is_ok() {
                continue;
            }
            let pid = control2.GetProcessId().unwrap_or(0);
            if pid == 0 {
                continue;
            }
            let display = control
                .GetDisplayName()
                .ok()
                .and_then(|s| s.to_string().ok())
                .unwrap_or_default();
            sessions.push(AudioSession {
                pid,
                name: display,
                device: device_name.clone(),
                capture: true,
            });
        }
    }
    Ok(sessions)
}
