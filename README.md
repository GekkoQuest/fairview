# Fairview

Fairview is a local interview-monitoring **agent**. It inspects the machine it runs on, records structured **evidence**, and evaluates that evidence against a session policy.

It does **not** decide that someone is cheating. Reports talk about findings (a click-through overlay, a virtual display, a known assistant process), not guilt. Client-side heuristics also cannot see a phone, a second laptop, or ChatGPT inside a whitelisted browser tab.

## What it actually measures

| Signal | How it is collected | What it is *not* |
|---|---|---|
| Displays | Windows: `QueryDisplayConfig` + EDID from the monitor device node. Linux: `/sys/class/drm/*/edid`. macOS: CoreGraphics active display list. | Counting GPUs. Treating “Generic PnP Monitor” as an HDMI splitter. Flagging dual monitors. |
| Overlays | Windows: `EnumWindows` + extended styles + `GetLayeredWindowAttributes` + `GetWindowDisplayAffinity` (`WDA_EXCLUDEFROMCAPTURE`). macOS: `CGWindowListCopyWindowInfo` (layer, alpha, sharing state). | “Any layered window.” Discord / NVIDIA / Steam overlays. The taskbar. |
| Audio | Windows: WASAPI `IAudioSessionManager2` on **capture** endpoints, active sessions only, with PID. Linux: PipeWire `pw-dump` JSON (`Stream/Input/Audio`) or ALSA `/proc/asound`. | “Zoom is running.” “This Mac has a built-in mic.” `gdi32.dll` / `winmm.dll` loaded. |
| Processes | `sysinfo` snapshot. Baseline keyed by PID **and** image path (PID reuse is a new process). Windows `OriginalFilename` from the version resource. Exact image-name match against a catalog. | Substring `contains("gpt")`. “Has screen capture permission” because `gdi32` is mapped. |
| Environment | CPUID hypervisor leaf, SMBIOS (`GetSystemFirmwareTable('RSMB')` / DMI sysfs / `hw.model`), Hyper-V guest parameter key. | Calling a Windows 11 VBS/WSL2 host a VM. |
| Remote | `GetSystemMetrics(SM_REMOTESESSION)` + `GlassSessionId` + `WTSClientProtocolType`. Linux: established sockets on 3389/5900 in `/proc/net/tcp`. | “Port 5900 is listening.” |
| Cameras | SetupAPI camera/image classes (Windows), `/sys/class/video4linux` (Linux), `system_profiler -json` (macOS). | Treating every UVC device as cheating. |

A stock Windows 11 box with Hyper-V / Memory Integrity enabled is classified as `hypervisor_root` (informational), not as a guest. Dual physical monitors with distinct EDIDs are inventory, not findings.

## Build

Rust 1.70+ (tested on 1.97).

```bash
cargo build --release
```

Binary: `target/release/fairview` (`.exe` on Windows).

## Usage

```bash
# Write fairview_config.toml if missing, take a baseline, scan until Ctrl+C
fairview

fairview --once                         # single scan, exit 1 if the alert level is reached
fairview --once --json                  # JSON on stdout
fairview --config path.toml --interval 15
fairview --expect code.exe --expect zoom.exe --allow-vm
fairview --no-baseline                  # skip baseline (every process looks “new”)
```

JSON reports go to `fairview-reports/` by default.

### Configuration

```toml
[scan]
interval_seconds = 30
alert_level = "medium"          # info | low | medium | high | critical

[session]
expected_processes = ["chrome.exe", "code.exe", "zoom.exe", "ms-teams.exe"]
allow_extra_displays = true     # dual monitors are normal
allow_vm_guest = false
allow_virtual_camera = false
assume_meeting_apps = true      # Zoom/Teams mic sessions are expected

[monitoring]
process = true
overlay = true
audio = true
display = true
remote = true
environment = true
camera = true

[output]
directory = "fairview-reports"
write_json = true
```

Policy, not detectors, decides what is unexpected. A Zoom capture session is informational when `assume_meeting_apps` is on. A Hyper-V **guest** is unexpected unless `allow_vm_guest` is on. A Hyper-V **root** (VBS) is always informational.

## Findings worth knowing

**High / critical (examples)**

- `overlay.exclude_from_capture` — `SetWindowDisplayAffinity(WDA_EXCLUDEFROMCAPTURE)` or macOS sharing-none. This is how some assistants hide from Zoom/Meet.
- `overlay.click_through_topmost` — layered + click-through + topmost, owner not Discord/NVIDIA/Steam/OS.
- `process.interview_assistant` — catalog hit on image name **or** PE `OriginalFilename` (renames still match).
- `process.remote_tool` — AnyDesk, RustDesk, TeamViewer, Parsec, Sunshine, …
- `display.virtual` / `display.dummy_edid` — indirect display, IDD, dummy-plug EDID.
- `display.cloned_edid` — two outputs with the same manufacturer + product + **non-zero serial** (cloned EDID / splitter). Two identical model panels with serial 0 is only `display.same_model` (low).
- `display.added` — monitor identity appeared after baseline.
- `remote.session` — this logon session is RDP.

**Not flagged**

- Two real monitors (this machine’s ViewSonic DP + ASUS HDMI is inventory).
- `gdi32.dll` / `d3d11.dll` in a process.
- Generic PnP as a splitter.
- Microsoft Hv CPUID on a Dell/Lenovo/ASUS SMBIOS host.

## Architecture

```
src/
  edid.rs smbios.rs overlay.rs display.rs policy.rs   # pure, unit-tested
  known.rs process.rs detect.rs session.rs
  platform/windows/   QueryDisplayConfig, WASAPI, WTS, SetupAPI, SMBIOS
  platform/linux/     DRM EDID, PipeWire/ALSA, /proc/net/tcp, DMI
  platform/macos/     CoreGraphics, sysctl, system_profiler -json
```

Detectors return `Finding` values (`signal`, `severity`, `confidence`, details). `policy::evaluate` splits them into unexpected vs informational.

## Tests

```bash
cargo test
```

Parsers (EDID, SMBIOS classification, overlay rules, policy, process baseline) run on every OS. Live Win32/WASAPI/DRM calls are exercised by `fairview --once`.

## Limits

- A candidate can quit the agent, use a second device, or use a browser tab in an expected Chrome process.
- Wayland does not expose a global window list to ordinary clients; Linux overlay detection is empty by design, not faked with `xwininfo`.
- macOS has no public “who holds the microphone” API; audio findings there are process-catalog based, not session-based.
- HDMI splitters that clone a panel **without** presenting a second output are invisible to the OS. Identical non-zero EDIDs on two outputs are the detectable case.

## License

MIT. See [LICENSE](LICENSE).
