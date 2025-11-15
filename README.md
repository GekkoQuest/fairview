# Fairview

A cross-platform system monitoring tool designed to detect potential cheating behaviors during technical interviews and online assessments. Fairview monitors processes, hardware configurations, audio capture, and screen overlays to identify suspicious activities.

## Overview

Fairview is built in Rust and provides real-time monitoring capabilities across Windows, macOS, and Linux systems. It generates risk scores based on multiple detection vectors and produces detailed JSON reports for analysis.

## Features

### Process Monitoring
- Detects processes with screen capture permissions
- Identifies applications with audio recording capabilities
- Monitors accessibility API access
- Flags suspicious process names and patterns
- Analyzes loaded modules and DLLs (Windows)

### Hardware Detection
- Multi-display configuration monitoring
- Virtual display detection
- HDMI splitter signature identification
- Remote desktop connection detection
- Display configuration change tracking
- USB and wireless display detection

### Audio Monitoring
- Real-time audio processing detection
- PulseAudio monitoring (Linux)
- PipeWire detection (Linux)
- Audio device enumeration (macOS)
- Audio capture DLL detection (Windows)

### Overlay Detection (Windows)
- Transparent window detection
- Layered window identification
- Topmost window tracking
- Hidden overlay discovery

## Installation

### Prerequisites
- Rust 1.70 or higher
- Cargo package manager

### Building from Source

```bash
git clone https://github.com/yourusername/fairview.git
cd fairview
cargo build --release
```

The compiled binary will be available at `target/release/fairview`.

## Usage

Run Fairview with:

```bash
cargo run --release
```

Or execute the compiled binary directly:

```bash
./target/release/fairview
```

Fairview runs in a continuous monitoring loop, performing scans every 30 seconds. Each scan generates:
- Console output with detection summaries
- A JSON report file (`detection_report.json`)

### Sample Output

```
Cluely Detector v0.1.0

[*] Starting Cluely detection scan...
[+] Found 2 suspicious processes
[+] Found 0 suspicious overlays
[+] Audio monitoring detected: false
[+] Hardware risk score: 0.15
[!] Overall risk score: 0.35/1.0

============================================================
CLUELY DETECTION REPORT
============================================================
Timestamp: SystemTime { ... }
Overall Risk Score: 0.35/1.0

SUSPICIOUS PROCESSES:
  - suspicious-app.exe (PID: 1234)
    Path: C:\Users\...\suspicious-app.exe
    Risk Score: 0.60
    Reasons:
      * Has screen capture permission
      * Suspicious process name
...
```

## Architecture

Fairview is organized into five main modules:

### Core Modules

**main.rs**
- Orchestrates all detection modules
- Calculates overall risk scores
- Generates and formats reports
- Manages the scanning loop

**process_monitor.rs**
- Enumerates running processes
- Checks permissions and capabilities
- Platform-specific permission detection
- Module/DLL analysis (Windows)

**hardware_detector.rs**
- Display configuration enumeration
- Connection type detection
- Virtual display identification
- Remote desktop detection

**audio_detector.rs**
- Audio processing detection
- Platform-specific audio system queries
- Real-time capture monitoring

**overlay_detector.rs**
- Window enumeration (Windows)
- Transparent overlay detection
- Layered window analysis

## Risk Scoring

Fairview uses a weighted risk scoring system:

- **Process Risk** (40%): Based on permissions and suspicious names
- **Overlay Detection** (25%): Presence of hidden overlays
- **Audio Monitoring** (15%): Real-time audio processing
- **Hardware Suspicion** (20%): Display configuration anomalies

Individual risk factors:
- Screen capture permission: +0.3
- Audio capture permission: +0.3
- Accessibility API access: +0.2
- Suspicious process name: +0.4
- Virtual display: +0.5
- HDMI splitter signature: +0.7
- Remote desktop: +0.8
- Multiple displays: +0.05 to +0.15

## Platform Support

### Windows
- Full process monitoring with DLL analysis
- Comprehensive overlay detection
- Display configuration via Win32 API
- Remote Desktop Protocol (RDP) detection

### macOS
- Process enumeration via sysinfo
- Display detection via system_profiler
- Screen sharing detection
- Audio device monitoring

### Linux
- Process monitoring with /proc filesystem
- X11 display detection via xrandr
- PulseAudio and PipeWire monitoring
- VNC/remote desktop detection

## Detection Capabilities

### Suspicious Process Patterns
- AI assistant applications
- Interview helper tools
- Screen sharing utilities
- Unauthorized automation tools

### Hardware Cheating Methods
- Multiple monitor setups
- Virtual displays
- HDMI splitters for secondary viewing
- Remote desktop connections
- Wireless display casting

### Audio-Based Cheating
- Real-time transcription services
- Voice assistant applications
- Audio streaming to external devices

## Configuration

Currently, Fairview uses hardcoded detection rules. Future versions will support configuration files for:
- Custom suspicious process patterns
- Whitelisted applications
- Risk score weights
- Scan intervals

## Output Format

Reports are generated in JSON format:

```json
{
  "timestamp": "2025-01-15T10:30:00Z",
  "suspicious_processes": [...],
  "hidden_overlays": [...],
  "audio_monitoring_detected": false,
  "hardware_suspicion": {
    "risk_score": 0.15,
    "display_count": 2,
    "flags": [...]
  },
  "overall_risk_score": 0.35
}
```

## Dependencies

- **sysinfo** (0.30): Cross-platform system information
- **serde** (1.0): Serialization framework
- **serde_json** (1.0): JSON serialization
- **tokio** (1.35): Async runtime for scheduling
- **windows** (0.52): Windows API bindings (Windows only)

## Limitations

- macOS permission checks use heuristics rather than TCC database queries
- Linux audio detection requires PulseAudio or PipeWire
- Overlay detection is Windows-only
- Some legitimate applications may trigger false positives
- Advanced evasion techniques may bypass detection

## License

MIT License - see LICENSE file for details

## Contributing

Contributions are welcome! Areas for improvement:
- Detection algorithms
- Configuration file support
- Potentially a web dashboard for report visualization
- Machine learning-based anomaly detection (0 clue how I'd go about this quite yet)
- Better platform support

## Disclaimer

This tool is intended for legitimate interview proctoring and assessment security purposes. Users are responsible for ensuring compliance with applicable laws and regulations. The authors assume no liability for misuse of this software.
