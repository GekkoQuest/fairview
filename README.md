# Fairview

A cross-platform system monitoring tool designed to detect potential cheating behaviors during technical interviews and online assessments. Fairview monitors processes, hardware configurations, audio capture, and screen overlays to identify suspicious activities.

## Overview

Fairview is built in Rust and provides real-time monitoring capabilities across Windows, macOS, and Linux systems. It generates risk scores based on multiple detection vectors and produces detailed JSON reports for analysis.

## What's New in v0.2.0

**1. Baseline Collection**
- Pre-interview baseline scan captures normal system state
- Detects processes and hardware added during interview
- Helps reduce false positives from legitimate tools

**2. Configurable Thresholds**
- TOML-based configuration file (`fairview_config.toml`)
- Customizable risk weights for different interview types
- Per-module thresholds for fine-tuned detection
- Whitelist support for approved applications

**3. Timestamped Events**
- All reports include RFC 3339 timestamps
- Tracks when suspicious processes started
- Reports saved with timestamps for audit trail
- Scan numbering for tracking progression

**4. Graceful Degradation**
- Continues monitoring even if individual modules fail
- Logs module failures without crashing
- Configurable failure handling (continue or stop)
- Better error reporting for troubleshooting

## Features

### Process Monitoring
- Detects processes with screen capture permissions
- Identifies applications with audio recording capabilities
- Monitors accessibility API access
- Flags suspicious process names and patterns
- Analyzes loaded modules and DLLs (Windows)
- **NEW:** Tracks processes started during interview
- **NEW:** Whitelist support for approved applications

### Hardware Detection
- Multi-display configuration monitoring
- Virtual display detection
- HDMI splitter signature identification
- Remote desktop connection detection
- Display configuration change tracking
- USB and wireless display detection
- **NEW:** Baseline comparison for display changes

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

## Configuration

### First Run

On first run, Fairview will create a default `fairview_config.toml` file. You can customize this file to match your needs:

```toml
[scan]
interval_seconds = 30          # How often to scan
risk_threshold = 0.5           # Overall risk threshold
interview_type = "coding"      # coding, behavioral, technical, general

[weights]
# Component weights (must sum to 1.0)
process_risk = 0.4
overlay_risk = 0.25
audio_risk = 0.15
hardware_risk = 0.2

[thresholds]
# Individual component thresholds
process_threshold = 0.6
hardware_threshold = 0.5
audio_threshold = 0.3
overlay_threshold = 0.4

[whitelist]
# Whitelisted process names
processes = [
    "code.exe",
    "vscode.exe",
    "chrome.exe",
    # Add more as needed
]

# Whitelisted directories
directories = [
    "C:\\Program Files\\Git",
    "/usr/bin",
    # Add more as needed
]

[monitoring]
enable_process_monitoring = true
enable_hardware_monitoring = true
enable_audio_monitoring = true
enable_overlay_monitoring = true
collect_baseline = true          # Enable baseline collection
baseline_duration_seconds = 10
continue_on_module_failure = true  # Graceful degradation
```

## Usage

### Basic Usage

Run Fairview with default configuration:

```bash
cargo run --release
```

Or execute the compiled binary:

```bash
./target/release/fairview
```

### With Baseline Collection

When baseline collection is enabled (default), Fairview will:

1. Prompt you to ensure all necessary applications are running
2. Collect a baseline snapshot of processes and hardware
3. Wait for you to press Enter to begin monitoring
4. Flag any new processes or hardware changes during the interview

### Custom Configuration

Create your own configuration file:

```bash
# Edit fairview_config.toml with your preferences
./target/release/fairview
```

### Baseline Collection Workflow

```
1. Start Fairview
2. Fairview collects baseline (10 seconds by default)
   - Records all running processes
   - Records display configuration
3. Candidate sets up their environment (IDE, browser, docs)
4. Press Enter to begin interview monitoring
5. Fairview monitors for changes and suspicious activity
```

## Output

### Console Output

Fairview provides real-time console output with color-coded status:

```
Fairview v0.1.0 - Interview Monitoring System

[+] Loaded configuration from fairview_config.toml

============================================================
COLLECTING BASELINE
============================================================
[*] Please ensure all necessary applications are running
[*] Baseline collection will take 10 seconds...

[*] Collecting baseline processes...
[+] Baseline collected: 127 processes
[+] Hardware baseline: 2 displays detected
[+] Baseline collection complete

Press Enter to start monitoring...

============================================================
STARTING CONTINUOUS MONITORING
Scan interval: 30 seconds
============================================================

[*] Starting scan #1 at SystemTime { ... }
[+] Found 1 suspicious processes
[+] Found 0 suspicious overlays
[+] Audio monitoring detected: false
[+] Hardware risk score: 0.15
[!] Overall risk score: 0.45/1.0

============================================================
FAIRVIEW DETECTION REPORT - Scan #1
============================================================
Timestamp: 2025-01-15 10:30:00 UTC
Interview Type: coding
Overall Risk Score: 0.45/1.0
Risk Threshold: 0.50
✓ STATUS: Within acceptable risk levels

SUSPICIOUS PROCESSES:
  - suspicious-app.exe (PID: 1234)
    Path: C:\Users\...\suspicious-app.exe
    Risk Score: 0.60
    ⚠️  Started during interview
    Reasons:
      * Has screen capture permission
      * Suspicious process name
      * Started during interview

[+] Report saved to detection_report_20250115_103000.json
```

### JSON Reports

Reports are saved with timestamps for audit trail:

- `detection_report_20250115_103000.json`
- `detection_report_20250115_103030.json`
- etc.

**Report Structure:**

```json
{
  "timestamp": "2025-01-15T10:30:00.000Z",
  "scan_number": 1,
  "suspicious_processes": [
    {
      "pid": 1234,
      "name": "suspicious-app.exe",
      "path": "C:\\Users\\...\\suspicious-app.exe",
      "risk_score": 0.6,
      "reasons": [
        "Has screen capture permission",
        "Suspicious process name",
        "Started during interview"
      ],
      "started_during_interview": true,
      "is_whitelisted": false
    }
  ],
  "hidden_overlays": [],
  "audio_monitoring_detected": false,
  "hardware_suspicion": {
    "risk_score": 0.15,
    "display_count": 2,
    "baseline_display_count": 1,
    "display_changed": true,
    "has_virtual_display": false,
    "has_hdmi_splitter": false,
    "remote_desktop_active": false,
    "flags": [
      "Multiple displays detected: 2 displays",
      "Display configuration changed during interview (baseline: 1, current: 2)",
      "New display connected during interview: Generic PnP Monitor"
    ]
  },
  "overall_risk_score": 0.45,
  "exceeds_threshold": false,
  "module_failures": []
}
```

## Risk Scoring

Fairview uses a configurable weighted risk scoring system:

### Default Weights
- **Process Risk** (40%): Based on permissions and suspicious names
- **Overlay Detection** (25%): Presence of hidden overlays
- **Audio Monitoring** (15%): Real-time audio processing
- **Hardware Suspicion** (20%): Display configuration anomalies

### Individual Risk Factors
- Screen capture permission: +0.3
- Audio capture permission: +0.3
- Accessibility API access: +0.2
- Suspicious process name: +0.4
- Started during interview: +0.3
- Virtual display: +0.5
- HDMI splitter signature: +0.7
- Remote desktop: +0.8
- Multiple displays: +0.05 to +0.15
- Display configuration changed: +0.4
- New display added: +0.3

### Interview Type Adjustment

The `interview_type` configuration allows for different risk profiles:

- **coding**: Standard weights (for coding interviews where IDE + browser is normal)
- **behavioral**: Lower process thresholds (fewer tools expected)
- **technical**: Moderate thresholds (some technical tools expected)
- **general**: Flexible thresholds (various tools may be needed)

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
- Processes started during interview

### Hardware Cheating Methods
- Multiple monitor setups
- Virtual displays
- HDMI splitters for secondary viewing
- Remote desktop connections
- Wireless display casting
- Display configuration changes during interview

### Audio-Based Cheating
- Real-time transcription services
- Voice assistant applications
- Audio streaming to external devices

### False Positives

If legitimate tools are flagged:

1. Add them to the process whitelist in config
2. Add their installation directory to the directory whitelist
3. Adjust the `process_threshold` higher
4. Consider the interview type setting

### Baseline Collection Issues

If baseline collection fails:
1. Ensure you have read permissions for process information
2. Check that display detection commands work on your system
3. Disable baseline collection temporarily: `collect_baseline = false`

## Dependencies

- **sysinfo** (0.30): Cross-platform system information
- **serde** (1.0): Serialization framework
- **serde_json** (1.0): JSON serialization
- **tokio** (1.35): Async runtime for scheduling
- **toml** (0.8): TOML configuration parsing
- **chrono** (0.4): Timestamp formatting
- **windows** (0.52): Windows API bindings (Windows only)

## Limitations

- macOS permission checks use heuristics rather than TCC database queries
- Linux audio detection requires PulseAudio or PipeWire
- Overlay detection is Windows-only
- Some legitimate applications may trigger false positives
- Advanced evasion techniques may bypass detection
- Baseline collection requires stable system state

## License

MIT License - see LICENSE file for details

## Contributing

Contributions are welcome! Areas for improvement:

### Priority Items
- Better macOS TCC integration
- Linux overlay detection via X11/Wayland
- Improved behavioral analysis
- Machine learning-based anomaly detection(?)
- Web dashboard for report visualization
- Automated whitelist suggestions

## Roadmap

- [ ] Machine learning-based anomaly detection
- [ ] Behavioral pattern analysis (typing, mouse movement)
- [ ] Web-based report dashboard
- [ ] Real-time alerting system
- [ ] Clipboard monitoring with privacy controls

## Changelog

### v0.2.0 (Current)
- ✅ Baseline collection system
- ✅ TOML configuration support
- ✅ Configurable risk thresholds
- ✅ Process whitelist system
- ✅ Directory whitelist system
- ✅ Timestamped event tracking
- ✅ Graceful module degradation
- ✅ Interview type profiles
- ✅ Timestamped report files
- ✅ Enhanced console output
- ✅ Module failure reporting