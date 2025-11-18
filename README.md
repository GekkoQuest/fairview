# Fairview v0.2.0

**Fairview** is a comprehensive interview monitoring system designed to detect potential cheating attempts during technical interviews and coding assessments. It provides real-time monitoring of system activities, processes, hardware configurations, and virtualization environments.

## Features

### 🖥️ Process Monitoring
- Detects suspicious processes with screen/audio capture capabilities
- Identifies processes started during the interview
- Monitors for AI assistants and automation tools
- Tracks accessibility API usage
- Configurable whitelist for legitimate applications

### 🎥 Screen Overlay Detection
- Identifies hidden transparent windows
- Detects topmost layered windows
- Monitors suspicious overlay applications

### 🎤 Audio Capture Detection
- Detects real-time audio processing applications
- Monitors microphone access across platforms
- Identifies recording and streaming software

### 🖥️ Hardware Monitoring
- **Display Configuration Tracking**
  - Monitors for multiple displays
  - Detects virtual displays
  - Identifies HDMI splitters
  - Tracks display changes during interviews
  
- **Remote Desktop Detection**
  - Windows RDP monitoring
  - macOS Screen Sharing detection
  - Linux VNC/remote desktop detection

### 🆕 Virtual Machine Detection
- **CPUID Hypervisor Detection**
  - Checks hypervisor presence bit
  - Identifies VM vendor (VMware, VirtualBox, QEMU, KVM, Xen, etc.)
  
- **System Fingerprinting**
  - Analyzes system model names
  - Checks hostname patterns
  
- **Network Adapter Analysis**
  - Detects VM-specific MAC address prefixes
  - Identifies VirtualBox, VMware, QEMU, and Parallels network adapters

- **Confidence Scoring**
  - Provides detailed reasoning for VM detection
  - Assigns risk scores based on multiple indicators

### 📊 Risk Scoring System
- Weighted risk calculation across all detection categories
- Configurable thresholds for each monitoring type
- Overall risk assessment with customizable alert levels

### 📁 Detailed Reporting
- JSON reports with timestamps
- Comprehensive detection details
- Process-level risk analysis
- Hardware change tracking
- VM detection confidence scores

## Installation

### Prerequisites
- Rust 1.70 or later
- Cargo package manager

### Platform-Specific Requirements

**Windows:**
- Windows 10/11 or Windows Server 2016+
- Administrator privileges for some features

**macOS:**
- macOS 10.15 (Catalina) or later
- Appropriate system permissions for monitoring

**Linux:**
- Modern Linux distribution
- X11 or Wayland display server
- PulseAudio, PipeWire, or ALSA

### Build from Source

```bash
git clone https://github.com/GekkoQuest/fairview.git
cd fairview
cargo build --release
```

The compiled binary will be available at `target/release/fairview`

## Usage

### Quick Start

1. Run Fairview with default configuration:
```bash
cargo run --release
```

Or if already built:
```bash
./target/release/fairview
```

2. On first run, a `fairview_config.toml` file will be created with default settings.

3. The system will collect a baseline of running processes and hardware configuration.

4. Press Enter to begin continuous monitoring.

### Configuration

Edit `fairview_config.toml` to customize behavior:

```toml
[scan]
interval_seconds = 30          # Scan frequency
risk_threshold = 0.5           # Alert threshold (0.0-1.0)
interview_type = "coding"      # Interview context

[weights]
process_risk = 0.30    # Weight for suspicious processes
overlay_risk = 0.20    # Weight for screen overlays
audio_risk = 0.10      # Weight for audio monitoring
hardware_risk = 0.15   # Weight for hardware changes
vm_risk = 0.25         # Weight for VM detection

[thresholds]
process_threshold = 0.6     # Individual process risk threshold
hardware_threshold = 0.5    # Hardware change threshold
audio_threshold = 0.3       # Audio monitoring threshold
overlay_threshold = 0.4     # Overlay detection threshold

[whitelist]
processes = [
    "code.exe",
    "vscode.exe",
    "chrome.exe",
    "firefox.exe",
]

directories = [
    "C:\\Program Files\\Git",
    "/usr/bin",
    "/Applications",
]

[monitoring]
enable_process_monitoring = true
enable_hardware_monitoring = true
enable_audio_monitoring = true
enable_overlay_monitoring = true
enable_vm_detection = true
collect_baseline = true
baseline_duration_seconds = 10
continue_on_module_failure = true
```

## Output

### Console Output

```
==============================================================
FAIRVIEW DETECTION REPORT - Scan #3
==============================================================
Timestamp: 2024-11-18 15:30:45 UTC

🔴 🔴 CRITICAL: VIRTUAL MACHINE DETECTED 🔴 🔴
Confidence Score: 0.90
  - CPUID hypervisor bit set
  - Hypervisor Vendor detected: VMware
  - VM Network Adapter (VMware) detected on eth0

Overall Risk Score: 0.85/1.0
⚠️  STATUS: RISK THRESHOLD EXCEEDED

SUSPICIOUS PROCESSES:
  - cluely.exe (PID: 4521)
    Risk Score: 0.70
    ⚠️  Started during interview
    Reasons:
      * Suspicious process name
      * Has screen capture permission
      * Started during interview

HARDWARE SUMMARY:
  Risk Score: 0.45
  Display Count: 2
  ⚠️  Display configuration changed (Baseline: 1)
  Flags:
    * Multiple displays detected: 2 displays
    * New display connected during interview: Generic PnP Monitor

==============================================================
```

### JSON Reports

Reports are automatically saved with timestamps:
```
detection_report_20241118_153045.json
```

Example JSON structure:
```json
{
  "timestamp": "2024-11-18T15:30:45.123Z",
  "scan_number": 3,
  "overall_risk_score": 0.85,
  "exceeds_threshold": true,
  "vm_detection": {
    "is_vm": true,
    "confidence_score": 0.90,
    "reasons": [
      "CPUID hypervisor bit set",
      "Hypervisor Vendor detected: VMware",
      "VM Network Adapter (VMware) detected on eth0"
    ]
  },
  "suspicious_processes": [...],
  "hardware_suspicion": {...},
  "audio_monitoring_detected": false,
  "hidden_overlays": []
}
```

## Detection Methods

### VM Detection Algorithm

Fairview uses multiple techniques to detect virtual machines:

1. **CPUID Instruction Analysis**
   - Checks the hypervisor presence bit (CPUID.0x1.ECX[31])
   - Identifies specific hypervisor vendors through CPUID leaves

2. **System Information Inspection**
   - Analyzes system model names for VM-specific strings
   - Checks for VM-related keywords in hostname

3. **Network Adapter Fingerprinting**
   - Detects MAC address prefixes assigned to VM vendors:
     - VMware: 00:05:69, 00:0C:29, 00:1C:14, 00:50:56
     - VirtualBox: 08:00:27
     - QEMU/KVM: 52:54:00
     - Xen: 00:16:3E
     - Parallels: 00:1C:42

4. **Confidence Scoring**
   - Hypervisor bit: +0.1 to +0.8 depending on vendor
   - System fingerprinting: +0.6
   - MAC address detection: +0.5
   - Threshold: 0.7 for VM classification

## Platform Support

| Feature | Windows | macOS | Linux |
|---------|---------|-------|-------|
| Process Monitoring | ✅ | ✅ | ✅ |
| Audio Detection | ✅ | ✅ | ✅ |
| Overlay Detection | ✅ | ❌ | ❌ |
| Hardware Monitoring | ✅ | ✅ | ✅ |
| VM Detection | ✅ | ✅ | ✅ |
| Remote Desktop Detection | ✅ | ✅ | ✅ |

## Troubleshooting

### Permission Issues

**Windows:**
```bash
# Run as Administrator
./fairview
```

**macOS:**
```bash
# Grant appropriate permissions in System Preferences > Security & Privacy
```

**Linux:**
```bash
# Ensure user has access to /proc and network tools
```

### Module Failures

If specific modules fail, check the console output for error messages. You can disable problematic modules in the configuration:

```toml
[monitoring]
enable_vm_detection = false  # Disable if causing issues
```

## Development

### Project Structure

```
fairview/
├── src/
│   ├── main.rs              # Main application logic
│   ├── config.rs            # Configuration management
│   ├── process_monitor.rs   # Process detection
│   ├── audio_detector.rs    # Audio monitoring
│   ├── overlay_detector.rs  # Overlay detection
│   ├── hardware_detector.rs # Hardware monitoring
│   └── vm_detector.rs       # VM detection (NEW)
├── Cargo.toml
└── fairview_config.toml
```

### Building for Development

```bash
cargo build
cargo run
```

### Running Tests

```bash
cargo test
```

## Dependencies

- `sysinfo` - System and process information
- `serde` / `serde_json` - Serialization
- `tokio` - Async runtime
- `toml` - Configuration parsing
- `chrono` - Timestamp handling
- `raw-cpuid` - CPUID instruction access for VM detection
- `windows` - Windows API bindings (Windows only)

## Changelog

### v0.2.0
- **Added:** Comprehensive VM detection system
- **Added:** CPUID hypervisor bit checking
- **Added:** Hypervisor vendor identification
- **Added:** VM network adapter fingerprinting
- **Added:** Confidence scoring for VM detection
- **Enhanced:** Risk weighting system to include VM risk
- **Improved:** Reporting with VM detection details

### v0.1.0
- Initial release
- Process monitoring
- Audio capture detection
- Screen overlay detection
- Hardware monitoring
- Risk scoring system

## Contributing

Contributions are welcome! Please:
- Fork the [repository](https://github.com/GekkoQuest/fairview)
- Create a feature branch
- Ensure code follows Rust best practices
- Ensure all tests pass
- Update documentation as needed
- Maintain ethical considerations
- Submit a pull request

## License

This project is licensed under the MIT License. See the [LICENSE](https://github.com/GekkoQuest/fairview/blob/main/LICENSE) file for details.

## Support

For issues, questions, or feature requests, please open an issue on the [GitHub repository](https://github.com/GekkoQuest/fairview/issues).

## Disclaimer

This software is provided "as is" without warranty. Users are responsible for ensuring compliance with all applicable laws and regulations. The developers assume no liability for misuse of this software.