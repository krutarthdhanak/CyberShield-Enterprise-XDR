# 🛡 CyberShield Enterprise XDR

> Automated Network Vulnerability Assessment, USB Threat Detection & XDR Monitoring Platform

CyberShield Enterprise XDR is a Flask-based cybersecurity platform designed to combine network vulnerability assessment, automated USB malware detection, risk analysis, XDR event monitoring, and professional security reporting in a single dashboard.

The platform automatically detects removable USB devices, scans their contents, calculates risk, generates PDF reports, and records security events in an XDR activity feed.

---

# 🚀 Key Features

## 🌐 Network Vulnerability Assessment

- IP Address / Domain Validation
- TCP Port Scanning
- Banner Grabbing
- Service Detection
- Port Risk Classification
- High / Medium / Low Risk Analysis
- Security Score Calculation
- Network Scan History
- Professional PDF Security Reports

---

## 💾 Automatic USB Threat Detection

- Automatic USB Device Detection
- Automatic USB Mounting
- Automatic USB Scanning
- File Extension Analysis
- Suspicious File Detection
- Malware Risk Classification
- SHA-256 File Hashing
- Live USB Scan Results
- Automatic USB PDF Report Generation
- USB Threat Logging

No manual scan button is required after inserting a USB device.

---

# 🛡 Enterprise XDR Monitoring

CyberShield Enterprise XDR records important security activities through an XDR event system.

### XDR Events Include

- Network Scan Started
- Network Scan Completed
- Network Scan Failed
- USB Scan Completed
- USB Suspicious Activity
- USB Threat Detected

Each event contains:

- Event Type
- Severity
- Source
- Security Details
- Timestamp

Example:

```text
USB_THREAT_DETECTED
Severity: CRITICAL
Source: USB Scanner
Details: 11 infected files detected
