# 🛡️ CyberShield Enterprise XDR

> **An Automated Network Vulnerability Assessment & USB Malware Detection Platform**

CyberShield Enterprise XDR is a Flask-based cybersecurity application that combines network security assessment and USB malware detection into a single dashboard. The platform automatically detects USB devices, performs malware scanning, assesses network vulnerabilities, and generates professional PDF security reports with risk analysis and recommendations.

---

# 📌 Features

## 🌐 Network Security Assessment
- Network Port Scanner
- Banner Grabbing
- Service Detection
- Risk Assessment (High / Medium / Low)
- Security Score Calculation
- Executive Recommendations
- Professional PDF Report Generation

---

## 💾 USB Malware Detection

- Automatic USB Detection
- Automatic USB Scanning
- SHA-256 File Hashing
- Suspicious File Detection
- Malware Risk Classification
- Live USB Scan Results
- Professional USB PDF Report

---

## 📊 Enterprise XDR Dashboard

- Live Dashboard Updates
- Security Score
- Scan History
- Total Scan Statistics
- Open Port Statistics
- High-Risk Findings
- Real-Time USB Status
- Download Reports

---

# 🛠 Technologies Used

| Technology | Purpose |
|------------|---------|
| Python | Backend Development |
| Flask | Web Framework |
| HTML5 | User Interface |
| CSS3 | Styling |
| Bootstrap | Responsive Dashboard |
| JavaScript | Live Updates |
| SQLite | Scan History Database |
| ReportLab | PDF Report Generation |
| Socket Library | Port Scanning |
| Hashlib | SHA-256 Hashing |

---

# 📂 Project Structure

```text
CyberShield/
│
├── app.py
├── requirements.txt
├── README.md
├── cybershield.db
│
├── scanner/
│   ├── validator.py
│   ├── port_scanner.py
│   ├── report.py
│   └── database.py
│
├── usb/
│   ├── monitor.py
│   ├── malware.py
│   ├── hashing.py
│   └── file_scanner.py
│
├── templates/
│   ├── index.html
│   └── history.html
│
├── static/
├── reports/
└── signatures/
```

---

# ⚙️ Installation

## Clone the Repository

```bash
git clone https://github.com/yourusername/CyberShield-Enterprise-XDR.git
cd CyberShield-Enterprise-XDR
```

## Create Virtual Environment

```bash
python3 -m venv venv
```

Activate:

### Linux

```bash
source venv/bin/activate
```

### Windows

```bash
venv\Scripts\activate
```

---

## Install Dependencies

```bash
pip install -r requirements.txt
```

---

## Run the Application

```bash
python3 app.py
```

Open your browser:

```
http://127.0.0.1:5000
```

---

# 🚀 How It Works

## Network Scan

1. Enter an IP address or domain.
2. Start the scan.
3. CyberShield scans common ports.
4. Open services are identified.
5. Banner grabbing is performed.
6. Risk levels are calculated.
7. A professional PDF report is generated.

---

## USB Scan

1. Insert a USB drive.
2. CyberShield automatically detects the device.
3. USB scanning starts automatically.
4. Files are analyzed.
5. SHA-256 hashes are generated.
6. Suspicious files are identified.
7. A USB malware report is generated automatically.

---

# 📄 Generated Reports

CyberShield generates:

- Network Security Assessment Report
- USB Malware Scan Report

Each report contains:

- Executive Summary
- Risk Analysis
- Security Score
- Scan Results
- Business Impact
- Security Recommendations

---

# 📸 Screenshots

Add screenshots of:

- Dashboard
- Network Scan Results
- USB Scan Results
- Network PDF Report
- USB PDF Report
- Scan History

---

# 🔒 Security Features

- Network Port Scanning
- Banner Grabbing
- Risk Classification
- SHA-256 Hashing
- Automatic USB Detection
- Malware Identification
- PDF Security Reporting
- Live Dashboard Monitoring

---

# 🚀 Future Enhancements

- SIEM Integration
- Threat Intelligence Feeds
- Email Alert System
- Multi-Host Scanning
- AI-Based Threat Detection
- Scheduled Scanning
- User Authentication
- Cloud Deployment

---

# 🎯 Learning Outcomes

This project demonstrates practical knowledge of:

- Network Security
- Vulnerability Assessment
- Socket Programming
- Flask Web Development
- Database Management
- Malware Detection Concepts
- SHA-256 Hashing
- PDF Report Generation
- Enterprise Security Dashboard Design

---

# 👨‍💻 Author

**Krutarth Dhanak**

Master's Student – Cyber Security Management

---

# 📜 License

This project was developed for academic and educational purposes.
