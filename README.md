# 🔐 NovaCrypt Defense - Hybrid Hacking Toolkit

![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)
![Streamlit](https://img.shields.io/badge/Streamlit-1.28+-red.svg)
![License](https://img.shields.io/badge/License-Educational-green.svg)
![Status](https://img.shields.io/badge/Status-Active-brightgreen.svg)

**A comprehensive Python-based cybersecurity testing toolkit designed for PayBuddy FinTech security assessment.**

> **CY4053 - Cybersecurity for FinTech | Final Project | Fall 2025**

---

## 👥 Team: NovaCrypt Defense

- **Moazam** | BSFT07-9953
- **Abdullah** | BSFT07-7465

---

## 🎯 Project Overview

NovaCrypt Defense is an all-in-one ethical hacking suite developed for authorized security testing of PayBuddy's APIs and wallet services. Built entirely in Python without external Kali Linux tools, it provides modular security assessment capabilities with comprehensive logging and reporting.

### 🚀 Key Features

- ✅ **Identity & Safety Verification** - Mandatory consent and identity checks before execution
- 🔍 **Port Scanner** - TCP scanning with banner grabbing and service detection
- 🔑 **Password Assessment** - Policy validation, entropy analysis, and hash testing
- 💥 **DOS/Stress Testing** - Controlled load testing with latency monitoring
- 🌐 **Web Discovery** - Directory enumeration and API endpoint discovery
- 📦 **Packet Capture** - Network traffic analysis with protocol filtering
- 📊 **Automated Reporting** - PDF/Word/JSON reports with SHA-256 integrity

---

## 🛠️ Technology Stack

- **Frontend:** Streamlit (Interactive Dashboard)
- **Backend:** Python 3.9+
- **Security Tools:** Custom-built Python implementations
- **Logging:** Centralized logging with SHA-256 integrity
- **Reporting:** Auto-generated PDF/Word documents

---

## 📋 Modules

### 1️⃣ Identity & Safety
- Verifies `identity.txt` and `consent.txt` before any operation
- Implements `--dry-run` mode for safe testing
- Blocks execution if verification fails

### 2️⃣ Port Scanner
- Multi-threaded TCP port scanning
- Banner grabbing for service identification
- Export results to JSON/HTML

### 3️⃣ Password Assessment
- Password policy compliance checking
- Entropy calculation (Shannon entropy)
- Offline hash simulation (MD5, SHA256, bcrypt)

### 4️⃣ DOS/Stress Testing
- Configurable client load (max 200 concurrent)
- Real-time latency monitoring
- Generates performance plots and graphs

### 5️⃣ Web Discovery (DIRB-style)
- Directory and subdomain enumeration
- API endpoint discovery
- Rate-limited for ethical testing

### 6️⃣ Packet Capture & Analysis
- Real-time network traffic capture
- Protocol filtering (HTTP, HTTPS, DNS, TCP)
- Saves .pcap files with parsed summaries

### 7️⃣ Logging & Reporting
- Append-only tamper-proof logs
- SHA-256 integrity verification
- Downloadable reports in multiple formats

---

## 🚀 Quick Start

### Prerequisites
```bash
Python 3.9 or higher
pip (Python package manager)
```

### Installation

1. **Clone the repository:**
```bash
git clone https://github.com/YOUR_USERNAME/NovaCrypt-Defense.git
cd NovaCrypt-Defense
```

2. **Install dependencies:**
```bash
pip install -r requirements.txt
```

3. **Run the application:**
```bash
streamlit run app.py
```

4. **Access the dashboard:**
```
Open your browser and navigate to: http://localhost:8501
```

---

## 📁 Project Structure

```
NovaCrypt-Defense/
├── app.py                 # Main Streamlit application
├── requirements.txt       # Python dependencies
├── identity.txt          # Team identity verification
├── consent.txt           # Approved testing targets
├── evidence/             # Generated logs and reports
│   └── report and demo video
├── README.md             # Project documentation
└── .gitignore           # Git ignore rules
```

---

## 🎨 Dashboard Preview

The toolkit features a modern cybersecurity-themed interface with:
- **Dark gradient background** (cyber purple/blue theme)
- **Glowing text effects** and animated buttons
- **Real-time logging** display
- **Module selection** via sidebar navigation
- **Session statistics** and metrics

---

## ⚠️ Ethical Testing Guidelines

### Approved Targets Only
- ✅ localhost / 127.0.0.1
- ✅ http://testphp.vulnweb.com
- ✅ scanme.nmap.org
- ✅ Personal test servers
- ✅ Authorized lab environments

### Prohibited Actions
- ❌ Never test external/public systems without permission
- ❌ No malicious use of the toolkit
- ❌ Always follow responsible disclosure practices

---

## 📊 Features & Capabilities

| Feature | Status | Description |
|---------|--------|-------------|
| Identity Verification | ✅ Complete | Auto-checks identity and consent files |
| Centralized Logging | ✅ Complete | Timestamped logs with SHA-256 integrity |
| Port Scanner | ✅ Complete | Multi-threaded TCP scanning |
| Password Assessment | ✅ Complete | Policy checks and entropy analysis |
| DOS/Stress Testing | ✅ Complete | Controlled load testing |
| Web Discovery | ✅ Complete | Directory and API enumeration |
| Packet Capture | ✅ Complete | Traffic analysis with filtering |
| Auto Reporting | ✅ Complete | PDF/Word/JSON export |

---

## 🔒 Security Features

- **Consent-based execution** - Requires explicit approval
- **Tamper-proof logging** - SHA-256 integrity checks
- **Rate limiting** - Prevents aggressive testing
- **Dry run mode** - Test without actual attacks
- **Real-time monitoring** - Track all operations

---

## 📝 Logging System

Every action is logged with:
- Timestamp (YYYY-MM-DD HH:MM:SS)
- Module name (e.g., PORT_SCAN, WEB_DISCOVERY)
- Action performed
- Detailed results

Example log entry:
```
[2025-11-30 15:23:45] [INFO] [PORT_SCAN] Started scan on testphp.vulnweb.com
[2025-11-30 15:23:50] [INFO] [PORT_SCAN] Found open port: 80 (HTTP)
```

---

## 📈 Report Generation

The toolkit generates comprehensive reports including:
- Executive summary of findings
- Detailed module results
- Security vulnerabilities discovered
- Remediation recommendations
- FinTech-specific security advice

**Export Formats:**
- PDF Report
- Word Document (.docx)
- JSON Data
- Plain text logs

---

## 🎓 Academic Context

**Course:** CY4053 - Cybersecurity for FinTech  
**Instructor:** Dr. Usama Arshad  
**Institution:** BSFT - 7th Semester (Fall 2025)  
**Project Type:** Final Project (Group Work)  
**Deadline:** November 30, 2025

---

## 📜 License

This project is developed for **educational purposes only** as part of the CY4053 course. 

**Disclaimer:** This toolkit is designed for authorized security testing only. Unauthorized use of these tools against systems you do not own or have explicit permission to test is illegal and unethical.

---

## 🙏 Acknowledgments

- Dr. Usama Arshad for project guidance
- PayBuddy FinTech (fictional scenario)
- Open-source Python community
- Streamlit framework developers

---

## 📧 Contact

For questions or feedback regarding this project:

- **Team Lead:** Moazam (BSFT07-9953)
- **Team Member:** Abdullah (BSFT07-7465)

---

## 🔗 Links

- 🌐 **Live Demo:** (https://novacryptdefense-cb5gkgwkjxyue8u7mspp8d.streamlit.app/)
- 📹 **Github Repository:** (https://github.com/moazamrathore/NovaCrypt_Defense)

---

<div align="center">

**⭐ Star this repository if you find it useful!**

Made with 💙 by NovaCrypt Defense Team

</div>
