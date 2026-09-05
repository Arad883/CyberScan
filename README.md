# CyberScan
Multi-threaded port scanner with smart banner grabbing &amp; instant security alerts for misconfigurations (Redis, MySQL, SSH)

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.6%2B-blue?style=for-the-badge&logo=python&logoColor=white" alt="Python Version"/>
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License MIT"/>
  <img src="https://img.shields.io/badge/Security-Recon-red?style=for-the-badge&logo=hackaday&logoColor=white" alt="Security Recon"/>
  <img src="https://img.shields.io/badge/Threading-High%20Performance-orange?style=for-the-badge" alt="Multi-threading"/>
</p>

<h1 align="center">🔒 CyberScan</h1>
<p align="center">
  <b>Professional Port Scanner & Service Detector for Security Assessments</b><br>
  <i>Lightning-fast multi-threaded scanning with smart banner grabbing and risk analysis.</i>
</p>

---

## 📖 Table of Contents
- [✨ Features](#-features)
- [⚙️ Installation](#️-installation)
- [🚀 Quick Start](#-quick-start)
- [📋 Command Line Options](#-command-line-options)
- [💡 Practical Examples](#-practical-examples)
- [🛡️ Security Alerts Logic](#️-security-alerts-logic)
- [📸 Sample Output](#-sample-output)
- [⚠️ Legal Disclaimer](#️-legal-disclaimer)
- [🤝 Contributing](#-contributing)

---

## ✨ Features

| Feature | Description |
| :--- | :--- |
| **⚡ Ultra-Fast** | Multi-threaded architecture (configurable up to 500+ threads) scans thousands of ports in seconds. |
| **📡 Smart Banner Grabbing** | Automatically retrieves service banners (HTTP, SSH, FTP, MySQL, etc.) to identify exact versions. |
| **🔥 Risk Assessment** | Built-in vulnerability heuristics instantly warn about misconfigurations like open Redis, default MySQL, or weak SSH settings. |
| **🎨 Beautiful CLI** | Color-coded, boxed interface with real-time progress updates and a structured final report. |
| **🧩 Zero Dependencies** | Uses only Python's standard library – no external packages required! |
| **🌍 Cross-Platform** | Works flawlessly on Linux, macOS, and Windows (WSL/PowerShell). |

---

## ⚙️ Installation

Getting started is as simple as cloning the repository. No `pip install` needed!

```bash
# Clone the repository
git clone https://github.com/Arad883/CyberScan.git

# Make it executable (Linux/macOS)
chmod +x cyberscan.py
```

Note: Requires Python 3.6 or higher. Check your version with python3 --version.

🚀 Quick Start

Run your first scan against a local or remote target:

```bash
python cyberscan.py -t 192.168.1.1 -p 1-1000 -th 150
```

This will scan the top 1000 ports on 192.168.1.1 using 150 concurrent threads.

---

📋 Command Line Options

Argument Alias Description Default
--target -t Required. Target IP address or domain name. None
--ports -p Port range to scan. (e.g., 20-1000 or 22,80,443) 1-1024
--threads -th Number of concurrent threads for faster scanning. 100
--timeout -to Connection timeout per port in seconds. 2.0
--help -h Show the help message and exit. -

---

💡 Practical Examples

1. Reconnaissance on a Web Server

Quickly check for common web, mail, and database ports:

```bash
python cyberscan.py -t example.com -p 21,22,25,80,443,3306,6379 -th 50
```

2. Deep Scan on Internal Network

Scan a large range with high speed (adjust timeout for local networks):

```bash
python cyberscan.py -t 10.0.0.1 -p 1-65535 -th 300 -to 0.5
```

3. Focused Scan for Critical Vulnerabilities

Check only for high-risk services that often have default credentials:

```bash
python cyberscan.py -t 172.16.1.10 -p 21,22,3306,6379,27017,1433
```

---

🛡️ Security Alerts Logic

CyberScan doesn't just find open ports; it thinks like a pentester. If it detects a service on a sensitive port, it immediately displays a red warning with remediation advice:

Port Service Alert Message
21 FTP Check if Anonymous Access is disabled.
22 SSH Enforce public-key authentication.
3306 MySQL Verify root user isn't accessible with a blank password.
6379 Redis CRITICAL: Check for missing authentication (requirepass).
27017 MongoDB Ensure --auth flag is enabled.

These warnings are built directly into the source code and can be easily extended for your own red-team or blue-team use cases.

---

📸 Sample Output

When you run CyberScan, your terminal will display a clean, boxed header followed by real-time results and a final summary.

```bash
┌──────────────────────────────────────────────────────────────┐
│  🔒 CyberScan v1.0 - Professional Port Scanner             │
│  📡 Target: 192.168.1.1                                    │
│  🧵 Threads: 150                                          │
│  📋 Total Ports: 1000                                     │
└──────────────────────────────────────────────────────────────┘

🚀 Starting scan on 192.168.1.1
⏳ Start time: 2026-09-05 14:23:10
🔍 Total ports to scan: 1000
🧵 Thread count: 150
----------------------------------------------------------------------
[+] Port 22 is open | Service: SSH
    ⚠️  SSH is open. Enforce public-key authentication and disable weak passwords!
    📄 Banner: SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5
[+] Port 80 is open | Service: HTTP
    📄 Banner: HTTP/1.1 200 OK Date: Sat, 05 Sep 2026 14:23:12 GMT Server: nginx/1.18.0
[+] Port 6379 is open | Service: Redis
    🔥 CRITICAL! Redis without authentication? Run 'CONFIG GET requirepass' immediately.
    📄 Banner: +OK

======================================================================
✅ Final Scan Report
======================================================================
Total open ports found: 3

Port     Service      Security Status
----------------------------------------------------------------------
22       SSH          ⚠️  Needs Review
   └─ ⚠️  SSH is open. Enforce public-key authentication.
80       HTTP         ✅ Safe
6379     Redis        ⚠️  Needs Review
   └─ 🔥 CRITICAL! Redis without authentication?
======================================================================
```

---

⚠️ Legal Disclaimer

🛑 IMPORTANT:
This tool is developed strictly for educational purposes, authorized penetration testing, and security research.

Scanning networks or systems without explicit written permission from the owner is illegal in most countries and violates computer fraud laws (e.g., CFAA in the US, Computer Misuse Act in the UK).

The author assumes zero liability for any misuse or damage caused by this software. Use responsibly and only on your own infrastructure or with proper authorization.

---

🤝 Contributing

We love contributions! If you have ideas for new features (like UDP scanning, output to JSON/CSV, or ICMP host discovery), feel free to:

1. Fork the repository.
2. Create your feature branch (git checkout -b feature/AmazingFeature).
3. Commit your changes (git commit -m 'Add some AmazingFeature').
4. Push to the branch (git push origin feature/AmazingFeature).
5. Open a Pull Request.

---

<div align="center">
  <sub>Built with ❤️ for the cybersecurity community.</sub><br>
  <sub>⭐ Don't forget to star the repository if you found it useful! ⭐</sub>
</div>
