# 🛡️ SysGuard AI

> **AI-Powered Ubuntu System Monitoring & Security Dashboard**

SysGuard AI is a modern, intelligent Linux monitoring and security dashboard built for Ubuntu systems. It combines real-time system monitoring, security auditing, AI-powered analysis, and historical trend tracking into a single interface.

Unlike traditional monitoring tools that simply display metrics, SysGuard AI focuses on **understanding system health**, **detecting security risks**, and **providing actionable recommendations**.

---

## ✨ Features

### 📊 Live System Monitoring

- CPU Usage
- Memory Usage
- Disk Usage
- Swap Usage
- Health Score
- Overall System Status

---

### 🛡 Security Audits

Perform on-demand security scans including:

- Firewall Status
- Open Ports
- Failed SSH Login Detection
- Suspicious Cron Jobs
- Pending Security Updates
- AppArmor Status
- Rootkit Detection (rkhunter)
- Static File Analysis

---

### 🌐 Network Analysis

Monitor and inspect:

- Active Connections
- Listening Ports
- Network Statistics
- Packet Information
- Network Health

---

### 🤖 AI Advisor

AI-powered assistant capable of:

- Explaining system issues
- Recommending fixes
- Analyzing security findings
- Suggesting performance improvements

*(Future versions will support local LLMs such as Ollama.)*

---

### 📈 History & Trends

Track historical system information including:

- CPU Trends
- RAM Trends
- Health Score History
- Database Statistics
- Performance Changes

---

### ⚡ Smart Actions

Automatically suggest maintenance actions including:

- Cache Cleaning
- System Optimization
- Disk Cleanup
- Security Recommendations

---

## 🖥 Dashboard

Current modules include:

```
✔ Live Monitoring
✔ Security Audits
✔ Network Analysis
✔ AI Advisor
✔ Smart Actions
✔ Historical Analytics
```

---

## 📷 Screenshots

### Live Monitoring

![Dashboard](assets/dashboard.png)

---

### Security Audit

![Security](assets/security.png)

---

### History & Trends

![History](assets/history.png)

---

## 🏗 Project Structure

```
SysGuard-AI/
│
├── app.py
├── actions.py
├── ai_advisor.py
├── cache_manager.py
├── health_score.py
├── malware_analysis.py
├── metrics_store.py
├── network_analysis.py
├── report_generator.py
├── security_checks.py
├── system_monitor.py
│
├── requirements.txt
├── README.md
├── LICENSE
├── .gitignore
│
├── assets/
├── reports/
└── captures/
```

---

## 🚀 Installation

Clone the repository

```bash
git clone https://github.com/yourusername/SysGuard-AI.git
```

Enter project

```bash
cd SysGuard-AI
```

Create virtual environment

```bash
python3 -m venv venv
```

Activate

Linux

```bash
source venv/bin/activate
```

Windows

```bash
venv\Scripts\activate
```

Install dependencies

```bash
pip install -r requirements.txt
```

Run

```bash
streamlit run app.py
```

---

## Requirements

- Ubuntu 22.04+
- Python 3.11+
- Streamlit
- psutil
- pandas
- plotly

Some security features require:

- sudo privileges
- rkhunter
- ufw
- AppArmor
- systemctl

---

## Health Score

SysGuard AI generates an overall health score using multiple indicators:

- CPU Utilization
- RAM Usage
- Disk Health
- Swap Usage
- Security Checks
- Stability Metrics
- Performance Metrics

The goal is to summarize overall system health into a single score while still providing detailed diagnostics.

---

## Security Philosophy

SysGuard AI is designed around three principles:

- Monitor continuously
- Detect intelligently
- Recommend actionable fixes

The project focuses on assisting administrators rather than replacing security professionals.

---

## Roadmap

### Version 1

- [x] Live Monitoring
- [x] Health Score
- [x] Security Audits
- [x] History
- [x] Reports

---


- System Monitoring
- Threat Detection
- AI-Assisted Analysis
- Historical Analytics
- Local LLM Assistance
- Automated Recommendations

while remaining fully self-hosted.

---

## Contributing

Contributions, ideas, bug reports, and feature requests are welcome.

Feel free to fork the repository and submit pull requests.

---



## License

This project is licensed under the **GNU General Public License v3.0 (GPL-3.0)**.

You are free to use, study, modify, and distribute this software under the terms of the GPLv3. Any distributed modified versions must also be released under the GPLv3.

See the [LICENSE](LICENSE) file for details.

---

## Author

**Arzoo Singh**

Cybersecurity • AI • Linux • Open Source

---

>
