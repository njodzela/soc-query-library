# 🛡️ SOC Query Library

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-v14-red)](https://attack.mitre.org/)
[![Platforms](https://img.shields.io/badge/Platforms-5%20SIEMs-green)](#supported-platforms)
[![Detections](https://img.shields.io/badge/Detections-50+-orange)](#detection-categories)

A production-grade collection of detection queries spanning **5 major SIEM platforms** and **10 threat categories** mapped to the MITRE ATT&CK framework. Built for SOC analysts, detection engineers, and threat hunters.

**Author:** Christian M. Njodzela

---

## 📋 Supported Platforms

| Platform | Language | Directory |
|----------|----------|-----------|
| Splunk | SPL | [`splunk/`](splunk/) |
| Microsoft Sentinel | KQL | [`sentinel/`](sentinel/) |
| IBM QRadar | AQL | [`qradar/`](qradar/) |
| Google SecOps (Chronicle) | YARA-L 2.0 | [`google-secops/`](google-secops/) |
| Microsoft Defender | KQL (Advanced Hunting) | [`defender/`](defender/) |

## 🎯 Detection Categories

| # | Category | MITRE Tactic | Key Techniques |
|---|----------|-------------|----------------|
| 1 | Brute-Force Detection | Credential Access | T1110.001, T1110.003, T1110.004 |
| 2 | Lateral Movement | Lateral Movement | T1021.001, T1021.002, T1021.004, T1570 |
| 3 | Data Exfiltration | Exfiltration | T1048.001, T1048.002, T1567, T1041 |
| 4 | Phishing Indicators | Initial Access | T1566.001, T1566.002, T1598 |
| 5 | Privilege Escalation | Privilege Escalation | T1068, T1548.002, T1134, T1078.002 |
| 6 | Persistence Mechanisms | Persistence | T1053.005, T1547.001, T1136, T1543.003 |
| 7 | Command and Control | Command and Control | T1071.001, T1071.004, T1573, T1105 |
| 8 | Credential Access | Credential Access | T1003.001, T1558.003, T1555, T1552 |
| 9 | Defense Evasion | Defense Evasion | T1070.001, T1562.001, T1036.005, T1027 |
| 10 | Reconnaissance | Reconnaissance | T1595, T1592, T1589, T1590 |

## 🗺️ MITRE ATT&CK Coverage Matrix

```
┌─────────────────────┬────────┬──────────┬────────┬─────────────┬──────────┐
│ Tactic              │ Splunk │ Sentinel │ QRadar │ Google SecOps│ Defender │
├─────────────────────┼────────┼──────────┼────────┼─────────────┼──────────┤
│ Reconnaissance      │   ✅   │    ✅    │   ✅   │      ✅     │    ✅    │
│ Initial Access      │   ✅   │    ✅    │   ✅   │      ✅     │    ✅    │
│ Persistence         │   ✅   │    ✅    │   ✅   │      ✅     │    ✅    │
│ Privilege Escalation│   ✅   │    ✅    │   ✅   │      ✅     │    ✅    │
│ Defense Evasion     │   ✅   │    ✅    │   ✅   │      ✅     │    ✅    │
│ Credential Access   │   ✅   │    ✅    │   ✅   │      ✅     │    ✅    │
│ Lateral Movement    │   ✅   │    ✅    │   ✅   │      ✅     │    ✅    │
│ Command and Control │   ✅   │    ✅    │   ✅   │      ✅     │    ✅    │
│ Exfiltration        │   ✅   │    ✅    │   ✅   │      ✅     │    ✅    │
└─────────────────────┴────────┴──────────┴────────┴─────────────┴──────────┘
```

## 🚀 Quick Start

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/soc-query-library.git
   ```

2. **Navigate to your SIEM platform directory**
   ```bash
   cd soc-query-library/splunk/
   ```

3. **Import queries into your SIEM** — each file is self-contained with documentation, tuning guidance, and false positive notes.

## 📁 Repository Structure

```
soc-query-library/
├── README.md
├── LICENSE
├── CONTRIBUTING.md
├── .gitignore
├── splunk/              # 10 SPL detection queries
├── sentinel/            # 10 KQL detection queries
├── qradar/              # 10 AQL detection queries
├── google-secops/       # 10 YARA-L 2.0 detection rules
├── defender/            # 10 KQL Advanced Hunting queries
└── mitre-mapping/
    └── attack-navigator.json
```

## 🤝 Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## 📄 License

This project is licensed under the MIT License — see [LICENSE](LICENSE).

---

> *"Detection is not a product, it's a process."* — SOC Query Library
