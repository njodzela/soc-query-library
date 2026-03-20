# 🛡️ SOC Query Library

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-v14-red)](https://attack.mitre.org/)
[![Platforms](https://img.shields.io/badge/Platforms-5%20SIEMs-green)](#supported-platforms)
[![Detections](https://img.shields.io/badge/Detections-48%20Rules%20·%2030%20Hunting%20Queries-orange)](#detection-categories)

A production-grade collection of **48 detection rules** and **30 threat hunting queries** spanning **5 major SIEM platforms** and **16 threat categories** mapped to the MITRE ATT&CK framework. Built for SOC analysts, detection engineers, and threat hunters.

**Author:** Christian M. Njodzela · Cybersecurity Analyst & Detection Engineer

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
| 2 | Command and Control | Command and Control | T1071.001, T1071.004, T1573, T1105 |
| 3 | Credential Access | Credential Access | T1003.001, T1558.003, T1555, T1552 |
| 4 | Data Exfiltration | Exfiltration | T1048.001, T1048.002, T1567, T1041 |
| 5 | Defense Evasion | Defense Evasion | T1070.001, T1562.001, T1036.005, T1027 |
| 6 | Lateral Movement | Lateral Movement | T1021.001, T1021.002, T1021.006, T1570 |
| 7 | Persistence Mechanisms | Persistence | T1053.005, T1547.001, T1543.003, T1574.002 |
| 8 | Phishing Indicators | Initial Access | T1566.001, T1566.002, T1598 |
| 9 | Privilege Escalation | Privilege Escalation | T1068, T1548.002, T1134, T1078.002 |
| 10 | Reconnaissance | Reconnaissance | T1595, T1590, T1589 |
| 11 | Forwarding Rule Abuse ★ | Collection | T1114.003 |
| 12 | Impossible Travel ★ | Identity | T1078, T1078.004 |
| 13 | Spam Bot Detection ★ | Initial Access | T1566, T1071, T1078 |
| 14 | Email Spoofing ★ | Initial Access | T1566.001, T1566.002, T1534 |
| 15 | Anomalous Process Execution ★ | Execution / Evasion | T1059, T1036, T1218, T1204 |
| 16 | Routine Threat Hunting ★ | Proactive | T1053, T1547, T1105, T1543, T1574 |

> ★ = New categories added in the 2026 edition

## 📚 Documentation

| Document | Description |
|----------|-------------|
| [`docs/SOC-Query-Library-Simplified.md`](docs/SOC-Query-Library-Simplified.md) | Simplified reference card — all 48 rules with match conditions, risk scores, and tuning guidance at a glance |
| [`docs/Threat-Hunting-Quick-Reference.md`](docs/Threat-Hunting-Quick-Reference.md) | 30 copy-paste hunting queries organized by investigation type (Identity, Network, Endpoint, Email, Lateral Movement, Cloud) with swap placeholders and triage guidance |

## 🗺️ MITRE ATT&CK Coverage Matrix

```
┌──────────────────────┬────────┬──────────┬────────┬──────────────┬──────────┐
│ Tactic               │ Splunk │ Sentinel │ QRadar │ Google SecOps│ Defender │
├──────────────────────┼────────┼──────────┼────────┼──────────────┼──────────┤
│ Reconnaissance       │   ✅   │    ✅    │   ✅   │      ✅      │    ✅    │
│ Initial Access       │   ✅   │    ✅    │   ✅   │      ✅      │    ✅    │
│ Execution            │   ✅   │    ✅    │   ✅   │      ✅      │    ✅    │
│ Persistence          │   ✅   │    ✅    │   ✅   │      ✅      │    ✅    │
│ Privilege Escalation │   ✅   │    ✅    │   ✅   │      ✅      │    ✅    │
│ Defense Evasion      │   ✅   │    ✅    │   ✅   │      ✅      │    ✅    │
│ Credential Access    │   ✅   │    ✅    │   ✅   │      ✅      │    ✅    │
│ Lateral Movement     │   ✅   │    ✅    │   ✅   │      ✅      │    ✅    │
│ Collection           │   ✅   │    ✅    │   ✅   │      ✅      │    ✅    │
│ Command and Control  │   ✅   │    ✅    │   ✅   │      ✅      │    ✅    │
│ Exfiltration         │   ✅   │    ✅    │   ✅   │      ✅      │    ✅    │
│ Identity (cross)     │   ✅   │    ✅    │   ✅   │      ✅      │    ✅    │
└──────────────────────┴────────┴──────────┴────────┴──────────────┴──────────┘
```

**40+ MITRE ATT&CK techniques** covered across all 14 tactics.

## 🚀 Quick Start

1. **Clone the repository**
   ```bash
   git clone https://github.com/njodzela/soc-query-library.git
   ```

2. **Navigate to your SIEM platform directory**
   ```bash
   cd soc-query-library/google-secops/
   ```

3. **Import queries into your SIEM** — each file is self-contained with documentation, tuning guidance, and false positive notes.

4. **For hunting** — open [`docs/Threat-Hunting-Quick-Reference.md`](docs/Threat-Hunting-Quick-Reference.md), find the query matching your investigation, swap the placeholders, and paste into Chronicle.

## 📁 Repository Structure

```
soc-query-library/
├── README.md
├── LICENSE
├── CONTRIBUTING.md
├── .gitignore
├── docs/
│   ├── SOC-Query-Library-Simplified.md     # Simplified rule reference
│   └── Threat-Hunting-Quick-Reference.md   # 30 hunting queries
├── splunk/              # SPL detection queries
├── sentinel/            # KQL detection queries
├── qradar/              # AQL detection queries
├── google-secops/       # YARA-L 2.0 detection rules (48 rules)
├── defender/            # KQL Advanced Hunting queries
└── mitre-mapping/
    └── attack-navigator.json
```

## 🤝 Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## 📄 License

This project is licensed under the MIT License — see [LICENSE](LICENSE).

---

> *"Detection is not a product, it's a process."* — SOC Query Library

© 2026 Christian M. Njodzela
