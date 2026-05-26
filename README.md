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
   cd soc-query-library
   ```

2. **Find a query** — browse [`INDEX.md`](INDEX.md) or search by MITRE technique, platform, or severity tag.

3. **Navigate to your SIEM platform directory**
   ```bash
   cd splunk/          # SPL queries
   cd sentinel/        # KQL queries
   cd qradar/          # AQL queries
   cd google-secops/   # YARA-L rules
   cd defender/        # KQL Advanced Hunting
   ```

4. **Import queries into your SIEM** — each file is self-contained with a header block containing the title, MITRE mapping, severity, data sources, tuning notes, and false positive guidance.

5. **For hunting** — open [`docs/Threat-Hunting-Quick-Reference.md`](docs/Threat-Hunting-Quick-Reference.md), find the query matching your investigation, swap the `<PLACEHOLDER>` values, and paste directly into your SIEM.

### Example — Run a Splunk Brute Force Detection

```spl
` Single-source brute force: >10 failures from one IP in 10 minutes`
index=windows sourcetype="WinEventLog:Security" EventCode=4625
| bin _time span=10m
| stats count as failed_attempts dc(src_ip) as unique_sources values(src_ip) as source_ips
    by Account_Name, _time
| where failed_attempts > 10 AND unique_sources <= 2
| table _time, Account_Name, failed_attempts, source_ips
```

### Example — KQL Impossible Travel (Sentinel)

```kql
// Detect logins from two countries within 1 hour for the same user
let timeframe = 1h;
SigninLogs
| where TimeGenerated > ago(1d)
| where ResultType == "0"  // Successful sign-ins only
| project TimeGenerated, UserPrincipalName, Location, IPAddress
| join kind=inner (
    SigninLogs
    | where ResultType == "0"
    | project TimeGenerated2=TimeGenerated, UserPrincipalName,
              Location2=Location, IPAddress2=IPAddress
) on UserPrincipalName
| where Location != Location2
      and abs(datetime_diff('minute', TimeGenerated, TimeGenerated2)) < 60
| project UserPrincipalName, Location, IPAddress, TimeGenerated,
          Location2, IPAddress2, TimeGenerated2
```

## 📁 Repository Structure

```
soc-query-library/
├── README.md                               # This file
├── INDEX.md                                # Master query index (searchable)
├── LICENSE
├── CONTRIBUTING.md
├── .gitignore
├── docs/
│   ├── SOC-Complete-Reference.md           # Full rule reference
│   ├── SOC-Query-Library-Simplified.md     # Simplified rule reference card
│   └── Threat-Hunting-Quick-Reference.md   # 30 copy-paste hunting queries
├── splunk/              # SPL detection queries
├── sentinel/            # KQL detection queries
├── qradar/              # AQL detection queries
├── google-secops/       # YARA-L 2.0 detection rules
├── defender/            # KQL Advanced Hunting queries
├── mitre-mapping/
│   └── attack-navigator.json               # ATT&CK Navigator layer
└── tools/
    └── validate_queries.py                 # Coverage + syntax validator
```

## 🤝 Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for full guidelines. Quick workflow:

### Adding a New Query

1. **Fork & branch**
   ```bash
   git checkout -b feat/add-<category>-<platform>
   ```

2. **Create your query file** in the correct platform directory using the naming convention: `<category-name>.<ext>`
   - Include the standard header block (Title, Description, MITRE ATT&CK, Severity, Data Sources, Author, Date)

3. **Add to all 5 platforms** — cross-platform parity is required. If you add a new category, it must exist in `splunk/`, `sentinel/`, `qradar/`, `google-secops/`, and `defender/`.

4. **Update INDEX.md** — add your new category entry to [`INDEX.md`](INDEX.md) following the existing format.

5. **Validate locally**
   ```bash
   python3 tools/validate_queries.py --verbose
   ```
   All checks must pass (0 errors) before submitting.

6. **Open a pull request** — include:
   - What threat the query detects
   - MITRE ATT&CK technique(s) covered
   - Platforms it's been tested on
   - Known false positive scenarios

### Query Header Template

```
// ============================================================
// Title:        <Detection Name>
// Description:  <What it detects and why it matters>
// MITRE ATT&CK: <T1XXX.XXX> (<Technique Name>)
// Severity:     Critical | High | Medium | Low
// Data Sources: <Log sources required>
// Author:       Christian M. Njodzela
// Date:         YYYY-MM-DD
// ============================================================
```

### Validate Before You Push

```bash
# Check coverage and syntax
python3 tools/validate_queries.py

# Verbose output (shows every file check)
python3 tools/validate_queries.py --verbose

# Generate a gap report if files are missing
python3 tools/validate_queries.py --fix-report
```

## 📄 License

This project is licensed under the MIT License — see [LICENSE](LICENSE).

---

> *"Detection is not a product, it's a process."* — SOC Query Library

© 2026 Christian M. Njodzela
