# 📇 SOC Query Library — Master Index

> **80 query files · 16 threat categories · 5 SIEM platforms · 40+ MITRE ATT&CK techniques**
>
> Use `Ctrl+F` / `Cmd+F` to search by category, technique ID, tactic, severity, or platform.

---

## 🔍 Quick Search Tags

`#InitialAccess` `#Persistence` `#PrivilegeEscalation` `#DefenseEvasion` `#CredentialAccess`
`#LateralMovement` `#Collection` `#Exfiltration` `#CommandAndControl` `#Reconnaissance`
`#Splunk` `#Sentinel` `#QRadar` `#GoogleSecOps` `#Defender`
`#High` `#Medium` `#Critical` `#KQL` `#SPL` `#AQL` `#YARAL`

---

## 📋 All Queries by Category

### 1. 🔐 Brute-Force Detection
| Field | Value |
|-------|-------|
| **MITRE Tactic** | Credential Access |
| **Techniques** | T1110.001 · T1110.003 · T1110.004 |
| **Severity** | High |
| **Tags** | `#CredentialAccess` `#BruteForce` `#PasswordSpray` |

| Platform | File | Language |
|----------|------|----------|
| Splunk | [splunk/brute-force-detection.spl](splunk/brute-force-detection.spl) | SPL |
| Microsoft Sentinel | [sentinel/brute-force-detection.kql](sentinel/brute-force-detection.kql) | KQL |
| IBM QRadar | [qradar/brute-force-detection.aql](qradar/brute-force-detection.aql) | AQL |
| Google SecOps | [google-secops/brute-force-detection.yaral](google-secops/brute-force-detection.yaral) | YARA-L |
| Microsoft Defender | [defender/brute-force-detection.kql](defender/brute-force-detection.kql) | KQL |

---

### 2. 🌐 Command and Control (C2)
| Field | Value |
|-------|-------|
| **MITRE Tactic** | Command and Control |
| **Techniques** | T1071.001 · T1071.004 · T1573 · T1105 |
| **Severity** | Critical |
| **Tags** | `#CommandAndControl` `#C2` `#Beaconing` |

| Platform | File | Language |
|----------|------|----------|
| Splunk | [splunk/command-and-control.spl](splunk/command-and-control.spl) | SPL |
| Microsoft Sentinel | [sentinel/command-and-control.kql](sentinel/command-and-control.kql) | KQL |
| IBM QRadar | [qradar/command-and-control.aql](qradar/command-and-control.aql) | AQL |
| Google SecOps | [google-secops/command-and-control.yaral](google-secops/command-and-control.yaral) | YARA-L |
| Microsoft Defender | [defender/command-and-control.kql](defender/command-and-control.kql) | KQL |

---

### 3. 🔑 Credential Access
| Field | Value |
|-------|-------|
| **MITRE Tactic** | Credential Access |
| **Techniques** | T1003.001 · T1558.003 · T1555 · T1552 |
| **Severity** | Critical |
| **Tags** | `#CredentialAccess` `#CredentialDumping` `#Kerberoasting` |

| Platform | File | Language |
|----------|------|----------|
| Splunk | [splunk/credential-access.spl](splunk/credential-access.spl) | SPL |
| Microsoft Sentinel | [sentinel/credential-access.kql](sentinel/credential-access.kql) | KQL |
| IBM QRadar | [qradar/credential-access.aql](qradar/credential-access.aql) | AQL |
| Google SecOps | [google-secops/credential-access.yaral](google-secops/credential-access.yaral) | YARA-L |
| Microsoft Defender | [defender/credential-access.kql](defender/credential-access.kql) | KQL |

---

### 4. 📤 Data Exfiltration
| Field | Value |
|-------|-------|
| **MITRE Tactic** | Exfiltration |
| **Techniques** | T1048.001 · T1048.002 · T1567 · T1041 |
| **Severity** | High |
| **Tags** | `#Exfiltration` `#DataTheft` `#DNSTunnel` |

| Platform | File | Language |
|----------|------|----------|
| Splunk | [splunk/data-exfiltration.spl](splunk/data-exfiltration.spl) | SPL |
| Microsoft Sentinel | [sentinel/data-exfiltration.kql](sentinel/data-exfiltration.kql) | KQL |
| IBM QRadar | [qradar/data-exfiltration.aql](qradar/data-exfiltration.aql) | AQL |
| Google SecOps | [google-secops/data-exfiltration.yaral](google-secops/data-exfiltration.yaral) | YARA-L |
| Microsoft Defender | [defender/data-exfiltration.kql](defender/data-exfiltration.kql) | KQL |

---

### 5. 🛡️ Defense Evasion
| Field | Value |
|-------|-------|
| **MITRE Tactic** | Defense Evasion |
| **Techniques** | T1070.001 · T1562.001 · T1036.005 · T1027 |
| **Severity** | High |
| **Tags** | `#DefenseEvasion` `#LogTampering` `#Obfuscation` |

| Platform | File | Language |
|----------|------|----------|
| Splunk | [splunk/defense-evasion.spl](splunk/defense-evasion.spl) | SPL |
| Microsoft Sentinel | [sentinel/defense-evasion.kql](sentinel/defense-evasion.kql) | KQL |
| IBM QRadar | [qradar/defense-evasion.aql](qradar/defense-evasion.aql) | AQL |
| Google SecOps | [google-secops/defense-evasion.yaral](google-secops/defense-evasion.yaral) | YARA-L |
| Microsoft Defender | [defender/defense-evasion.kql](defender/defense-evasion.kql) | KQL |

---

### 6. 📧 Email Spoofing ★
| Field | Value |
|-------|-------|
| **MITRE Tactic** | Initial Access |
| **Techniques** | T1566.001 · T1566.002 · T1534 |
| **Severity** | High |
| **Tags** | `#InitialAccess` `#EmailSpoofing` `#Phishing` `#DMARC` |

| Platform | File | Language |
|----------|------|----------|
| Splunk | [splunk/email-spoofing.spl](splunk/email-spoofing.spl) | SPL |
| Microsoft Sentinel | [sentinel/email-spoofing.kql](sentinel/email-spoofing.kql) | KQL |
| IBM QRadar | [qradar/email-spoofing.aql](qradar/email-spoofing.aql) | AQL |
| Google SecOps | [google-secops/email-spoofing.yaral](google-secops/email-spoofing.yaral) | YARA-L |
| Microsoft Defender | [defender/email-spoofing.kql](defender/email-spoofing.kql) | KQL |

---

### 7. 📨 Forwarding Rule Abuse ★
| Field | Value |
|-------|-------|
| **MITRE Tactic** | Collection |
| **Techniques** | T1114.003 |
| **Severity** | High |
| **Tags** | `#Collection` `#EmailForwarding` `#BEC` `#InboxRule` |

| Platform | File | Language |
|----------|------|----------|
| Splunk | [splunk/forwarding-rule-abuse.spl](splunk/forwarding-rule-abuse.spl) | SPL |
| Microsoft Sentinel | [sentinel/forwarding-rule-abuse.kql](sentinel/forwarding-rule-abuse.kql) | KQL |
| IBM QRadar | [qradar/forwarding-rule-abuse.aql](qradar/forwarding-rule-abuse.aql) | AQL |
| Google SecOps | [google-secops/forwarding-rule-abuse.yaral](google-secops/forwarding-rule-abuse.yaral) | YARA-L |
| Microsoft Defender | [defender/forwarding-rule-abuse.kql](defender/forwarding-rule-abuse.kql) | KQL |

---

### 8. 🌍 Impossible Travel ★
| Field | Value |
|-------|-------|
| **MITRE Tactic** | Identity (Cross-Tactic) |
| **Techniques** | T1078 · T1078.004 |
| **Severity** | High |
| **Tags** | `#Identity` `#ImpossibleTravel` `#AccountCompromise` `#CloudSecurity` |

| Platform | File | Language |
|----------|------|----------|
| Splunk | [splunk/impossible-travel.spl](splunk/impossible-travel.spl) | SPL |
| Microsoft Sentinel | [sentinel/impossible-travel.kql](sentinel/impossible-travel.kql) | KQL |
| IBM QRadar | [qradar/impossible-travel.aql](qradar/impossible-travel.aql) | AQL |
| Google SecOps | [google-secops/impossible-travel.yaral](google-secops/impossible-travel.yaral) | YARA-L |
| Microsoft Defender | [defender/impossible-travel.kql](defender/impossible-travel.kql) | KQL |

---

### 9. 🔄 Lateral Movement
| Field | Value |
|-------|-------|
| **MITRE Tactic** | Lateral Movement |
| **Techniques** | T1021.001 · T1021.002 · T1021.006 · T1570 |
| **Severity** | High |
| **Tags** | `#LateralMovement` `#RDP` `#SMB` `#PsExec` `#WinRM` |

| Platform | File | Language |
|----------|------|----------|
| Splunk | [splunk/lateral-movement.spl](splunk/lateral-movement.spl) | SPL |
| Microsoft Sentinel | [sentinel/lateral-movement.kql](sentinel/lateral-movement.kql) | KQL |
| IBM QRadar | [qradar/lateral-movement.aql](qradar/lateral-movement.aql) | AQL |
| Google SecOps | [google-secops/lateral-movement.yaral](google-secops/lateral-movement.yaral) | YARA-L |
| Microsoft Defender | [defender/lateral-movement.kql](defender/lateral-movement.kql) | KQL |

---

### 10. 🔒 Persistence Mechanisms
| Field | Value |
|-------|-------|
| **MITRE Tactic** | Persistence |
| **Techniques** | T1053.005 · T1547.001 · T1543.003 · T1574.002 |
| **Severity** | High |
| **Tags** | `#Persistence` `#ScheduledTask` `#RegistryRun` `#Service` |

| Platform | File | Language |
|----------|------|----------|
| Splunk | [splunk/persistence-mechanisms.spl](splunk/persistence-mechanisms.spl) | SPL |
| Microsoft Sentinel | [sentinel/persistence-mechanisms.kql](sentinel/persistence-mechanisms.kql) | KQL |
| IBM QRadar | [qradar/persistence-mechanisms.aql](qradar/persistence-mechanisms.aql) | AQL |
| Google SecOps | [google-secops/persistence-mechanisms.yaral](google-secops/persistence-mechanisms.yaral) | YARA-L |
| Microsoft Defender | [defender/persistence-mechanisms.kql](defender/persistence-mechanisms.kql) | KQL |

---

### 11. 🎣 Phishing Indicators
| Field | Value |
|-------|-------|
| **MITRE Tactic** | Initial Access |
| **Techniques** | T1566.001 · T1566.002 · T1598 |
| **Severity** | High |
| **Tags** | `#InitialAccess` `#Phishing` `#Spearphishing` `#MaliciousAttachment` |

| Platform | File | Language |
|----------|------|----------|
| Splunk | [splunk/phishing-indicators.spl](splunk/phishing-indicators.spl) | SPL |
| Microsoft Sentinel | [sentinel/phishing-indicators.kql](sentinel/phishing-indicators.kql) | KQL |
| IBM QRadar | [qradar/phishing-indicators.aql](qradar/phishing-indicators.aql) | AQL |
| Google SecOps | [google-secops/phishing-indicators.yaral](google-secops/phishing-indicators.yaral) | YARA-L |
| Microsoft Defender | [defender/phishing-indicators.kql](defender/phishing-indicators.kql) | KQL |

---

### 12. ⬆️ Privilege Escalation
| Field | Value |
|-------|-------|
| **MITRE Tactic** | Privilege Escalation |
| **Techniques** | T1068 · T1548.002 · T1134 · T1078.002 |
| **Severity** | Critical |
| **Tags** | `#PrivilegeEscalation` `#UAC` `#TokenManipulation` `#LocalAdmin` |

| Platform | File | Language |
|----------|------|----------|
| Splunk | [splunk/privilege-escalation.spl](splunk/privilege-escalation.spl) | SPL |
| Microsoft Sentinel | [sentinel/privilege-escalation.kql](sentinel/privilege-escalation.kql) | KQL |
| IBM QRadar | [qradar/privilege-escalation.aql](qradar/privilege-escalation.aql) | AQL |
| Google SecOps | [google-secops/privilege-escalation.yaral](google-secops/privilege-escalation.yaral) | YARA-L |
| Microsoft Defender | [defender/privilege-escalation.kql](defender/privilege-escalation.kql) | KQL |

---

### 13. 🔭 Reconnaissance
| Field | Value |
|-------|-------|
| **MITRE Tactic** | Reconnaissance |
| **Techniques** | T1595 · T1590 · T1589 |
| **Severity** | Medium |
| **Tags** | `#Reconnaissance` `#PortScan` `#NetworkScan` `#Discovery` |

| Platform | File | Language |
|----------|------|----------|
| Splunk | [splunk/reconnaissance.spl](splunk/reconnaissance.spl) | SPL |
| Microsoft Sentinel | [sentinel/reconnaissance.kql](sentinel/reconnaissance.kql) | KQL |
| IBM QRadar | [qradar/reconnaissance.aql](qradar/reconnaissance.aql) | AQL |
| Google SecOps | [google-secops/reconnaissance.yaral](google-secops/reconnaissance.yaral) | YARA-L |
| Microsoft Defender | [defender/reconnaissance.kql](defender/reconnaissance.kql) | KQL |

---

### 14. 🕵️ Routine Threat Hunting ★
| Field | Value |
|-------|-------|
| **MITRE Tactic** | Proactive (Cross-Tactic) |
| **Techniques** | T1053 · T1547 · T1105 · T1543 · T1574 |
| **Severity** | Medium |
| **Tags** | `#ThreatHunting` `#Proactive` `#HuntingQueries` |

| Platform | File | Language |
|----------|------|----------|
| Splunk | [splunk/routine-threat-hunting.spl](splunk/routine-threat-hunting.spl) | SPL |
| Microsoft Sentinel | [sentinel/routine-threat-hunting.kql](sentinel/routine-threat-hunting.kql) | KQL |
| IBM QRadar | [qradar/routine-threat-hunting.aql](qradar/routine-threat-hunting.aql) | AQL |
| Google SecOps | [google-secops/routine-threat-hunting.yaral](google-secops/routine-threat-hunting.yaral) | YARA-L |
| Microsoft Defender | [defender/routine-threat-hunting.kql](defender/routine-threat-hunting.kql) | KQL |

---

### 15. 🤖 Spam Bot Detection ★
| Field | Value |
|-------|-------|
| **MITRE Tactic** | Initial Access |
| **Techniques** | T1566 · T1071 · T1078 |
| **Severity** | Medium |
| **Tags** | `#InitialAccess` `#SpamBot` `#BulkEmail` `#RateLimiting` |

| Platform | File | Language |
|----------|------|----------|
| Splunk | [splunk/spam-bot-detection.spl](splunk/spam-bot-detection.spl) | SPL |
| Microsoft Sentinel | [sentinel/spam-bot-detection.kql](sentinel/spam-bot-detection.kql) | KQL |
| IBM QRadar | [qradar/spam-bot-detection.aql](qradar/spam-bot-detection.aql) | AQL |
| Google SecOps | [google-secops/spam-bot-detection.yaral](google-secops/spam-bot-detection.yaral) | YARA-L |
| Microsoft Defender | [defender/spam-bot-detection.kql](defender/spam-bot-detection.kql) | KQL |

---

### 16. ⚙️ Anomalous Process Execution ★
| Field | Value |
|-------|-------|
| **MITRE Tactic** | Execution / Defense Evasion |
| **Techniques** | T1059 · T1036 · T1218 · T1204 |
| **Severity** | High |
| **Tags** | `#Execution` `#DefenseEvasion` `#LOLBins` `#ProcessAnomaly` |

| Platform | File | Language |
|----------|------|----------|
| Splunk | [splunk/anomalous-process-execution.spl](splunk/anomalous-process-execution.spl) | SPL |
| Microsoft Sentinel | [sentinel/anomalous-process-execution.kql](sentinel/anomalous-process-execution.kql) | KQL |
| IBM QRadar | [qradar/anomalous-process-execution.aql](qradar/anomalous-process-execution.aql) | AQL |
| Google SecOps | [google-secops/anomalous-process-execution.yaral](google-secops/anomalous-process-execution.yaral) | YARA-L |
| Microsoft Defender | [defender/anomalous-process-execution.kql](defender/anomalous-process-execution.kql) | KQL |

---

## 📊 Summary Matrix

| Category | Splunk | Sentinel | QRadar | Google SecOps | Defender | Severity |
|----------|:------:|:--------:|:------:|:-------------:|:--------:|----------|
| Brute-Force Detection | ✅ | ✅ | ✅ | ✅ | ✅ | High |
| Command & Control | ✅ | ✅ | ✅ | ✅ | ✅ | Critical |
| Credential Access | ✅ | ✅ | ✅ | ✅ | ✅ | Critical |
| Data Exfiltration | ✅ | ✅ | ✅ | ✅ | ✅ | High |
| Defense Evasion | ✅ | ✅ | ✅ | ✅ | ✅ | High |
| Email Spoofing | ✅ | ✅ | ✅ | ✅ | ✅ | High |
| Forwarding Rule Abuse | ✅ | ✅ | ✅ | ✅ | ✅ | High |
| Impossible Travel | ✅ | ✅ | ✅ | ✅ | ✅ | High |
| Lateral Movement | ✅ | ✅ | ✅ | ✅ | ✅ | High |
| Persistence Mechanisms | ✅ | ✅ | ✅ | ✅ | ✅ | High |
| Phishing Indicators | ✅ | ✅ | ✅ | ✅ | ✅ | High |
| Privilege Escalation | ✅ | ✅ | ✅ | ✅ | ✅ | Critical |
| Reconnaissance | ✅ | ✅ | ✅ | ✅ | ✅ | Medium |
| Routine Threat Hunting | ✅ | ✅ | ✅ | ✅ | ✅ | Medium |
| Spam Bot Detection | ✅ | ✅ | ✅ | ✅ | ✅ | Medium |
| Anomalous Process Execution | ✅ | ✅ | ✅ | ✅ | ✅ | High |

**80 / 80 files present · 100% coverage across all platforms**

> ★ = 2026 edition additions | Last validated: 2026-05-26

---

*See [README.md](README.md) for full documentation · [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidelines · [tools/validate_queries.py](tools/validate_queries.py) to validate locally*
