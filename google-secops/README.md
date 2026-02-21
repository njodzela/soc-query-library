# Google SecOps (Chronicle) — YARA-L 2.0 Detection Rules

## Overview

This directory contains 10 detection rules written in **YARA-L 2.0** for Google SecOps (formerly Chronicle). Each rule maps to a MITRE ATT&CK tactic and includes multiple detection scenarios, tuning guidance, and false positive documentation.

## Platform Setup

### Prerequisites
- Active Google SecOps (Chronicle) instance
- Appropriate IAM permissions: `chronicle.rules.create`, `chronicle.rules.update`
- Log sources ingesting into Chronicle via forwarders or direct API

### Importing Rules

1. **Via Chronicle UI:**
   - Navigate to **Detection → Rules Editor**
   - Click **New Rule**
   - Paste the `.yaral` file contents
   - Click **Save** then **Enable Live Rule** or **Enable Test Rule**

2. **Via Chronicle API:**
   ```bash
   curl -X POST \
     "https://<instance>.backstory.chronicle.security/v2/detect/rules" \
     -H "Authorization: Bearer $(gcloud auth print-access-token)" \
     -H "Content-Type: application/json" \
     -d @rule.json
   ```

3. **Via Terraform (recommended for CI/CD):**
   ```hcl
   resource "google_chronicle_rule" "brute_force" {
     rule_text = file("brute-force-detection.yaral")
     enabled   = true
   }
   ```

### Data Source Requirements

| Rule | Required Log Sources |
|------|---------------------|
| Brute-Force Detection | UDM Authentication Events (OKTA, Azure AD, etc.) |
| Lateral Movement | UDM Network + Process Events (EDR, Windows Event Logs) |
| Data Exfiltration | UDM Network Events, DLP Logs, Cloud Storage Audit |
| Phishing Indicators | UDM Email Events, URL Reputation Feeds |
| Privilege Escalation | UDM Process Events, Windows Security Logs |
| Persistence Mechanisms | UDM Registry, Process, Scheduled Task Events |
| Command and Control | UDM Network Events, DNS Logs, Proxy Logs |
| Credential Access | UDM Process Events, Windows Security Logs |
| Defense Evasion | UDM Process Events, Sysmon, AV Logs |
| Reconnaissance | UDM Network Events, DNS Logs, Firewall Logs |

### Rule Severity Levels
- **Critical** — Immediate analyst review required
- **High** — Review within 1 hour
- **Medium** — Review within 4 hours
- **Low/Informational** — Review during next shift

## File Listing

| File | MITRE Tactic | Severity |
|------|-------------|----------|
| `brute-force-detection.yaral` | Credential Access (T1110) | High |
| `lateral-movement.yaral` | Lateral Movement (T1021) | High |
| `data-exfiltration.yaral` | Exfiltration (T1048) | Critical |
| `phishing-indicators.yaral` | Initial Access (T1566) | High |
| `privilege-escalation.yaral` | Privilege Escalation (T1068) | Critical |
| `persistence-mechanisms.yaral` | Persistence (T1053) | High |
| `command-and-control.yaral` | Command and Control (T1071) | High |
| `credential-access.yaral` | Credential Access (T1003) | Critical |
| `defense-evasion.yaral` | Defense Evasion (T1070) | High |
| `reconnaissance.yaral` | Reconnaissance (T1595) | Medium |

## Author

**Christian M. Njodzela** — 2026-02-21
