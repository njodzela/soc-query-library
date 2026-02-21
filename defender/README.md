# Microsoft Defender — Advanced Hunting Queries (KQL)

## Overview

This directory contains 16 Advanced Hunting queries written in **KQL** for Microsoft 365 Defender. Each query maps to a MITRE ATT&CK tactic and includes multiple detection scenarios, tuning guidance, and false positive documentation.

## Platform Setup

### Prerequisites
- Microsoft 365 Defender portal access (`security.microsoft.com`)
- Appropriate RBAC role: **Security Reader** (read-only) or **Security Operator** (to create custom detections)
- Relevant data sources onboarded to Microsoft Defender

### Using Queries

1. **Advanced Hunting (ad-hoc):**
   - Navigate to **Hunting → Advanced Hunting** in the M365 Defender portal
   - Paste the query and click **Run query**
   - Adjust the time range as needed (default: last 30 days)

2. **Custom Detection Rules (scheduled):**
   - Run the query in Advanced Hunting
   - Click **Create detection rule**
   - Configure frequency (every 1h, 3h, 12h, or 24h)
   - Set alert severity and automated response actions
   - Map to MITRE ATT&CK technique

3. **API (programmatic):**
   ```python
   import requests
   url = "https://api.security.microsoft.com/api/advancedhunting/run"
   headers = {"Authorization": f"Bearer {token}"}
   body = {"Query": open("brute-force-detection.kql").read()}
   response = requests.post(url, headers=headers, json=body)
   ```

### Available Tables

| Table | Description |
|-------|-------------|
| `DeviceProcessEvents` | Process creation and related events |
| `DeviceNetworkEvents` | Network connections and related events |
| `DeviceFileEvents` | File creation, modification, deletion |
| `DeviceRegistryEvents` | Registry modifications |
| `DeviceLogonEvents` | Logon events on devices |
| `EmailEvents` | Email delivery and related events |
| `EmailUrlInfo` | URL info from emails |
| `EmailAttachmentInfo` | Attachment info from emails |
| `IdentityLogonEvents` | Azure AD and on-prem AD logon events |
| `IdentityDirectoryEvents` | AD directory changes (group mods, etc.) |
| `CloudAppEvents` | Cloud application activity |
| `AlertEvidence` | Evidence from triggered alerts |

## File Listing

| File | MITRE Tactic | Severity |
|------|-------------|----------|
| `brute-force-detection.kql` | Credential Access (T1110) | High |
| `lateral-movement.kql` | Lateral Movement (T1021) | High |
| `data-exfiltration.kql` | Exfiltration (T1048) | Critical |
| `phishing-indicators.kql` | Initial Access (T1566) | High |
| `privilege-escalation.kql` | Privilege Escalation (T1068) | Critical |
| `persistence-mechanisms.kql` | Persistence (T1053) | High |
| `command-and-control.kql` | Command and Control (T1071) | High |
| `credential-access.kql` | Credential Access (T1003) | Critical |
| `defense-evasion.kql` | Defense Evasion (T1070) | High |
| `reconnaissance.kql` | Reconnaissance (T1595) | Medium |
| `forwarding-rule-abuse.kql` | Collection (T1114) | High |
| `impossible-travel.kql` | Initial Access (T1078) | High |
| `spam-bot-detection.kql` | Initial Access (T1078) | High |
| `email-spoofing.kql` | Initial Access (T1566) | High |
| `anomalous-process-execution.kql` | Execution (T1059) | High |
| `routine-threat-hunting.kql` | Persistence (T1053) | Medium |

## Author

**Christian M. Njodzela** — 2026-02-21
