# Splunk SPL Detection Queries

This directory contains 10 production-ready SPL queries for Splunk Enterprise / Splunk Cloud.

## Prerequisites
- Splunk Enterprise 8.x+ or Splunk Cloud
- Common Information Model (CIM) add-on recommended
- Data sources: Windows Event Logs, Sysmon, firewall, proxy, EDR

## Files

| File | Category | MITRE Tactic |
|------|----------|-------------|
| `brute-force-detection.spl` | Brute Force | Credential Access |
| `lateral-movement.spl` | Lateral Movement | Lateral Movement |
| `data-exfiltration.spl` | Data Exfiltration | Exfiltration |
| `phishing-indicators.spl` | Phishing | Initial Access |
| `privilege-escalation.spl` | Privilege Escalation | Privilege Escalation |
| `persistence-mechanisms.spl` | Persistence | Persistence |
| `command-and-control.spl` | C2 Communication | Command and Control |
| `credential-access.spl` | Credential Theft | Credential Access |
| `defense-evasion.spl` | Defense Evasion | Defense Evasion |
| `reconnaissance.spl` | Reconnaissance | Reconnaissance |

## Usage

Import queries into Splunk as saved searches or add to detection rules in Splunk ES.
