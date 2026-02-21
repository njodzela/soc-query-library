# Microsoft Sentinel KQL Detection Queries

This directory contains 10 production-ready KQL queries for Microsoft Sentinel.

## Prerequisites
- Microsoft Sentinel workspace with relevant data connectors
- Key tables: SecurityEvent, SigninLogs, AzureActivity, CommonSecurityLog, Syslog, DeviceEvents

## Files

| File | Category | MITRE Tactic |
|------|----------|-------------|
| `brute-force-detection.kql` | Brute Force | Credential Access |
| `lateral-movement.kql` | Lateral Movement | Lateral Movement |
| `data-exfiltration.kql` | Data Exfiltration | Exfiltration |
| `phishing-indicators.kql` | Phishing | Initial Access |
| `privilege-escalation.kql` | Privilege Escalation | Privilege Escalation |
| `persistence-mechanisms.kql` | Persistence | Persistence |
| `command-and-control.kql` | C2 Communication | Command and Control |
| `credential-access.kql` | Credential Theft | Credential Access |
| `defense-evasion.kql` | Defense Evasion | Defense Evasion |
| `reconnaissance.kql` | Reconnaissance | Reconnaissance |

## Usage

Create Analytics Rules in Sentinel or run in Log Analytics workspace.
