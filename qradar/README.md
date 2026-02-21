# IBM QRadar AQL Detection Queries

This directory contains 10 production-ready AQL queries for IBM QRadar SIEM.

## Prerequisites
- IBM QRadar 7.5+ with relevant log sources
- Key data: Windows Event Logs, firewall, proxy, DNS, flow data

## Files

| File | Category | MITRE Tactic |
|------|----------|-------------|
| `brute-force-detection.aql` | Brute Force | Credential Access |
| `lateral-movement.aql` | Lateral Movement | Lateral Movement |
| `data-exfiltration.aql` | Data Exfiltration | Exfiltration |
| `phishing-indicators.aql` | Phishing | Initial Access |
| `privilege-escalation.aql` | Privilege Escalation | Privilege Escalation |
| `persistence-mechanisms.aql` | Persistence | Persistence |
| `command-and-control.aql` | C2 Communication | Command and Control |
| `credential-access.aql` | Credential Theft | Credential Access |
| `defense-evasion.aql` | Defense Evasion | Defense Evasion |
| `reconnaissance.aql` | Reconnaissance | Reconnaissance |

## Usage

Run queries in the QRadar Advanced Search or use as building blocks for custom rules.
