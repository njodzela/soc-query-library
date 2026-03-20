# SOC Detection & Threat Hunting — Complete Reference

**Google SecOps (Chronicle SIEM) · YARA-L 2.0**

| | |
|---|---|
| **Total Detection Rules** | 48 |
| **Threat Hunting Queries** | 30 |
| **Detection Categories** | 16 |
| **MITRE ATT&CK Techniques** | 40+ |
| **Platform** | Google SecOps (Chronicle) |
| **Also Available** | Splunk (SPL), Sentinel (KQL), QRadar (AQL), Defender (KQL) |
| **Author** | Christian M. Njodzela |
| **Edition** | 2026 |

---

## Executive Summary

This document is the single, comprehensive reference for the SOC Detection Query Library — combining 48 production-ready detection rules with 30 operational threat hunting queries. It covers the full MITRE ATT&CK kill chain from initial access through exfiltration.

**Key capabilities:**
- Real-time detection of phishing, credential theft, lateral movement, and data exfiltration
- Email security: forwarding rule abuse, spoofing (SPF/DKIM/DMARC), spam bot identification
- Identity protection: impossible travel, brute force, privilege escalation monitoring
- Endpoint security: anomalous process execution, LOLBin abuse, masquerading detection
- Proactive threat hunting: scheduled queries for rare processes, new services, unsigned binaries
- Full MITRE ATT&CK mapping across 40+ techniques with severity-based risk scoring

---

## Severity Legend

| Severity | Risk Score | Action |
|----------|------------|--------|
| 🔴 CRITICAL | 90–95 | Isolate host NOW. Page on-call. Open P1 incident. |
| 🟠 HIGH | 70–90 | Disable account. Notify SOC lead within 30 min. Preserve logs. |
| 🟡 MEDIUM | 55–70 | Investigate within 2 hours. Correlate with other queries. Escalate if confirmed. |
| 🟢 LOW | 35–55 | Document and verify with asset owner. Add to watch list if unexplained. |

> ⚡ = REQUIRES CUSTOMIZATION BEFORE DEPLOYMENT

---

# PART 1 — DETECTION RULES (48 Rules)

Each rule card includes: what it detects, the YARA-L match/condition logic, risk score, and tuning guidance.

---

## Section 01 · Brute-Force Detection

**MITRE ATT&CK:** T1110.001 / T1110.003 / T1110.004

### `brute_force_single_source` — 🟠 HIGH — T1110.001

**Detects:** Excessive failed logins from one IP within 10 min.

```yaral
rule brute_force_single_source {
  meta:
    author = "Christian M. Njodzela"
    description = "Detects excessive failed login attempts from a single IP address within a short window."
    severity = "High"
    mitre_attack = "T1110.001"
  events:
    $fail.metadata.event_type = "USER_LOGIN"
    $fail.security_result.action = "BLOCK"
    $fail.security_result.category = "AUTH_VIOLATION"
    $fail.principal.ip = $source_ip
    $fail.target.user.userid = $target_user
  match:
    $source_ip over 10m
  condition:
    #fail > 15
  outcome:
    $risk_score = 75
    $event_count = #fail
    $target_users = array_distinct($fail.target.user.userid)
}
```

| Key | Value |
|-----|-------|
| **Trigger** | `#fail > 15` in 10 min from single IP |
| **Risk Score** | 75 |
| **⚠ Tune** | Exclude VPN egress IPs, load balancers, cloud IdPs |

### `password_spraying_detection` — 🟠 HIGH — T1110.003

**Detects:** Failed logins to many distinct accounts from one source (30 min window).

```yaral
rule password_spraying_detection {
  meta:
    author = "Christian M. Njodzela"
    severity = "High"
    mitre_attack = "T1110.003"
  events:
    $fail.metadata.event_type = "USER_LOGIN"
    $fail.security_result.action = "BLOCK"
    $fail.principal.ip = $source_ip
    $fail.target.user.userid = $target_user
  match:
    $source_ip over 30m
  condition:
    #fail > 10 and count_distinct($fail.target.user.userid) > 8
  outcome:
    $risk_score = 85
    $unique_targets = count_distinct($fail.target.user.userid)
    $event_count = #fail
}
```

| Key | Value |
|-----|-------|
| **Trigger** | `>10 fails AND >8 unique users` in 30 min |
| **Risk Score** | 85 |
| **⚠ Tune** | FP: expired service accounts, federated auth flows |

### `credential_stuffing_success` — 🔴 CRITICAL — T1110.004

**Detects:** Successful login preceded by 10+ failures from same IP — classic stuffing pattern.

```yaral
rule credential_stuffing_success {
  meta:
    author = "Christian M. Njodzela"
    severity = "Critical"
    mitre_attack = "T1110.004"
  events:
    $fail.metadata.event_type = "USER_LOGIN"
    $fail.security_result.action = "BLOCK"
    $fail.principal.ip = $source_ip
    $success.metadata.event_type = "USER_LOGIN"
    $success.security_result.action = "ALLOW"
    $success.principal.ip = $source_ip
    $fail.metadata.event_timestamp.seconds < $success.metadata.event_timestamp.seconds
  match:
    $source_ip over 30m
  condition:
    #fail > 10 and #success > 0
  outcome:
    $risk_score = 90
    $failed_count = #fail
    $successful_users = array_distinct($success.target.user.userid)
}
```

| Key | Value |
|-----|-------|
| **Trigger** | `>10 fails then ≥1 success` from same IP in 30 min |
| **Risk Score** | 90 |
| **⚠ Tune** | FP: password reset flows, expired service account creds |

#### 🔍 Hunting Query — Failed Logins Single User

```yaral
event_type = "USER_LOGIN"
AND security_result.action = "BLOCK"
AND target.user.userid = "REPLACE_USERNAME"
AND timestamp > now() - 30m
| stats count() as fail_count by principal.ip
| where fail_count > 5
| sort fail_count desc
```

> **Swap:** `REPLACE_USERNAME` · **Look for:** Same IP with many failures → then a success within seconds = red flag

---

## Section 02 · Command & Control Detection

**MITRE ATT&CK:** T1071.001 / T1071.004 / T1573 / T1105

### `c2_http_beaconing` — 🟠 HIGH — T1071.001

**Detects:** Regular-interval HTTP/S connections from internal IP to single external domain — C2 beacon pattern.

```yaral
rule c2_http_beaconing {
  meta:
    author = "Christian M. Njodzela"
    severity = "High"
    mitre_attack = "T1071.001"
  events:
    $beacon.metadata.event_type = "NETWORK_HTTP"
    $beacon.principal.ip = $src_ip
    $beacon.target.hostname = $domain
    ($beacon.target.port = 80 or $beacon.target.port = 443)
    net.ip_in_range_cidr($beacon.principal.ip, "10.0.0.0/8") or
    net.ip_in_range_cidr($beacon.principal.ip, "172.16.0.0/12") or
    net.ip_in_range_cidr($beacon.principal.ip, "192.168.0.0/16")
  match:
    $src_ip, $domain over 1h
  condition:
    #beacon > 60
  outcome:
    $risk_score = 75
    $connection_count = #beacon
    $target_domain = array_distinct($beacon.target.hostname)
}
```

| Key | Value |
|-----|-------|
| **Trigger** | `>60 connections` to same domain in 1h from internal host |
| **Risk Score** | 75 |
| **⚠ Tune** | Add JA3/JA3S fingerprinting. Tune for CDN traffic. |

### `c2_dns_channel` — 🟠 HIGH — T1071.004

**Detects:** DNS C2 via excessive TXT queries to a single parent domain.

| Key | Value |
|-----|-------|
| **Trigger** | `>50 TXT DNS queries` in 30 min from single IP |
| **Risk Score** | 80 |
| **⚠ Tune** | FP: CDN resolution generating many TXT queries |

### `c2_encrypted_nonstandard_port` — 🟠 HIGH — T1573

**Detects:** TLS traffic on non-standard ports (not 443/8443/993/995/636) to external IPs.

| Key | Value |
|-----|-------|
| **Trigger** | `>5 TLS connections` on non-standard ports in 1h |
| **Risk Score** | 80 |
| **⚠ Tune** | Build TLS non-standard port allow-list for VPN/apps |

#### 🔍 Hunting Queries — Network & C2

**High-Frequency Outbound (beaconing check):**
```yaral
event_type = "NETWORK_HTTP"
AND principal.ip = "REPLACE_SRC_IP"
AND NOT net.ip_in_range_cidr(target.ip, "10.0.0.0/8")
AND timestamp > now() - 1h
| stats count() as hits by target.hostname
| where hits > 30
| sort hits desc
```

**Rare Outbound Destinations (environment-wide):**
```yaral
event_type = "NETWORK_CONNECTION"
AND net.ip_in_range_cidr(principal.ip, "10.0.0.0/8")
AND NOT net.ip_in_range_cidr(target.ip, "10.0.0.0/8")
AND timestamp > now() - 24h
| stats count_distinct(principal.ip) as src_count by target.ip
| where src_count < 3
| sort src_count asc
```

**TLS on Non-Standard Ports:**
```yaral
event_type = "NETWORK_CONNECTION"
AND network.application_protocol = "TLS"
AND target.port != 443 AND target.port != 8443
AND NOT net.ip_in_range_cidr(target.ip, "10.0.0.0/8")
AND timestamp > now() - 24h
| stats count() as conn_count, array_distinct(target.port) as ports
    by principal.ip, target.ip
| sort conn_count desc
```

> **Look for:** Same domain at regular intervals with small payloads = beaconing. Common C2 ports: 4444, 8080, 1337, 50050.

---

## Section 03 · Credential Access Detection

**MITRE ATT&CK:** T1003.001 / T1558.003 / T1555

### `credential_lsass_access` — 🔴 CRITICAL — T1003.001

**Detects:** Non-system process accessing LSASS memory — credential dumping.

```yaral
rule credential_lsass_access {
  meta:
    author = "Christian M. Njodzela"
    severity = "Critical"
    mitre_attack = "T1003.001"
  events:
    $access.metadata.event_type = "PROCESS_OPEN"
    $access.principal.hostname = $host
    $access.principal.user.userid = $user
    re.regex($access.target.process.file.full_path, `(?i)\\lsass\.exe$`)
    not re.regex($access.principal.process.file.full_path,
      `(?i)(\\csrss\.exe|\\wininit\.exe|\\svchost\.exe|\\MsMpEng\.exe|\\lsm\.exe)$`)
  match:
    $host over 5m
  condition:
    #access > 0
  outcome:
    $risk_score = 95
    $accessing_processes = array_distinct($access.principal.process.file.full_path)
    $users = array_distinct($access.principal.user.userid)
}
```

| Key | Value |
|-----|-------|
| **Trigger** | Any non-system process opening LSASS |
| **Risk Score** | 95 |
| **⚠ Tune** | Whitelist AV/EDR by process hash, not just name |

### `credential_kerberoasting` — 🟠 HIGH — T1558.003

| Key | Value |
|-----|-------|
| **Trigger** | `>10 TGS requests` with RC4 (0x17) in 30 min |
| **Risk Score** | 85 |
| **⚠ Tune** | FP: service accounts making legitimate Kerberos requests |

### `credential_file_access` — 🟠 HIGH — T1555

| Key | Value |
|-----|-------|
| **Trigger** | Non-browser reading credential files (Login Data, .kdbx, SAM, NTDS.dit) |
| **Risk Score** | 85 |
| **⚠ Tune** | Customize path list for org-specific credential stores |

---

## Section 04 · Data Exfiltration Detection

**MITRE ATT&CK:** T1048.001 / T1567 / T1041

### `exfiltration_large_outbound` — 🔴 CRITICAL — T1048.001

**Detects:** Internal host sending >500 MB to external IP in 1 hour.

| Key | Value |
|-----|-------|
| **Trigger** | `sum(sent_bytes) > 524288000` (500 MB) in 1h |
| **Risk Score** | 90 |
| **⚠ Tune** | Tune threshold by env. Exclude backup/DR traffic. |

### `exfiltration_dns_tunneling` — 🟠 HIGH — T1048.001

| Key | Value |
|-----|-------|
| **Trigger** | `>100 long DNS queries` (>50 chars, TXT/NULL/CNAME) in 30 min |
| **Risk Score** | 85 |
| **⚠ Tune** | Some CDNs use long subdomains |

### `exfiltration_cloud_upload` — 🟠 HIGH — T1567

| Key | Value |
|-----|-------|
| **Trigger** | `>3 uploads` (>1 MB each) to Dropbox/Drive/OneDrive/Mega in 1h |
| **Risk Score** | 80 |
| **⚠ Tune** | Allow-list sanctioned cloud storage |

#### 🔍 Hunting Queries — Exfiltration

**DNS Tunneling Detection:**
```yaral
event_type = "NETWORK_DNS"
AND network.dns.questions.type = "TXT"
AND strings.length(network.dns.questions.name) > 50
AND timestamp > now() - 24h
| stats count() as query_count by principal.ip
| where query_count > 20
| sort query_count desc
```

**Large Outbound Transfers:**
```yaral
event_type = "NETWORK_CONNECTION"
AND net.ip_in_range_cidr(principal.ip, "10.0.0.0/8")
AND NOT net.ip_in_range_cidr(target.ip, "10.0.0.0/8")
AND network.sent_bytes > 0 AND timestamp > now() - 1h
| stats sum(network.sent_bytes) as total_bytes by principal.ip, target.ip
| where total_bytes > 104857600
| sort total_bytes desc
```

---

## Section 05 · Defense Evasion Detection

**MITRE ATT&CK:** T1070.001 / T1562.001 / T1036.005

### `evasion_log_clearing` — 🔴 CRITICAL — T1070.001

**Detects:** Windows event logs cleared via wevtutil, Clear-EventLog, or Remove-EventLog.

| Key | Value |
|-----|-------|
| **Trigger** | Any log clearing command detected |
| **Risk Score** | 90 |
| **⚠ Tune** | Non-SYSTEM log clearing = immediate investigation |

### `evasion_disable_security_tools` — 🔴 CRITICAL — T1562.001

**Detects:** Attempt to stop/disable security services (Defender, EDR agents).

| Key | Value |
|-----|-------|
| **Trigger** | net stop/sc stop/sc config + AV/EDR service names, or Set-MpPreference -Disable |
| **Risk Score** | 95 |
| **⚠ Tune** | FP: software installers. Correlate with change window. |

### `evasion_masquerading` — 🟠 HIGH — T1036.005

**Detects:** Known Windows binary names running from paths outside System32/SysWOW64.

| Key | Value |
|-----|-------|
| **Trigger** | svchost/csrss/lsass/etc. running from wrong path |
| **Risk Score** | 90 |
| **⚠ Tune** | Expand path exclusions for non-standard Windows installs |

#### 🔍 Hunting Query — Log Clearing

```yaral
event_type = "PROCESS_LAUNCH"
AND (target.process.command_line = /(?i)wevtutil\s+(cl|clear-log)/
    OR target.process.command_line = /(?i)Clear-EventLog/
    OR target.process.command_line = /(?i)Remove-EventLog/)
AND timestamp > now() - 24h
| stats count() by principal.hostname, principal.user.userid,
    target.process.command_line
```

> This should **always return zero** in a healthy environment. Any result = investigate immediately.

---

## Section 06 · Lateral Movement Detection

**MITRE ATT&CK:** T1021.001 / T1021.002 / T1021.006

### `lateral_movement_rdp_internal` — 🟠 HIGH — T1021.001

| Key | Value |
|-----|-------|
| **Trigger** | `≥3 distinct internal RDP targets` from one host in 1h |
| **Risk Score** | 80 |
| **⚠ Tune** | Exclude jump servers and IT RDP bastion hosts |

### `lateral_movement_smb_sweep` — 🟠 HIGH — T1021.002

| Key | Value |
|-----|-------|
| **Trigger** | ADMIN$/C$/IPC$ access on `≥5 internal hosts` in 30 min |
| **Risk Score** | 85 |
| **⚠ Tune** | FP: SCCM, SolarWinds, PRTG, GPO-triggered SMB |

### `lateral_movement_winrm` — 🟠 HIGH — T1021.006

| Key | Value |
|-----|-------|
| **Trigger** | WinRM (5985/5986) to `≥3 targets` in 1h |
| **Risk Score** | 80 |
| **⚠ Tune** | Add user account context for compromised account chains |

#### 🔍 Hunting Queries — Lateral Movement

**RDP Between Workstations:**
```yaral
event_type = "NETWORK_CONNECTION"
AND target.port = 3389
AND net.ip_in_range_cidr(principal.ip, "10.0.0.0/8")
AND net.ip_in_range_cidr(target.ip, "10.0.0.0/8")
AND timestamp > now() - 24h
| stats count_distinct(target.ip) as rdp_targets by principal.ip
| where rdp_targets >= 2
| sort rdp_targets desc
```

**SMB Admin Share Access:**
```yaral
event_type = "NETWORK_CONNECTION"
AND target.port = 445
AND target.resource.name = /(?i)(ADMIN\$|C\$|IPC\$)/
AND timestamp > now() - 1h
| stats count_distinct(target.ip) as target_count by principal.ip
| where target_count >= 3
```

**Pass-the-Hash / Credential Reuse:**
```yaral
event_type = "USER_LOGIN"
AND security_result.action = "ALLOW"
AND net.ip_in_range_cidr(principal.ip, "10.0.0.0/8")
AND timestamp > now() - 1h
| stats count_distinct(target.hostname) as host_count by principal.user.userid
| where host_count >= 5
| sort host_count desc
```

---

## Section 07 · Persistence Mechanisms

**MITRE ATT&CK:** T1053.005 / T1547.001 / T1543.003

### `persistence_scheduled_task` — 🟠 HIGH — T1053.005

| Key | Value |
|-----|-------|
| **Trigger** | Non-SYSTEM creating scheduled task via schtasks /create |
| **Risk Score** | 70 |
| **⚠ Tune** | FP: AV/EDR, endpoint management, patching tools |

### `persistence_registry_run_key` — 🟠 HIGH — T1547.001

| Key | Value |
|-----|-------|
| **Trigger** | Run/RunOnce/RunServices key modified |
| **Risk Score** | 75 |
| **⚠ Tune** | FP: legitimate software installers |

### `persistence_suspicious_service` — 🟠 HIGH — T1543.003

| Key | Value |
|-----|-------|
| **Trigger** | New service with binary outside System32/Program Files |
| **Risk Score** | 80 |
| **⚠ Tune** | Build approved service binary path allow-list |

#### 🔍 Hunting Queries — Persistence

**New Scheduled Tasks (daily):**
```yaral
event_type = "PROCESS_LAUNCH"
AND target.process.file.full_path = /(?i)schtasks\.exe$/
AND target.process.command_line = /(?i)\/create/
AND principal.user.userid != /(?i)SYSTEM/
AND timestamp > now() - 24h
| stats count() by principal.hostname, principal.user.userid,
    target.process.command_line
```

**Registry Run Key Modifications (daily):**
```yaral
event_type = "REGISTRY_MODIFICATION"
AND target.registry.registry_key
    = /(?i)(\\CurrentVersion\\Run|\\CurrentVersion\\RunOnce)/
AND timestamp > now() - 24h
| stats count() by principal.hostname, principal.user.userid,
    target.registry.registry_key, target.registry.registry_value_data
```

---

## Section 08 · Phishing Indicators

**MITRE ATT&CK:** T1566.001 / T1566.002 / T1598

### `phishing_attachment_execution` — 🔴 CRITICAL — T1566.001

| Key | Value |
|-----|-------|
| **Trigger** | Suspicious attachment delivered AND executed from Temp/Downloads within 15 min |
| **Risk Score** | 95 |
| **⚠ Tune** | FP: new SaaS onboarding |

### `phishing_new_domain_click` — 🟠 HIGH — T1566.002

| Key | Value |
|-----|-------|
| **Trigger** | Click to domain registered <30 days via email client link |
| **Risk Score** | 80 |
| **⚠ Tune** | FP: new SaaS vendors, marketing redirects |

### `phishing_credential_harvest` — 🟠 HIGH — T1598

| Key | Value |
|-----|-------|
| **Trigger** | HTTP POST to non-corporate domain with credential URL keywords |
| **Risk Score** | 85 |
| **⚠ Tune** | ⚡ Replace example.com with actual corporate domains |

#### 🔍 Hunting Query — Clicked Phishing Link

```yaral
event_type = "NETWORK_HTTP"
AND principal.user.userid = "REPLACE_USERNAME"
AND target.domain.creation_time.seconds > 0
AND (timestamp.current_seconds() - target.domain.creation_time.seconds) < 2592000
AND network.http.referral_url = /(?i)(mail\.google\.com|outlook\.office|webmail)/
AND timestamp > now() - 24h
| stats count() by target.hostname, principal.user.userid
```

---

## Section 09 · Privilege Escalation

**MITRE ATT&CK:** T1068 / T1548.002 / T1134 / T1078.002

### `privesc_uac_bypass` — 🔴 CRITICAL — T1548.002

| Key | Value |
|-----|-------|
| **Trigger** | Auto-elevating binary (fodhelper/eventvwr/sdclt) spawning unexpected child |
| **Risk Score** | 95 |
| **⚠ Tune** | Very low FP. Any hit = immediate investigation. |

### `privesc_sensitive_privilege` — 🟠 HIGH — T1134

| Key | Value |
|-----|-------|
| **Trigger** | Event 4672 for non-system accounts |
| **Risk Score** | 75 |
| **⚠ Tune** | FP: domain join, IIS SeImpersonatePrivilege |

### `privesc_admin_group_addition` — 🔴 CRITICAL — T1078.002

| Key | Value |
|-----|-------|
| **Trigger** | Account added to Domain/Enterprise/Schema Admins or Backup Operators |
| **Risk Score** | 90 |
| **⚠ Tune** | Must correlate with change ticket |

#### 🔍 Hunting Query — Admin Group Changes (weekly)

```yaral
event_type = "GROUP_MODIFICATION"
AND target.group.group_display_name
    = /(?i)(Domain Admins|Enterprise Admins|Administrators)/
AND timestamp > now() - 7d
| stats count() by principal.user.userid,
    target.user.userid, target.group.group_display_name
```

> Any change with no matching change ticket is a **finding**.

---

## Section 10 · Reconnaissance Detection

**MITRE ATT&CK:** T1595 / T1590 / T1589

### `recon_port_scan` — 🟡 MEDIUM — T1595

| Key | Value |
|-----|-------|
| **Trigger** | `>50 distinct ports` scanned, <200 bytes per packet, in 10 min |
| **Risk Score** | 65 |
| **⚠ Tune** | FP: SCCM inventory, vulnerability scanners |

### `recon_network_sweep` — 🟡 MEDIUM — T1590

| Key | Value |
|-----|-------|
| **Trigger** | `>30 distinct IPs` scanned on common ports in 15 min |
| **Risk Score** | 70 |
| **⚠ Tune** | FP: SCCM, DNS/DHCP servers |

### `recon_ad_enumeration` — 🟡 MEDIUM — T1589

| Key | Value |
|-----|-------|
| **Trigger** | `>100 LDAP queries` (port 389) from non-DC host in 30 min |
| **Risk Score** | 70 |
| **⚠ Tune** | Exclude identity management tools |

#### 🔍 Hunting Query — Internal Scanning

```yaral
event_type = "NETWORK_CONNECTION"
AND principal.ip = "REPLACE_SRC_IP"
AND net.ip_in_range_cidr(target.ip, "10.0.0.0/8")
AND network.sent_bytes < 300
AND timestamp > now() - 15m
| stats count_distinct(target.ip) as hosts_scanned,
    count_distinct(target.port) as ports_scanned
    by principal.ip
| where hosts_scanned > 20 OR ports_scanned > 30
```

---

## Section 11 · Forwarding Rule Abuse ★ NEW

**MITRE ATT&CK:** T1114.003

### `forwarding_rule_inbox_creation` — 🟠 HIGH

| Key | Value |
|-----|-------|
| **Trigger** | Inbox rule created with ForwardTo/RedirectTo |
| **Risk Score** | 85 |

### `forwarding_rule_powershell_creation` — 🔴 CRITICAL

| Key | Value |
|-----|-------|
| **Trigger** | PowerShell creating Exchange forwarding (New-InboxRule, Set-Mailbox -ForwardingSmtpAddress) |
| **Risk Score** | 95 |
| **Key Insight** | PowerShell-created forwarding rules are almost always malicious |

### `forwarding_rule_external_domain` — 🟠 HIGH

| Key | Value |
|-----|-------|
| **Trigger** | Forwarding rule pointing to non-corporate domain |
| **Risk Score** | 90 |
| **⚡ Customize** | Replace @corp.example.com with your domain |

### `forwarding_rule_bulk_modification` — 🔴 CRITICAL

| Key | Value |
|-----|-------|
| **Trigger** | Single actor modifying forwarding on `≥3 mailboxes` in 1h |
| **Risk Score** | 95 |

#### 🔍 Hunting Query — Forwarding Rules (weekly)

```yaral
event_type = "EMAIL_UNCATEGORIZED"
AND metadata.product_event_type
    = /(?i)(New-InboxRule|Set-InboxRule|UpdateInboxRules)/
AND security_result.description
    = /(?i)(ForwardTo|RedirectTo|forward|redirect)/
AND timestamp > now() - 7d
| stats count() by principal.user.userid,
    security_result.description, principal.ip
```

> **Red flag:** Any forwarding to gmail.com, yahoo.com, protonmail.com = immediate user verification.

---

## Section 12 · Impossible Travel Detection ★ NEW

**MITRE ATT&CK:** T1078 / T1078.004

### `impossible_travel_successive_logins` — 🟠 HIGH

| Key | Value |
|-----|-------|
| **Trigger** | Same user, 2 countries, within 2 hours |
| **Risk Score** | 85 |

### `impossible_travel_city_level` — 🟠 HIGH

| Key | Value |
|-----|-------|
| **Trigger** | Same user, 2 cities, within 30 min |
| **Risk Score** | 80 |

### `impossible_travel_vpn_bypass` — 🔴 CRITICAL

| Key | Value |
|-----|-------|
| **Trigger** | Corporate VPN + foreign login within 5 min — active compromise |
| **Risk Score** | 95 |

### `impossible_travel_new_country` — 🟡 MEDIUM

| Key | Value |
|-----|-------|
| **Trigger** | First-ever login from a new country for this user |
| **Risk Score** | 60 |

#### 🔍 Hunting Query — Multi-Country Logins (daily)

```yaral
event_type = "USER_LOGIN"
AND security_result.action = "ALLOW"
AND timestamp > now() - 24h
| stats count_distinct(principal.location.country_or_region)
    as countries by principal.user.userid
| where countries > 1
```

---

## Section 13 · Spam Bot Detection ★ NEW

**MITRE ATT&CK:** T1566 / T1071 / T1078

### `spam_bot_high_volume_outbound` — 🟠 HIGH

| Key | Value |
|-----|-------|
| **Trigger** | `>100 outbound emails` in 1 hour |
| **Risk Score** | 80 |

### `spam_bot_many_unique_recipients` — 🟠 HIGH

| Key | Value |
|-----|-------|
| **Trigger** | `>50 unique external recipients` in 4 hours |
| **Risk Score** | 85 |

### `spam_bot_rapid_api_sends` — 🔴 CRITICAL

| Key | Value |
|-----|-------|
| **Trigger** | `>50 emails via SMTP/API` in 10 min — machine speed |
| **Risk Score** | 90 |

### `spam_bot_bounced_email_spike` — 🟠 HIGH

| Key | Value |
|-----|-------|
| **Trigger** | `>20 bounce/NDR messages` in 1 hour |
| **Risk Score** | 80 |

#### 🔍 Hunting Query — Spam Bot Check

```yaral
event_type = "EMAIL_TRANSACTION"
AND network.direction = "OUTBOUND"
AND timestamp > now() - 1h
| stats count() as sent_count,
    count_distinct(target.user.email_addresses) as unique_recipients
    by principal.user.userid
| where sent_count > 80
| sort sent_count desc
```

---

## Section 14 · Email Spoofing Detection ★ NEW

**MITRE ATT&CK:** T1566.001 / T1566.002 / T1534

### `spoofing_spf_dkim_dmarc_failure` — 🟠 HIGH

| Key | Value |
|-----|-------|
| **Trigger** | Inbound email failing SPF/DKIM/DMARC |
| **Risk Score** | 75 |

### `spoofing_display_name_impersonation` — 🔴 CRITICAL

| Key | Value |
|-----|-------|
| **Trigger** | Display name matches VIP but domain is external — CEO fraud/BEC |
| **Risk Score** | 90 |
| **⚡ Customize** | Replace executive names and corporate domain |

### `spoofing_lookalike_domain` — 🟠 HIGH

| Key | Value |
|-----|-------|
| **Trigger** | Sender domain typosquats your corporate domain |
| **Risk Score** | 85 |
| **⚡ Customize** | Generate regex using dnstwist for your domain |

### `spoofing_reply_to_mismatch` — 🟡 MEDIUM

| Key | Value |
|-----|-------|
| **Trigger** | Reply-To domain differs from From domain |
| **Risk Score** | 70 |

#### 🔍 Hunting Query — SPF/DKIM/DMARC Failures

```yaral
event_type = "EMAIL_TRANSACTION"
AND network.direction = "INBOUND"
AND security_result.description
    = /(?i)(spf=fail|spf=softfail|dkim=fail|dmarc=fail)/
AND timestamp > now() - 24h
| stats count() as fail_count by principal.user.email_addresses
| where fail_count > 3
| sort fail_count desc
```

> Focus on senders targeting executives or finance — a single failure targeting the CFO is more urgent than 10 targeting random users.

---

## Section 15 · Anomalous Process Execution ★ NEW

**MITRE ATT&CK:** T1059 / T1036 / T1218 / T1204

### `anomalous_parent_child_process` — 🟠 HIGH — T1059

| Key | Value |
|-----|-------|
| **Trigger** | Office→cmd/PS, w3wp→shell, WmiPrvSE→cmd |
| **Risk Score** | 85 |
| **⚠ Tune** | FP: Ansible/Chef/Puppet spawning shells |

### `anomalous_temp_directory_execution` — 🟠 HIGH — T1204

| Key | Value |
|-----|-------|
| **Trigger** | Binary from %TEMP%, Downloads, Desktop, Public |
| **Risk Score** | 75 |
| **⚠ Tune** | FP: Chrome/Firefox/Zoom auto-updaters |

### `anomalous_lolbin_abuse` — 🟠 HIGH — T1218

| Key | Value |
|-----|-------|
| **Trigger** | certutil downloading, mshta remote exec, bitsadmin transfer, wmic process create |
| **Risk Score** | 85 |
| **Key Insight** | certutil downloading a URL is almost never legitimate |

### `anomalous_renamed_binary` — 🟠 HIGH — T1036

| Key | Value |
|-----|-------|
| **Trigger** | PE original filename ≠ actual filename on disk |
| **Risk Score** | 90 |

#### 🔍 Hunting Queries — Process Anomalies

**Office App Spawning Scripting Engine (daily — almost always malicious):**
```yaral
event_type = "PROCESS_LAUNCH"
AND principal.process.file.full_path
    = /(?i)(WINWORD|EXCEL|POWERPNT|OUTLOOK)\.EXE$/
AND target.process.file.full_path
    = /(?i)(cmd\.exe|powershell\.exe|pwsh\.exe|
    wscript\.exe|cscript\.exe|mshta\.exe)$/
AND timestamp > now() - 24h
| stats count() by principal.hostname,
    target.process.file.full_path, target.process.command_line
```

**LOLBin Abuse:**
```yaral
event_type = "PROCESS_LAUNCH"
AND (
    (target.process.file.full_path = /(?i)certutil\.exe$/)
        AND target.process.command_line = /(?i)(-urlcache|-split|http)/)
    OR (target.process.file.full_path = /(?i)mshta\.exe$/)
        AND target.process.command_line = /(?i)(http|vbscript|javascript)/)
    OR (target.process.file.full_path = /(?i)bitsadmin\.exe$/)
        AND target.process.command_line = /(?i)(\/transfer|http)/)
)
AND timestamp > now() - 24h
| stats count() by principal.hostname, target.process.command_line
```

**Execution from Temp/Downloads:**
```yaral
event_type = "PROCESS_LAUNCH"
AND target.process.file.full_path
    = /(?i)(\\Temp\\|\\AppData\\Local\\Temp\\|
    \\Downloads\\|\\Users\\Public\\).*\.(exe|dll|scr|bat|cmd|ps1|vbs)$/
AND timestamp > now() - 24h
| stats count() by principal.hostname,
    target.process.file.full_path, principal.user.userid
| sort count() desc
```

---

## Section 16 · Routine Threat Hunting ★ NEW

**MITRE ATT&CK:** T1053 / T1547 / T1105 / T1543 / T1574

> 📋 Run these on a schedule for proactive detection

### `hunting_new_scheduled_tasks` — 🟡 MEDIUM — Run Daily

| Key | Value |
|-----|-------|
| **Trigger** | Any schtasks /create or Register-ScheduledTask in 24h |
| **Risk Score** | 50 |

### `hunting_new_services_installed` — 🟡 MEDIUM — Run Daily

| Key | Value |
|-----|-------|
| **Trigger** | sc.exe create or New-Service in 24h |
| **Risk Score** | 55 |

### `hunting_startup_folder_modifications` — 🟡 MEDIUM — Run Daily

| Key | Value |
|-----|-------|
| **Trigger** | Files written to Startup folder in 24h |
| **Risk Score** | 70 |

### `hunting_rare_process_execution` — 🟢 LOW — Run Weekly

| Key | Value |
|-----|-------|
| **Trigger** | Process seen on <3 hosts in 7 days |
| **Risk Score** | 40 |

### `hunting_unusual_outbound_connections` — 🟡 MEDIUM — Run Daily

| Key | Value |
|-----|-------|
| **Trigger** | External IP contacted by <3 internal hosts in 24h |
| **Risk Score** | 45 |

### `hunting_dll_sideloading_candidates` — 🟡 MEDIUM — Run Weekly

| Key | Value |
|-----|-------|
| **Trigger** | DLL from non-standard path loaded by vulnerable app |
| **Risk Score** | 65 |

### `hunting_unsigned_executables` — 🟢 LOW — Run Weekly

| Key | Value |
|-----|-------|
| **Trigger** | Unsigned/expired-signature executables running |
| **Risk Score** | 35 |

---

# PART 2 — CLOUD & SAAS HUNTING QUERIES

### OAuth App Consent — Broad Permissions `T1528`

```yaral
event_type = "USER_RESOURCE_ACCESS"
AND metadata.product_name = /(?i)(Azure AD|Google Workspace)/
AND security_result.description
    = /(?i)(Mail\.Read|Files\.ReadWrite|Calendars\.ReadWrite)/
AND timestamp > now() - 7d
| stats count() by principal.user.userid,
    target.application.asset_id, security_result.description
```

> Revoke consent immediately for unknown apps with mail access.

### New IAM Role Assignments (daily) `T1098`

```yaral
event_type = "GROUP_MODIFICATION"
OR (event_type = "USER_RESOURCE_ACCESS"
    AND metadata.product_event_type
    = /(?i)(Add member to role|roleAssignment\/write)/)
AND timestamp > now() - 24h
| stats count() by principal.user.userid,
    target.user.userid, security_result.description
```

### Cloud Logins from Unexpected Country `T1078.004`

```yaral
event_type = "USER_LOGIN"
AND security_result.action = "ALLOW"
AND metadata.product_name = /(?i)(Office 365|Azure AD|Google Workspace)/
AND principal.location.country_or_region != "REPLACE_HOME_COUNTRY"
AND timestamp > now() - 24h
| stats count() by principal.user.userid,
    principal.location.country_or_region, principal.ip
```

### Service Account Interactive Logins `T1078.003`

```yaral
event_type = "USER_LOGIN"
AND principal.user.userid = /(?i)(svc_|sa_|_svc|service)/
AND metadata.product_event_type = "interactive"
AND timestamp > now() - 7d
| stats count() as login_count by principal.user.userid
| sort login_count desc
```

### Dormant Accounts Active Again `T1078`

```yaral
event_type = "USER_LOGIN"
AND security_result.action = "ALLOW"
AND timestamp > now() - 1d
| join kind=leftanti (
    event_type = "USER_LOGIN"
    AND timestamp between (now()-60d, now()-1d)
) on principal.user.userid
| stats count() by principal.user.userid, principal.ip
```

---

# PART 3 — MITRE ATT&CK COVERAGE MATRIX

| Tactic | Techniques Covered |
|--------|-------------------|
| **Initial Access** | T1566.001, T1566.002, T1598 |
| **Execution** | T1059, T1204, T1218 |
| **Persistence** | T1053.005, T1547.001, T1543.003, T1574.002 |
| **Privilege Escalation** | T1068, T1548.002, T1134, T1078.002 |
| **Defense Evasion** | T1070.001, T1562.001, T1036.005, T1027 |
| **Credential Access** | T1003.001, T1558.003, T1555, T1552 |
| **Discovery** | T1595, T1592, T1589, T1590 |
| **Lateral Movement** | T1021.001, T1021.002, T1021.006, T1570 |
| **Collection** | T1114.003 |
| **Command & Control** | T1071.001, T1071.004, T1573, T1105 |
| **Exfiltration** | T1048.001, T1048.002, T1567, T1041 |
| **Identity (cross-tactic)** | T1078, T1078.004 |

---

# PART 4 — QUICK ESCALATION GUIDE

| Severity | What You Saw | Immediate Action |
|----------|-------------|------------------|
| 🔴 **CRITICAL** | Log clearing, LSASS access, security tool disabled, PowerShell forwarding rule, UAC bypass | **Isolate host NOW.** Page on-call. Open P1 incident. |
| 🟠 **HIGH** | Impossible travel, admin group change without ticket, Office→PowerShell, C2 beaconing | **Disable account.** Notify SOC lead within 30 min. Preserve logs. |
| 🟡 **MEDIUM** | Port scan, large data transfer, failed logins→success, new forwarding rule | **Investigate within 2 hours.** Correlate with other queries. Escalate if confirmed. |
| 🟢 **LOW / INFO** | Rare process, dormant account login, new task from known tool, unsigned binary | **Document and verify** with asset owner. Add to watch list if unexplained. |

---

# PART 5 — COMMON SUBSTITUTION REFERENCE

| Placeholder | Example | Where to Find It |
|-------------|---------|-------------------|
| `REPLACE_USERNAME` | `"jsmith"` | Ticket, alert, HR directory |
| `REPLACE_SRC_IP` | `"10.1.2.50"` | Alert, DHCP lease, asset inventory |
| `REPLACE_HOME_COUNTRY` | `"United States"` | Org primary country |
| `REPLACE_SAAS_PLATFORM` | `"Salesforce"` | Chronicle log source name |
| `YOUR_CORP_DOMAIN` | `"corp.example.com"` | Your email domain |
| `JUMP_SERVER_IP` | `"10.0.5.10"` | IT management server IPs |

---

**Author:** Christian M. Njodzela · Cybersecurity Analyst & Detection Engineer
**Repository:** [github.com/njodzela/soc-query-library](https://github.com/njodzela/soc-query-library)
**License:** MIT · © 2026
**Platforms:** Google SecOps (Chronicle), Splunk, Sentinel, QRadar, Defender
