# SOC Threat Hunting Quick Query Reference

**Google SecOps (Chronicle SIEM) · YARA-L 2.0**
*Supporting document for SOC Query Library*

| Stat | Value |
|------|-------|
| Queries | 30 |
| Categories | 6 |
| Format | 4 rows per query card |
| Platform | Google SecOps (Chronicle) |
| Edition | 2026 |

---

## How to Use This Document

Each query card has four rows. Read them in order before you run the query:

| Row | Color | What It Tells You |
|-----|-------|-------------------|
| **USE WHEN** | 🔵 Blue | The situation that makes this query worth running. Read first to decide if it applies. |
| **QUERY** | ⬛ Grey | The YARA-L query to paste into Google SecOps. Copy as-is, then make the SWAP changes. |
| **SWAP** | 🟡 Amber | What you must change before running. **Never run with `REPLACE_` placeholders.** |
| **LOOK FOR** | 🟢 Green | What a suspicious result looks like vs a false positive. Use this to triage. |

> **Quick Start:** Pick the section that matches your investigation → Find the right query → Check SWAP → Paste into Chronicle → Triage results using LOOK FOR.

---

## Sections at a Glance

| # | Section | Queries | Covers |
|---|---------|---------|--------|
| A | Identity & Access | 5 | Failed logins, impossible travel, dormant accounts, privilege changes |
| B | Network & C2 | 5 | Beaconing, rare destinations, DNS tunneling, large transfers |
| C | Endpoint & Process | 6 | Malicious process trees, LOLBins, persistence, log clearing |
| D | Email & Phishing | 4 | Forwarding rules, spoofing, spam bots, clicked phishing links |
| E | Lateral Movement | 4 | Internal scanning, RDP spread, SMB admin shares, credential reuse |
| F | Cloud & SaaS | 4 | OAuth consent abuse, IAM assignments, foreign logins |

---

## A — Identity & Access Hunting

*Find compromised accounts, privilege abuse, and unusual login patterns*

### Q01 · Failed Logins — Single User (30 min) `T1110.001`

**USE WHEN:** Investigating a suspected brute-force against a specific user account.

```yaral
event_type = "USER_LOGIN"
AND security_result.action = "BLOCK"
AND target.user.userid = "REPLACE_USERNAME"
AND timestamp > now() - 30m
| stats count() as fail_count by principal.ip
| where fail_count > 5
| sort fail_count desc
```

**SWAP:** `REPLACE_USERNAME` with the account you are investigating (e.g., `"jsmith"`)

**LOOK FOR:** Flag: same IP with many failures. Red flag: failures then a success from the same IP within seconds.

---

### Q02 · Logins from Multiple Countries — Same User (24 hrs) `T1078`

**USE WHEN:** Checking if a user account logged in from two or more countries today — impossible travel.

```yaral
event_type = "USER_LOGIN"
AND security_result.action = "ALLOW"
AND principal.user.userid = "REPLACE_USERNAME"
AND timestamp > now() - 24h
| stats count_distinct(principal.location.country_or_region)
    as countries by principal.user.userid
| where countries > 1
```

**SWAP:** `REPLACE_USERNAME` — or remove the user filter to scan all accounts.

**LOOK FOR:** Any result showing more than 1 country for the same account in 24 hours needs immediate review. Check if VPN egress IPs are skewing geolocation.

---

### Q03 · Admin Group Membership Changes (7 days) `T1078.002`

**USE WHEN:** Weekly hunt for unauthorized privilege escalation — users added to admin groups.

```yaral
event_type = "GROUP_MODIFICATION"
AND target.group.group_display_name
    = /(?i)(Domain Admins|Enterprise Admins|Administrators)/
AND timestamp > now() - 7d
| stats count() by principal.user.userid,
    target.user.userid, target.group.group_display_name
| sort timestamp desc
```

**SWAP:** Add your org-specific privileged group names to the regex list.

**LOOK FOR:** Cross-reference every result against your change management system. Any change with no matching ticket is a finding.

---

### Q04 · Service Account Interactive Logins `T1078.003`

**USE WHEN:** Hunting for service accounts being used interactively — they should only authenticate non-interactively.

```yaral
event_type = "USER_LOGIN"
AND principal.user.userid = /(?i)(svc_|sa_|_svc|service)/
AND metadata.product_event_type = "interactive"
AND timestamp > now() - 7d
| stats count() as login_count,
    array_distinct(principal.ip) as source_ips
    by principal.user.userid
| sort login_count desc
```

**SWAP:** Adjust the regex to match your org naming convention for service accounts (e.g., `svc_`, `sa_`, `_sa`).

**LOOK FOR:** Service accounts doing interactive logins may signal credential theft. Verify each account with its owner.

---

### Q05 · Dormant Accounts Active Again `T1078`

**USE WHEN:** Hunting for stale accounts that suddenly become active — common sign of forgotten credentials being exploited.

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

**SWAP:** Change `60d` to your dormancy threshold — some orgs use 30d or 90d.

**LOOK FOR:** Any dormant account suddenly active should be verified with HR and IT. Confirm the account should still exist.

---

## B — Network & Command-and-Control Hunting

*Identify beaconing, unusual outbound connections, and DNS abuse*

### Q06 · High-Frequency Outbound Connections — Single Host (1 hr) `T1071.001`

**USE WHEN:** A host is behaving oddly or an alert fired — check for C2 beaconing to an external domain.

```yaral
event_type = "NETWORK_HTTP"
AND principal.ip = "REPLACE_SRC_IP"
AND NOT net.ip_in_range_cidr(target.ip, "10.0.0.0/8")
AND NOT net.ip_in_range_cidr(target.ip, "192.168.0.0/16")
AND timestamp > now() - 1h
| stats count() as hits, min(timestamp) as first_seen
    by target.hostname
| where hits > 30
| sort hits desc
```

**SWAP:** `REPLACE_SRC_IP` with the internal host IP (e.g., `"10.1.2.50"`).

**LOOK FOR:** Beaconing pattern: same domain, very regular intervals, small consistent payload sizes. Check domain age and reputation.

---

### Q07 · Rare Outbound Destinations — Environment-Wide (24 hrs) `T1105`

**USE WHEN:** Daily hunt for external IPs that very few internal hosts have talked to — potential C2 or exfil destination.

```yaral
event_type = "NETWORK_CONNECTION"
AND net.ip_in_range_cidr(principal.ip, "10.0.0.0/8")
AND NOT net.ip_in_range_cidr(target.ip, "10.0.0.0/8")
AND NOT net.ip_in_range_cidr(target.ip, "192.168.0.0/16")
AND timestamp > now() - 24h
| stats count_distinct(principal.ip) as src_count
    by target.ip
| where src_count < 3
| sort src_count asc
```

**SWAP:** Replace `10.0.0.0/8` with your actual internal CIDR range if different.

**LOOK FOR:** Destinations only 1-2 internal hosts have ever touched are worth checking against threat intel.

---

### Q08 · Long DNS Query Names — DNS Tunneling Detection `T1048.001`

**USE WHEN:** Hunting for data being exfiltrated via DNS — encoded data makes query names unusually long.

```yaral
event_type = "NETWORK_DNS"
AND network.dns.questions.type = "TXT"
AND strings.length(network.dns.questions.name) > 50
AND timestamp > now() - 24h
| stats count() as query_count,
    array_distinct(network.dns.questions.name) as sample_queries
    by principal.ip
| where query_count > 20
| sort query_count desc
```

**SWAP:** Adjust the length threshold (50) down to 40 if you want to be more aggressive.

**LOOK FOR:** Legitimate DNS queries are short. Base64-encoded data in subdomains looks like: `a8f3kZpQ92mx.evil.com`.

---

### Q09 · TLS Traffic on Non-Standard Ports `T1573`

**USE WHEN:** Hunting for C2 frameworks hiding encrypted traffic on unusual ports.

```yaral
event_type = "NETWORK_CONNECTION"
AND network.application_protocol = "TLS"
AND target.port != 443
AND target.port != 8443
AND target.port != 993
AND target.port != 995
AND NOT net.ip_in_range_cidr(target.ip, "10.0.0.0/8")
AND timestamp > now() - 24h
| stats count() as conn_count,
    array_distinct(target.port) as ports
    by principal.ip, target.ip
| sort conn_count desc
```

**SWAP:** Add your org-specific allowed TLS ports (e.g., your VPN port).

**LOOK FOR:** Repeated TLS connections to the same external IP on a non-standard port. Common C2 ports: 4444, 8080, 1337, 50050.

---

### Q10 · Large Outbound Data Transfers (1 hr) `T1048`

**USE WHEN:** Investigating potential data exfiltration or scanning the environment for bulk transfers.

```yaral
event_type = "NETWORK_CONNECTION"
AND net.ip_in_range_cidr(principal.ip, "10.0.0.0/8")
AND NOT net.ip_in_range_cidr(target.ip, "10.0.0.0/8")
AND network.sent_bytes > 0
AND timestamp > now() - 1h
| stats sum(network.sent_bytes) as total_bytes
    by principal.ip, target.ip
| where total_bytes > 104857600
| sort total_bytes desc
```

**SWAP:** Change `104857600` (100 MB) to your threshold. Use `524288000` for 500 MB.

**LOOK FOR:** Context matters: backups and sync jobs are legitimate. Look for unusual destination IPs and off-hours timing.

---

## C — Endpoint & Process Hunting

*Find malicious process execution, LOLBin abuse, and persistence mechanisms*

### Q11 · Office App Spawning a Scripting Engine `T1059`

**USE WHEN:** Hunting for phishing payload execution — Office apps should never spawn PowerShell or cmd directly.

```yaral
event_type = "PROCESS_LAUNCH"
AND principal.process.file.full_path
    = /(?i)(WINWORD|EXCEL|POWERPNT|OUTLOOK)\.EXE$/
AND target.process.file.full_path
    = /(?i)(cmd\.exe|powershell\.exe|pwsh\.exe|
    wscript\.exe|cscript\.exe|mshta\.exe)$/
AND timestamp > now() - 24h
| stats count() by principal.hostname,
    principal.process.file.full_path,
    target.process.file.full_path,
    target.process.command_line
```

**SWAP:** No changes needed. Run this query daily.

**LOOK FOR:** Almost always malicious. Check the command line for `-enc` (encoded payload).

---

### Q12 · Execution from Temp / Downloads / AppData `T1204`

**USE WHEN:** Hunting for malware staging — malicious files are frequently dropped to temp directories.

```yaral
event_type = "PROCESS_LAUNCH"
AND target.process.file.full_path
    = /(?i)(\\Temp\\|\\AppData\\Local\\Temp\\|
    \\Downloads\\|\\Users\\Public\\).*
    \.(exe|dll|scr|bat|cmd|ps1|vbs)$/
AND timestamp > now() - 24h
| stats count() by principal.hostname,
    target.process.file.full_path,
    principal.user.userid
| sort count() desc
```

**SWAP:** Add known-good exclusions: `AND NOT target.process.file.full_path = /DismHost|TiWorker/`

**LOOK FOR:** Check file hashes for unknowns. Pay attention to `.ps1` and `.vbs` files in user Downloads or Desktop.

---

### Q13 · LOLBin Abuse — certutil / mshta / bitsadmin `T1218`

**USE WHEN:** Hunting for attackers using built-in Windows tools to download payloads or execute code.

```yaral
event_type = "PROCESS_LAUNCH"
AND (
    (target.process.file.full_path = /(?i)certutil\.exe$/)
        AND target.process.command_line = /(?i)(-urlcache|-split|http)/)
    OR
    (target.process.file.full_path = /(?i)mshta\.exe$/)
        AND target.process.command_line = /(?i)(http|vbscript|javascript)/)
    OR
    (target.process.file.full_path = /(?i)bitsadmin\.exe$/)
        AND target.process.command_line = /(?i)(\/transfer|http)/)
)
AND timestamp > now() - 24h
| stats count() by principal.hostname, target.process.command_line
```

**SWAP:** No changes needed. Extend with additional LOLBins: regsvr32, rundll32, wmic. See [lolbas-project.github.io](https://lolbas-project.github.io).

**LOOK FOR:** certutil downloading a URL is almost never legitimate. Any hit should be escalated.

---

### Q14 · New Scheduled Tasks Created (24 hrs) `T1053.005`

**USE WHEN:** Daily hunt for new persistence mechanisms added via scheduled tasks.

```yaral
event_type = "PROCESS_LAUNCH"
AND target.process.file.full_path = /(?i)schtasks\.exe$/
AND target.process.command_line = /(?i)\/create/
AND principal.user.userid != /(?i)SYSTEM/
AND timestamp > now() - 24h
| stats count() by principal.hostname,
    principal.user.userid,
    target.process.command_line
| sort timestamp desc
```

**SWAP:** Add exclusions for your endpoint management tool: `AND NOT principal.user.userid = "SCCM_SVC"`

**LOOK FOR:** Review `/TN` (task name) and `/TR` (task run command). Suspicious: tasks pointing to %TEMP%, encoded PowerShell, or unknown executables.

---

### Q15 · Registry Run Key Modifications `T1547.001`

**USE WHEN:** Hunting for persistence via startup registry keys.

```yaral
event_type = "REGISTRY_MODIFICATION"
AND target.registry.registry_key
    = /(?i)(\\CurrentVersion\\Run|
    \\CurrentVersion\\RunOnce|
    \\CurrentVersion\\RunServices)/
AND timestamp > now() - 24h
| stats count() by principal.hostname,
    principal.user.userid,
    target.registry.registry_key,
    target.registry.registry_value_data
| sort timestamp desc
```

**SWAP:** No changes needed for standard Windows environments.

**LOOK FOR:** Value data should point to a known, signed executable. Unknown paths or base64-encoded strings = high priority.

---

### Q16 · Windows Event Log Cleared `T1070.001`

**USE WHEN:** Immediate investigation trigger — attacker clearing logs to cover tracks.

```yaral
event_type = "PROCESS_LAUNCH"
AND (
    target.process.command_line = /(?i)wevtutil\s+(cl|clear-log)/
    OR target.process.command_line = /(?i)Clear-EventLog/
    OR target.process.command_line = /(?i)Remove-EventLog/
)
AND timestamp > now() - 24h
| stats count() by principal.hostname,
    principal.user.userid,
    target.process.command_line
```

**SWAP:** No changes needed. This should always return zero results in a healthy environment.

**LOOK FOR:** Any result from a non-admin account is **Critical**. Admin accounts clearing logs outside a documented maintenance window = investigate immediately.

---

## D — Email & Phishing Hunting

*Detect forwarding rule abuse, spoofing, and phishing delivery*

### Q17 · Mailbox Forwarding Rules Created (7 days) `T1114.003`

**USE WHEN:** Weekly hunt for inbox rules quietly forwarding email to external addresses.

```yaral
event_type = "EMAIL_UNCATEGORIZED"
AND metadata.product_event_type
    = /(?i)(New-InboxRule|Set-InboxRule|UpdateInboxRules)/
AND security_result.description
    = /(?i)(ForwardTo|RedirectTo|forward|redirect)/
AND timestamp > now() - 7d
| stats count() by principal.user.userid,
    security_result.description,
    principal.ip
| sort timestamp desc
```

**SWAP:** Add `AND NOT security_result.description = /@yourcorp\.com/` to suppress known-good internal forwarding.

**LOOK FOR:** Any forwarding to free email providers (gmail.com, yahoo.com, protonmail.com) warrants immediate user verification.

---

### Q18 · Inbound Emails Failing SPF / DKIM / DMARC `T1566.001`

**USE WHEN:** Hunting for spoofed inbound emails that bypassed your email gateway.

```yaral
event_type = "EMAIL_TRANSACTION"
AND network.direction = "INBOUND"
AND security_result.description
    = /(?i)(spf=fail|spf=softfail|dkim=fail|dmarc=fail)/
AND timestamp > now() - 24h
| stats count() as fail_count,
    array_distinct(target.user.email_addresses) as targets
    by principal.user.email_addresses
| where fail_count > 3
| sort fail_count desc
```

**SWAP:** Remove `fail_count > 3` to see all failures, not just repeat senders.

**LOOK FOR:** Focus on senders targeting executives or finance. A single spf=fail targeting the CFO is more urgent than 10 targeting random users.

---

### Q19 · High Volume Outbound Email — Possible Spam Bot `T1078`

**USE WHEN:** An account is sending abnormal volume — may be compromised for phishing distribution.

```yaral
event_type = "EMAIL_TRANSACTION"
AND network.direction = "OUTBOUND"
AND timestamp > now() - 1h
| stats count() as sent_count,
    count_distinct(target.user.email_addresses)
    as unique_recipients
    by principal.user.userid
| where sent_count > 80
| sort sent_count desc
```

**SWAP:** Change `80` to match your environment. Marketing/sales roles may need `150`.

**LOOK FOR:** Is the account sending to many external domains it has never contacted before? Correlate with authentication anomalies.

---

### Q20 · User Clicked Link to Newly Registered Domain `T1566.002`

**USE WHEN:** Following up on a suspicious email report — checking if the user actually clicked.

```yaral
event_type = "NETWORK_HTTP"
AND principal.user.userid = "REPLACE_USERNAME"
AND target.domain.creation_time.seconds > 0
AND (timestamp.current_seconds()
    - target.domain.creation_time.seconds) < 2592000
AND network.http.referral_url
    = /(?i)(mail\.google\.com|outlook\.office|webmail)/
AND timestamp > now() - 24h
| stats count() by target.hostname,
    target.domain.creation_time, principal.user.userid
```

**SWAP:** `REPLACE_USERNAME` with the user. Remove the filter to scan all users.

**LOOK FOR:** Domain under 30 days old + clicked from webmail = high suspicion. Check what happened on the endpoint within 15 min.

---

## E — Lateral Movement Hunting

*Detect internal scanning, RDP spread, and credential reuse across hosts*

### Q21 · Internal Host Scanning Multiple Targets (15 min) `T1595`

**USE WHEN:** A host is triggering connection alerts — check if it is actively scanning internally.

```yaral
event_type = "NETWORK_CONNECTION"
AND principal.ip = "REPLACE_SRC_IP"
AND net.ip_in_range_cidr(target.ip, "10.0.0.0/8")
AND network.sent_bytes < 300
AND timestamp > now() - 15m
| stats count_distinct(target.ip) as hosts_scanned,
    count_distinct(target.port) as ports_scanned,
    array_distinct(target.port) as port_list
    by principal.ip
| where hosts_scanned > 20 OR ports_scanned > 30
```

**SWAP:** `REPLACE_SRC_IP` with the host under investigation. Remove the IP filter to scan the whole environment.

**LOOK FOR:** Small sent_bytes (<300) plus many unique destination IPs = scan. Check what processes were running on the source.

---

### Q22 · RDP Connections Between Workstations `T1021.001`

**USE WHEN:** Hunting for lateral movement via RDP — workstation-to-workstation RDP is abnormal.

```yaral
event_type = "NETWORK_CONNECTION"
AND target.port = 3389
AND net.ip_in_range_cidr(principal.ip, "10.0.0.0/8")
AND net.ip_in_range_cidr(target.ip, "10.0.0.0/8")
AND timestamp > now() - 24h
| stats count_distinct(target.ip) as rdp_targets
    by principal.ip
| where rdp_targets >= 2
| sort rdp_targets desc
```

**SWAP:** Add `AND NOT principal.ip = "JUMP_SERVER_IP"` to exclude legitimate RDP jump hosts.

**LOOK FOR:** One workstation RDPing to 3+ others in a day is a strong lateral movement signal. Correlate with user accounts.

---

### Q23 · SMB Admin Share Access Across Multiple Hosts `T1021.002`

**USE WHEN:** Hunting for lateral movement via SMB — accessing ADMIN$, C$, IPC$ on multiple machines.

```yaral
event_type = "NETWORK_CONNECTION"
AND target.port = 445
AND target.resource.name = /(?i)(ADMIN\$|C\$|IPC\$)/
AND net.ip_in_range_cidr(principal.ip, "10.0.0.0/8")
AND timestamp > now() - 1h
| stats count_distinct(target.ip) as target_count,
    array_distinct(target.resource.name) as shares
    by principal.ip
| where target_count >= 3
| sort target_count desc
```

**SWAP:** Exclude monitoring tools: `AND NOT principal.ip = "YOUR_SCCM_IP"`

**LOOK FOR:** SCCM, PRTG, GPO push will show up — exclude them. Anything else accessing ADMIN$ on 3+ hosts needs investigation.

---

### Q24 · Same Account Authenticating to Many Hosts (1 hr) `T1550`

**USE WHEN:** Hunting for pass-the-hash or stolen credential reuse — one account authenticating to many hosts quickly.

```yaral
event_type = "USER_LOGIN"
AND security_result.action = "ALLOW"
AND net.ip_in_range_cidr(principal.ip, "10.0.0.0/8")
AND timestamp > now() - 1h
| stats count_distinct(target.hostname) as host_count,
    array_distinct(target.hostname) as hosts
    by principal.user.userid
| where host_count >= 5
| sort host_count desc
```

**SWAP:** Adjust `host_count` for non-admin users — even 3 hosts in an hour can be suspicious.

**LOOK FOR:** Pass-the-hash reuse tends to happen in rapid bursts. A standard user authenticating to 5 servers in 5 minutes is a strong signal.

---

## F — Cloud & SaaS Hunting

*Queries for Azure AD, Google Workspace, and SaaS platform log hunting*

### Q25 · OAuth App Consent with Broad Permission Scopes `T1528`

**USE WHEN:** Hunting for OAuth app consent abuse — malicious apps requesting broad permissions.

```yaral
event_type = "USER_RESOURCE_ACCESS"
AND metadata.product_name = /(?i)(Azure AD|Google Workspace)/
AND security_result.description
    = /(?i)(Mail\.Read|Files\.ReadWrite|
    Calendars\.ReadWrite|Directory\.ReadWrite)/
AND timestamp > now() - 7d
| stats count() by principal.user.userid,
    target.application.asset_id,
    security_result.description
| sort timestamp desc
```

**SWAP:** Add your org's sensitive scopes to the regex. Focus on `Mail.Read` and `Files.ReadWrite.All`.

**LOOK FOR:** Did the user intentionally install this app? Is it approved? Revoke consent immediately for unknown apps with mail access.

---

### Q26 · New IAM Role Assignments (24 hrs) `T1098`

**USE WHEN:** Daily check for new cloud admin or elevated role assignments.

```yaral
event_type = "GROUP_MODIFICATION"
OR (event_type = "USER_RESOURCE_ACCESS"
    AND metadata.product_event_type
    = /(?i)(Add member to role|roleAssignment\/write)/)
AND timestamp > now() - 24h
| stats count() by principal.user.userid,
    target.user.userid,
    security_result.description,
    timestamp
| sort timestamp desc
```

**SWAP:** Filter by platform if needed: `AND metadata.product_name = "Azure AD"`

**LOOK FOR:** Any Global Admin or Owner assignment without a matching change ticket is a finding. 2 AM role assignments are always suspicious.

---

### Q27 · Cloud App Logins from Unexpected Country `T1078.004`

**USE WHEN:** Hunting for cloud account compromise via foreign logins to O365, Azure, or Google Workspace.

```yaral
event_type = "USER_LOGIN"
AND security_result.action = "ALLOW"
AND metadata.product_name
    = /(?i)(Office 365|Azure AD|Google Workspace)/
AND principal.location.country_or_region
    != "REPLACE_HOME_COUNTRY"
AND timestamp > now() - 24h
| stats count() by principal.user.userid,
    principal.location.country_or_region,
    principal.ip
| sort count() desc
```

**SWAP:** `REPLACE_HOME_COUNTRY` with your primary country (e.g., `"United States"`). Add additional expected countries for global offices.

**LOOK FOR:** Filter out known VPN egress IPs first. Focus on finance, HR, and executive accounts.

---

### Q28 · SaaS Platform Admin Actions Audit (7 days) `T1098.003`

**USE WHEN:** Weekly review of admin-level actions in SaaS platforms.

```yaral
event_type = "USER_RESOURCE_ACCESS"
AND principal.user.userid = /(?i)(admin|administrator)/
AND security_result.action = "ALLOW"
AND metadata.product_name = "REPLACE_SAAS_PLATFORM"
AND timestamp > now() - 7d
| stats count() by principal.user.userid,
    metadata.product_event_type,
    principal.ip
| sort count() desc
```

**SWAP:** `REPLACE_SAAS_PLATFORM` with the Chronicle log source name (e.g., `"Salesforce"`, `"Slack"`, `"Okta"`).

**LOOK FOR:** Baseline normal admin activity. Flag: admin actions from unknown IPs or at unusual hours.

---

## Analyst Tips & Escalation Guide

### Running a Hunt — Step by Step

1. **Pick the right section** — Match your situation to A-F
2. **Read USE WHEN first** — Confirm the query matches your investigation
3. **Make your SWAP changes** — Replace all placeholders before running
4. **Start with a short time window** — Begin with 1h or 24h, widen to 7d only if needed
5. **Use LOOK FOR to triage** — Not every result is malicious
6. **Pivot from results** — Take the IP/hostname/username and run other queries in the same section

### Common Substitution Reference

| Placeholder | Example Value | Where to Find It |
|-------------|---------------|-------------------|
| `REPLACE_USERNAME` | `"jsmith"` or `"john.smith@corp.com"` | Ticket, alert, or HR directory |
| `REPLACE_SRC_IP` | `"10.1.2.50"` | Alert detail, DHCP lease, asset inventory |
| `REPLACE_HOME_COUNTRY` | `"United States"` | Your org primary operating country |
| `REPLACE_SAAS_PLATFORM` | `"Salesforce"` or `"Okta"` | Chronicle log source name |
| `YOUR_CORP_DOMAIN` | `"corp.example.com"` | Your actual email domain |
| `JUMP_SERVER_IP` / `SCCM_IP` | `"10.0.5.10"` | Your IT management server IPs |

### Quick Escalation Guide

| Severity | What You Saw | Immediate Action |
|----------|-------------|------------------|
| 🔴 **CRITICAL** | Log clearing, LSASS access, security tool disabled, PowerShell forwarding rule | Isolate host NOW. Page on-call. Open P1 incident. |
| 🟠 **HIGH** | Impossible travel, admin group change without ticket, Office app spawning PowerShell | Disable account. Notify SOC lead within 30 min. Preserve logs. |
| 🟡 **MEDIUM** | Port scan from internal host, large data transfer, failed logins then 1 success | Investigate within 2 hours. Correlate with other queries. Escalate if confirmed. |
| 🟢 **LOW / INFO** | Rare process, dormant account login, new scheduled task from known tool | Document and verify with asset owner. Add to watch list if unexplained. |

---

**Companion to SOC Detection Query Library** · [github.com/njodzela/soc-query-library](https://github.com/njodzela/soc-query-library) · Google SecOps / Chronicle · YARA-L 2.0 · 2026
