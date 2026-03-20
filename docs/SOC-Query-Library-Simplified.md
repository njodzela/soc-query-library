# SOC Detection Query Library — Simplified Reference

**Google SecOps (Chronicle SIEM) · YARA-L 2.0**

| Stat | Value |
|------|-------|
| Total Rules | 48 |
| Categories | 16 |
| MITRE Techniques | 40+ |
| Edition | 2026 |

## Severity Legend

| Severity | Risk Score |
|----------|------------|
| 🔴 CRITICAL | 90–95 |
| 🟠 HIGH | 70–90 |
| 🟡 MEDIUM | 55–70 |
| 🟢 LOW | 35–55 |

> ⚡ = REQUIRES CUSTOMIZATION BEFORE DEPLOYMENT

## How to Use This Document

Each rule card shows exactly what you need to deploy it in Google SecOps:

- **MATCH / WINDOW** — The event filter and time window for the YARA-L `match:` block
- **TRIGGER CONDITION** — The threshold or count that fires the alert (the YARA-L `condition:` block)
- **RISK SCORE** — Numeric score assigned in the `outcome:` block for prioritization
- **TUNE / FP** — Exclusions and false positive sources to address before go-live

---

## Section 01 · Brute-Force Detection

**MITRE ATT&CK:** T1110.001 / T1110.003 / T1110.004

### `brute_force_single_source` — 🟠 HIGH — T1110.001

**What It Detects:** Excessive failed logins from one IP within 10 min.

| Field | Value |
|-------|-------|
| **Match / Window** | `event_type = USER_LOGIN`, `action = BLOCK`, match: `$source_ip` over `10m` |
| **Trigger Condition** | `#fail > 15` |
| **Risk Score** | 75 |
| **⚠ Tune / FP** | Exclude VPN egress IPs, load balancers, cloud IdPs. |

### `password_spraying_detection` — 🟠 HIGH — T1110.003

**What It Detects:** Failed logins to many distinct accounts from one source (30 min window).

| Field | Value |
|-------|-------|
| **Match / Window** | `event_type = USER_LOGIN`, `action = BLOCK`, match: `$source_ip` over `30m` |
| **Trigger Condition** | `#fail > 10 AND count_distinct(target_user) > 8` |
| **Risk Score** | 85 |
| **⚠ Tune / FP** | FP: expired service accounts, federated auth flows. |

### `credential_stuffing_success` — 🔴 CRITICAL — T1110.004

**What It Detects:** Successful login preceded by 10+ failures from same IP — classic stuffing pattern.

| Field | Value |
|-------|-------|
| **Match / Window** | `event_type = USER_LOGIN`, fail→success from same `source_ip`, match over `30m` |
| **Trigger Condition** | `#fail > 10 AND #success > 0` |
| **Risk Score** | 90 |
| **⚠ Tune / FP** | FP: password reset flows, expired service account creds. |

---

## Section 02 · Command & Control Detection

**MITRE ATT&CK:** T1071.001 / T1071.004 / T1573 / T1105

### `c2_http_beaconing` — 🟠 HIGH — T1071.001

**What It Detects:** Regular-interval HTTP/S connections from internal IP to single external domain — C2 beacon pattern.

| Field | Value |
|-------|-------|
| **Match / Window** | `event_type = NETWORK_HTTP`, src from RFC1918, port 80/443, match: `$src_ip, $domain` over `1h` |
| **Trigger Condition** | `#beacon > 60` |
| **Risk Score** | 75 |
| **⚠ Tune / FP** | Add JA3/JA3S fingerprinting. Tune for CDN traffic. |

### `c2_dns_channel` — 🟠 HIGH — T1071.004

**What It Detects:** DNS C2 via excessive TXT queries to a single parent domain.

| Field | Value |
|-------|-------|
| **Match / Window** | `event_type = NETWORK_DNS`, query type = TXT, match: `$src_ip` over `30m` |
| **Trigger Condition** | `#dns > 50` |
| **Risk Score** | 80 |
| **⚠ Tune / FP** | FP: CDN resolution generating many TXT queries. |

### `c2_encrypted_nonstandard_port` — 🟠 HIGH — T1573

**What It Detects:** TLS traffic on non-standard ports (not 443/8443/993/995/636) to external IPs.

| Field | Value |
|-------|-------|
| **Match / Window** | `event_type = NETWORK_CONNECTION`, protocol = TLS, dst NOT RFC1918, port ≠ 443/8443/993/995/636 |
| **Trigger Condition** | `#conn > 5` over `1h` |
| **Risk Score** | 80 |
| **⚠ Tune / FP** | Build TLS non-standard port allow-list for VPN/apps. |

---

## Section 03 · Credential Access Detection

**MITRE ATT&CK:** T1003.001 / T1558.003 / T1555

### `credential_lsass_access` — 🔴 CRITICAL — T1003.001

**What It Detects:** Non-system process accessing LSASS memory — credential dumping.

| Field | Value |
|-------|-------|
| **Match / Window** | `event_type = PROCESS_OPEN`, target = `lsass.exe`, NOT csrss/wininit/svchost/MsMpEng/lsm |
| **Trigger Condition** | `#access > 0` over `5m` |
| **Risk Score** | 95 |
| **⚠ Tune / FP** | Whitelist AV/EDR vendors by process hash, not just name. |

### `credential_kerberoasting` — 🟠 HIGH — T1558.003

**What It Detects:** Excessive TGS ticket requests (Event 4769) with RC4 encryption (0x17) — Kerberoasting.

| Field | Value |
|-------|-------|
| **Match / Window** | `event_type = USER_RESOURCE_ACCESS`, event 4769, encryption 0x17, NOT machine accounts ($) |
| **Trigger Condition** | `#tgs > 10` over `30m` |
| **Risk Score** | 85 |
| **⚠ Tune / FP** | FP: service accounts making legitimate Kerberos requests. |

### `credential_file_access` — 🟠 HIGH — T1555

**What It Detects:** Non-browser process reading credential files (Login Data, .kdbx, SAM, NTDS.dit).

| Field | Value |
|-------|-------|
| **Match / Window** | `event_type = FILE_READ`, path matches credential files, NOT chrome/msedge/firefox/svchost |
| **Trigger Condition** | `#file > 0` over `30m` |
| **Risk Score** | 85 |
| **⚠ Tune / FP** | Customize path list for org-specific credential stores. |

---

## Section 04 · Data Exfiltration Detection

**MITRE ATT&CK:** T1048.001 / T1567 / T1041

### `exfiltration_large_outbound` — 🔴 CRITICAL — T1048.001

**What It Detects:** Internal host sending >500 MB to external IP in 1 hour.

| Field | Value |
|-------|-------|
| **Match / Window** | `event_type = NETWORK_CONNECTION`, src = RFC1918, dst = external, match: `$src_ip` over `1h` |
| **Trigger Condition** | `sum(sent_bytes) > 524288000` |
| **Risk Score** | 90 |
| **⚠ Tune / FP** | Tune threshold by env. Exclude backup/DR traffic. |

### `exfiltration_dns_tunneling` — 🟠 HIGH — T1048.001

**What It Detects:** High-volume TXT/NULL/CNAME DNS queries with long subdomains (>50 chars) — DNS tunneling.

| Field | Value |
|-------|-------|
| **Match / Window** | `event_type = NETWORK_DNS`, query length > 50, type = TXT/NULL/CNAME, match: `$src_ip` over `30m` |
| **Trigger Condition** | `#dns > 100` |
| **Risk Score** | 85 |
| **⚠ Tune / FP** | Some CDNs use long subdomains — tune length threshold. |

### `exfiltration_cloud_upload` — 🟠 HIGH — T1567

**What It Detects:** POST/PUT requests >1 MB to personal cloud storage (Dropbox, Drive, OneDrive, Mega, WeTransfer).

| Field | Value |
|-------|-------|
| **Match / Window** | `event_type = NETWORK_HTTP`, method = POST/PUT, target = cloud storage, sent_bytes > 1048576 |
| **Trigger Condition** | `#upload > 3` over `1h` |
| **Risk Score** | 80 |
| **⚠ Tune / FP** | Allow-list sanctioned cloud storage with verified business accounts. |

---

## Section 05 · Defense Evasion Detection

**MITRE ATT&CK:** T1070.001 / T1562.001 / T1036.005

### `evasion_log_clearing` — 🔴 CRITICAL — T1070.001

**What It Detects:** Windows event logs cleared via wevtutil, Clear-EventLog, or Remove-EventLog.

| Field | Value |
|-------|-------|
| **Match / Window** | `event_type = PROCESS_LAUNCH`, command matches log clearing commands |
| **Trigger Condition** | `#clear > 0` over `1h` |
| **Risk Score** | 90 |
| **⚠ Tune / FP** | Any log clearing by non-SYSTEM account should be investigated immediately. |

### `evasion_disable_security_tools` — 🔴 CRITICAL — T1562.001

**What It Detects:** Attempt to stop/disable security services (Defender, EDR agents) via net stop, sc config, or Set-MpPreference.

| Field | Value |
|-------|-------|
| **Match / Window** | `event_type = PROCESS_LAUNCH`, command matches service stop/disable + AV/EDR service names |
| **Trigger Condition** | `#tamper > 0` over `1h` |
| **Risk Score** | 95 |
| **⚠ Tune / FP** | FP: software installers stopping services. Correlate with change window. |

### `evasion_masquerading` — 🟠 HIGH — T1036.005

**What It Detects:** Known Windows binary names (svchost, lsass, etc.) running from paths outside System32/SysWOW64.

| Field | Value |
|-------|-------|
| **Match / Window** | `event_type = PROCESS_LAUNCH`, filename matches system binaries, path NOT System32/SysWOW64 |
| **Trigger Condition** | `#masq > 0` over `1h` |
| **Risk Score** | 90 |
| **⚠ Tune / FP** | Expand path exclusions for non-standard Windows installs. |

---

## Section 06 · Lateral Movement Detection

**MITRE ATT&CK:** T1021.001 / T1021.002 / T1021.006

### `lateral_movement_rdp_internal` — 🟠 HIGH — T1021.001

**What It Detects:** Single internal host initiating RDP (3389) to 3+ distinct internal targets in 1 hour.

| Field | Value |
|-------|-------|
| **Match / Window** | `event_type = NETWORK_CONNECTION`, port = 3389, src AND dst RFC1918, match: `$src_ip` over `1h` |
| **Trigger Condition** | `count_distinct(dst_ip) >= 3` |
| **Risk Score** | 80 |
| **⚠ Tune / FP** | Exclude jump servers and IT RDP bastion hosts. |

### `lateral_movement_smb_sweep` — 🟠 HIGH — T1021.002

**What It Detects:** Single host accessing SMB admin shares (ADMIN$, C$, IPC$) on 5+ internal systems in 30 min.

| Field | Value |
|-------|-------|
| **Match / Window** | `event_type = NETWORK_CONNECTION`, port = 445, share = ADMIN$/C$/IPC$, match: `$src_ip` over `30m` |
| **Trigger Condition** | `count_distinct(dst_ip) >= 5` |
| **Risk Score** | 85 |
| **⚠ Tune / FP** | FP: SCCM, SolarWinds, PRTG, GPO-triggered SMB connections. |

### `lateral_movement_winrm` — 🟠 HIGH — T1021.006

**What It Detects:** WinRM (5985/5986) connections from one internal host to 3+ targets — remote PowerShell lateral movement.

| Field | Value |
|-------|-------|
| **Match / Window** | `event_type = NETWORK_CONNECTION`, port = 5985/5986, src = RFC1918, match: `$src_ip` over `1h` |
| **Trigger Condition** | `count_distinct(dst_ip) >= 3` |
| **Risk Score** | 80 |
| **⚠ Tune / FP** | Add user account context to identify compromised account chains. |

---

## Section 07 · Persistence Mechanisms

**MITRE ATT&CK:** T1053.005 / T1547.001 / T1543.003

### `persistence_scheduled_task` — 🟠 HIGH — T1053.005

**What It Detects:** Non-SYSTEM account creating a scheduled task via schtasks.exe /create.

| Field | Value |
|-------|-------|
| **Match / Window** | `event_type = PROCESS_LAUNCH`, process = schtasks.exe, command includes /create, NOT SYSTEM |
| **Trigger Condition** | `#task > 0` over `1h` |
| **Risk Score** | 70 |
| **⚠ Tune / FP** | FP: AV/EDR, endpoint management, patching tools. |

### `persistence_registry_run_key` — 🟠 HIGH — T1547.001

**What It Detects:** Registry Run/RunOnce/RunServices key modified — common persistence mechanism.

| Field | Value |
|-------|-------|
| **Match / Window** | `event_type = REGISTRY_MODIFICATION`, key matches Run/RunOnce/RunServices |
| **Trigger Condition** | `#reg > 0` over `1h` |
| **Risk Score** | 75 |
| **⚠ Tune / FP** | FP: legitimate software installers. Correlate with installation change tickets. |

### `persistence_suspicious_service` — 🟠 HIGH — T1543.003

**What It Detects:** New Windows service created with binary path outside System32 or Program Files.

| Field | Value |
|-------|-------|
| **Match / Window** | `event_type = PROCESS_LAUNCH`, process = sc.exe, command includes create, path NOT standard |
| **Trigger Condition** | `#svc > 0` over `1h` |
| **Risk Score** | 80 |
| **⚠ Tune / FP** | Build approved service binary path allow-list. |

---

## Section 08 · Phishing Indicators

**MITRE ATT&CK:** T1566.001 / T1566.002 / T1598

### `phishing_attachment_execution` — 🔴 CRITICAL — T1566.001

**What It Detects:** Suspicious email attachment (.exe/.js/.ps1/.lnk etc.) delivered AND executed from Temp/Downloads within 15 min.

| Field | Value |
|-------|-------|
| **Match / Window** | `EMAIL_TRANSACTION` with suspicious extensions + `PROCESS_LAUNCH` from Temp/Downloads, exec within 900s |
| **Trigger Condition** | `#email > 0 AND #exec > 0` |
| **Risk Score** | 95 |
| **⚠ Tune / FP** | FP: new SaaS onboarding, URL shortener redirects. |

### `phishing_new_domain_click` — 🟠 HIGH — T1566.002

**What It Detects:** User navigates to domain registered <30 days ago via email client link.

| Field | Value |
|-------|-------|
| **Match / Window** | `event_type = NETWORK_HTTP`, domain creation < 30 days, referral = webmail |
| **Trigger Condition** | `#click > 0` over `1h` |
| **Risk Score** | 80 |
| **⚠ Tune / FP** | FP: new SaaS vendors, legitimate marketing redirects. |

### `phishing_credential_harvest` — 🟠 HIGH — T1598

**What It Detects:** HTTP POST to non-corporate domain with credential-related URL keywords (login/signin/auth/verify/password).

| Field | Value |
|-------|-------|
| **Match / Window** | `event_type = NETWORK_HTTP`, method = POST, target NOT corporate, URL path matches auth keywords |
| **Trigger Condition** | `#post > 0` over `1h` |
| **Risk Score** | 85 |
| **⚠ Tune / FP** | ⚡ Replace example.com with actual corporate domains. |

---

## Section 09 · Privilege Escalation

**MITRE ATT&CK:** T1068 / T1548.002 / T1134 / T1078.002

### `privesc_uac_bypass` — 🔴 CRITICAL — T1548.002

**What It Detects:** Auto-elevating Windows binary (fodhelper/eventvwr/computerdefaults/sdclt) spawning unexpected child process — UAC bypass.

| Field | Value |
|-------|-------|
| **Match / Window** | `event_type = PROCESS_LAUNCH`, parent = auto-elevating binary, child NOT mmc/control |
| **Trigger Condition** | `#proc > 0` over `5m` |
| **Risk Score** | 95 |
| **⚠ Tune / FP** | Very low FP. Any hit warrants immediate investigation. |

### `privesc_sensitive_privilege` — 🟠 HIGH — T1134

**What It Detects:** Event 4672 (special privileges assigned) for non-default service accounts.

| Field | Value |
|-------|-------|
| **Match / Window** | `event_type = USER_RESOURCE_ACCESS`, event 4672, NOT SYSTEM/LOCAL SERVICE/NETWORK SERVICE |
| **Trigger Condition** | `#priv > 0` over `1h` |
| **Risk Score** | 75 |
| **⚠ Tune / FP** | FP: domain join operations, SeImpersonatePrivilege for IIS. |

### `privesc_admin_group_addition` — 🔴 CRITICAL — T1078.002

**What It Detects:** Account added to Domain Admins, Enterprise Admins, Schema Admins, or Backup Operators.

| Field | Value |
|-------|-------|
| **Match / Window** | `event_type = GROUP_MODIFICATION`, target = privileged groups |
| **Trigger Condition** | `#add > 0` over `1h` |
| **Risk Score** | 90 |
| **⚠ Tune / FP** | Add org-specific privileged groups. Must correlate with change ticket. |

---

## Section 10 · Reconnaissance Detection

**MITRE ATT&CK:** T1595 / T1590 / T1589

### `recon_port_scan` — 🟡 MEDIUM — T1595

**What It Detects:** Single source connecting to >50 distinct ports with small payloads (<200 bytes) in 10 min.

| Field | Value |
|-------|-------|
| **Match / Window** | `event_type = NETWORK_CONNECTION`, sent_bytes < 200, match: `$src_ip` over `10m` |
| **Trigger Condition** | `count_distinct(port) > 50` |
| **Risk Score** | 65 |
| **⚠ Tune / FP** | FP: SCCM inventory, vulnerability scanners, Nessus. |

### `recon_network_sweep` — 🟡 MEDIUM — T1590

**What It Detects:** Internal host scanning 30+ distinct IPs on common ports in 15 min.

| Field | Value |
|-------|-------|
| **Match / Window** | `event_type = NETWORK_CONNECTION`, src = RFC1918, common ports, match: `$src_ip` over `15m` |
| **Trigger Condition** | `count_distinct(dst_ip) > 30` |
| **Risk Score** | 70 |
| **⚠ Tune / FP** | FP: SCCM, DNS/DHCP servers, identity sync tools. |

### `recon_ad_enumeration` — 🟡 MEDIUM — T1589

**What It Detects:** Non-DC host sending >100 LDAP queries (port 389) in 30 min — AD enumeration.

| Field | Value |
|-------|-------|
| **Match / Window** | `event_type = NETWORK_CONNECTION`, port = 389, src NOT DC, match: `$src_ip` over `30m` |
| **Trigger Condition** | `#ldap > 100` |
| **Risk Score** | 70 |
| **⚠ Tune / FP** | Exclude SIEM agents, identity management tools, LDAP-heavy apps. |

---

## Section 11 · Forwarding Rule Abuse ★ NEW

**MITRE ATT&CK:** T1114.003

### `forwarding_rule_inbox_creation` — 🟠 HIGH — T1114.003

**What It Detects:** Mailbox inbox rule created with ForwardTo/RedirectTo action (O365 / Google Workspace audit log).

| Field | Value |
|-------|-------|
| **Match / Window** | `event_type = EMAIL_UNCATEGORIZED`, event = New-InboxRule/Set-InboxRule, description matches forward/redirect |
| **Trigger Condition** | `#rule > 0` over `1h` |
| **Risk Score** | 85 |
| **⚠ Tune / FP** | Exclude IT admins managing shared mailboxes and migration tools. |

### `forwarding_rule_powershell_creation` — 🔴 CRITICAL — T1114.003

**What It Detects:** PowerShell command creating Exchange forwarding: New-InboxRule, Set-Mailbox -ForwardingSmtpAddress, Set-TransportRule.

| Field | Value |
|-------|-------|
| **Match / Window** | `event_type = PROCESS_LAUNCH`, command matches PowerShell forwarding cmdlets |
| **Trigger Condition** | `#cmd > 0` over `1h` |
| **Risk Score** | 95 |
| **⚠ Tune / FP** | Extremely low FP. PowerShell-created forwarding rules are almost always malicious. |

### `forwarding_rule_external_domain` — 🟠 HIGH — T1114.003

**What It Detects:** Inbox rule configured to forward to non-corporate domain.

| Field | Value |
|-------|-------|
| **Match / Window** | `event_type = EMAIL_UNCATEGORIZED`, action = rule creation, target NOT corporate domain |
| **Trigger Condition** | `#fwd > 0` over `24h` |
| **Risk Score** | 90 |
| **⚠ Tune / FP** | ⚡ Replace @corp.example.com with your actual domains. Allow-list legal/auditor addresses. |

### `forwarding_rule_bulk_modification` — 🔴 CRITICAL — T1114.003

**What It Detects:** Single actor modifying forwarding rules on 3+ mailboxes in 1 hour — automated compromise or insider threat.

| Field | Value |
|-------|-------|
| **Match / Window** | `event_type = EMAIL_UNCATEGORIZED`, actor modifying multiple target mailboxes |
| **Trigger Condition** | `count_distinct(target_mailbox) >= 3` over `1h` |
| **Risk Score** | 95 |
| **⚠ Tune / FP** | FP: HR offboarding, compliance archival setup. Should still be verified. |

---

## Section 12 · Impossible Travel Detection ★ NEW

**MITRE ATT&CK:** T1078 / T1078.004

### `impossible_travel_successive_logins` — 🟠 HIGH — T1078

**What It Detects:** Same user logs in from two different countries within 2 hours.

| Field | Value |
|-------|-------|
| **Match / Window** | 2× `USER_LOGIN` ALLOW, same user, different country, different IP, match over `2h` |
| **Trigger Condition** | `#login1 > 0 AND #login2 > 0`, login2 within 7200s of login1 |
| **Risk Score** | 85 |
| **⚠ Tune / FP** | Exclude VPN egress IPs and cloud proxy IPs (Zscaler, Cloudflare WARP). |

### `impossible_travel_city_level` — 🟠 HIGH — T1078

**What It Detects:** Same user logs in from two different cities within 30 min.

| Field | Value |
|-------|-------|
| **Match / Window** | 2× `USER_LOGIN` ALLOW, same user, different city, different IP, match over `1h` |
| **Trigger Condition** | `#login1 > 0 AND #login2 > 0`, login2 within 1800s of login1 |
| **Risk Score** | 80 |
| **⚠ Tune / FP** | FP: VPN split-tunneling, mobile users on cellular networks. |

### `impossible_travel_vpn_bypass` — 🔴 CRITICAL — T1078.004

**What It Detects:** Corporate VPN login and foreign country login from same user within 5 min — active credential compromise.

| Field | Value |
|-------|-------|
| **Match / Window** | VPN login ($home_country) + foreign login ($foreign_country), same user, within 300s |
| **Trigger Condition** | `#vpn > 0 AND #foreign > 0` |
| **Risk Score** | 95 |
| **⚠ Tune / FP** | FP: split-tunneling where personal/corporate traffic egress separately. |

### `impossible_travel_new_country` — 🟡 MEDIUM — T1078

**What It Detects:** Successful login from a country with no prior login history for this user.

| Field | Value |
|-------|-------|
| **Match / Window** | `event_type = USER_LOGIN`, ALLOW, src IP NOT in known VPN CIDR, match over `24h` |
| **Trigger Condition** | `#login > 0` |
| **Risk Score** | 60 |
| **⚠ Tune / FP** | ⚡ Replace 198.51.100.0/24 with your actual VPN egress CIDRs. |

---

## Section 13 · Spam Bot Detection ★ NEW

**MITRE ATT&CK:** T1566 / T1071 / T1078

### `spam_bot_high_volume_outbound` — 🟠 HIGH — T1078

**What It Detects:** Account sending >100 outbound emails in 1 hour.

| Field | Value |
|-------|-------|
| **Match / Window** | `event_type = EMAIL_TRANSACTION`, direction = OUTBOUND, match: `$sender` over `1h` |
| **Trigger Condition** | `#email > 100` |
| **Risk Score** | 80 |
| **⚠ Tune / FP** | Adjust per role — marketing/sales may send more. Exclude distribution lists. |

### `spam_bot_many_unique_recipients` — 🟠 HIGH — T1566

**What It Detects:** Account emailing 50+ unique external recipients in 4 hours.

| Field | Value |
|-------|-------|
| **Match / Window** | `event_type = EMAIL_TRANSACTION`, direction = OUTBOUND, external recipients, match: `$sender` over `4h` |
| **Trigger Condition** | `count_distinct(recipient) > 50` |
| **Risk Score** | 85 |
| **⚠ Tune / FP** | ⚡ Replace @corp.example.com with your domain. Exclude marketing platform accounts. |

### `spam_bot_rapid_api_sends` — 🔴 CRITICAL — T1071

**What It Detects:** 50+ emails sent via SMTP/API relay in 10 min — machine speed, not human.

| Field | Value |
|-------|-------|
| **Match / Window** | `event_type = EMAIL_TRANSACTION`, direction = OUTBOUND, protocol = SMTP/API, match: `$sender` over `10m` |
| **Trigger Condition** | `#send > 50` |
| **Risk Score** | 90 |
| **⚠ Tune / FP** | FP: legitimate email automation (ticketing/alert systems). Exclude known service accounts. |

### `spam_bot_bounced_email_spike` — 🟠 HIGH — T1078

**What It Detects:** 20+ NDR/bounce messages for one sender in 1 hour.

| Field | Value |
|-------|-------|
| **Match / Window** | `event_type = EMAIL_TRANSACTION`, description matches bounce/NDR, match: `$sender` over `1h` |
| **Trigger Condition** | `#bounce > 20` |
| **Risk Score** | 80 |
| **⚠ Tune / FP** | Correlate with auth anomalies: new IP + high volume + bounces = compromised account. |

---

## Section 14 · Email Spoofing Detection ★ NEW

**MITRE ATT&CK:** T1566.001 / T1566.002 / T1534

### `spoofing_spf_dkim_dmarc_failure` — 🟠 HIGH — T1566.001

**What It Detects:** Inbound email failing SPF, DKIM, or DMARC authentication checks.

| Field | Value |
|-------|-------|
| **Match / Window** | `event_type = EMAIL_TRANSACTION`, direction = INBOUND, description matches auth failures |
| **Trigger Condition** | `#email > 0` over `1h` |
| **Risk Score** | 75 |
| **⚠ Tune / FP** | FP: SPF softfail can be legitimate for some third-party senders. |

### `spoofing_display_name_impersonation` — 🔴 CRITICAL — T1534

**What It Detects:** Inbound email where display name matches VIP/executive but sending domain is external — CEO fraud/BEC.

| Field | Value |
|-------|-------|
| **Match / Window** | `event_type = EMAIL_TRANSACTION`, INBOUND, display name = VIP, domain NOT corporate |
| **Trigger Condition** | `#email > 0` over `24h` |
| **Risk Score** | 90 |
| **⚠ Tune / FP** | ⚡ Replace executive names and corporate domain with actual values. |

### `spoofing_lookalike_domain` — 🟠 HIGH — T1566.002

**What It Detects:** Inbound email from domain that typosquats your corporate domain.

| Field | Value |
|-------|-------|
| **Match / Window** | `event_type = EMAIL_TRANSACTION`, INBOUND, sender domain matches typosquat regex |
| **Trigger Condition** | `#email > 0` over `24h` |
| **Risk Score** | 85 |
| **⚠ Tune / FP** | ⚡ Generate lookalike regex using dnstwist for your specific domain. |

### `spoofing_reply_to_mismatch` — 🟡 MEDIUM — T1566.002

**What It Detects:** External inbound email with Reply-To differing from From domain — attacker-controlled reply interception.

| Field | Value |
|-------|-------|
| **Match / Window** | `event_type = EMAIL_TRANSACTION`, INBOUND, Reply-To present, sender NOT corporate |
| **Trigger Condition** | `#email > 0` over `24h` |
| **Risk Score** | 70 |
| **⚠ Tune / FP** | FP: newsletter services legitimately use different Reply-To. |

---

## Section 15 · Anomalous Process Execution ★ NEW

**MITRE ATT&CK:** T1059 / T1036 / T1218 / T1204

### `anomalous_parent_child_process` — 🟠 HIGH — T1059

**What It Detects:** Unusual parent→child process relationship: Office apps spawning cmd/PowerShell/mshta, web services spawning shells, WMI spawning interpreters.

| Field | Value |
|-------|-------|
| **Match / Window** | `event_type = PROCESS_LAUNCH`, suspicious parent→child combos |
| **Trigger Condition** | `#proc > 0` over `1h` |
| **Risk Score** | 85 |
| **⚠ Tune / FP** | FP: IT automation (Ansible/Chef/Puppet) spawning cmd/PowerShell from services. |

### `anomalous_temp_directory_execution` — 🟠 HIGH — T1204

**What It Detects:** Binary executed from %TEMP%, AppData, Downloads, Desktop, Documents, or Public.

| Field | Value |
|-------|-------|
| **Match / Window** | `event_type = PROCESS_LAUNCH`, path matches staging paths, NOT DismHost/TiWorker |
| **Trigger Condition** | `#proc > 0` over `1h` |
| **Risk Score** | 75 |
| **⚠ Tune / FP** | FP: software installers, Chrome/Firefox/Zoom auto-updaters from AppData. |

### `anomalous_lolbin_abuse` — 🟠 HIGH — T1218

**What It Detects:** LOLBin executing suspicious operations: certutil downloading, mshta/rundll32 executing remote content, bitsadmin transferring files, wmic process create.

| Field | Value |
|-------|-------|
| **Match / Window** | `event_type = PROCESS_LAUNCH`, LOLBin + suspicious command-line args |
| **Trigger Condition** | `#lol > 0` over `1h` |
| **Risk Score** | 85 |
| **⚠ Tune / FP** | Expand LOLBin list from LOLBAS project (lolbas-project.github.io). |

### `anomalous_renamed_binary` — 🟠 HIGH — T1036

**What It Detects:** PE original filename does not match actual filename on disk — renamed tool evasion.

| Field | Value |
|-------|-------|
| **Match / Window** | `event_type = PROCESS_LAUNCH`, original PE name ≠ actual filename |
| **Trigger Condition** | `#proc > 0` over `1h` |
| **Risk Score** | 90 |
| **⚠ Tune / FP** | FP: some installers legitimately rename system utilities. Verify with hash. |

---

## Section 16 · Routine Threat Hunting ★ NEW

**MITRE ATT&CK:** T1053 / T1547 / T1105 / T1543 / T1574

### `hunting_new_scheduled_tasks` — 🟡 MEDIUM — T1053.005

**What It Detects:** [RUN DAILY] All scheduled tasks created in past 24h. Review for persistence/malware callbacks.

| Field | Value |
|-------|-------|
| **Match / Window** | `event_type = PROCESS_LAUNCH`, schtasks /create OR Register-ScheduledTask, match over `24h` |
| **Trigger Condition** | `#task > 0` |
| **Risk Score** | 50 |
| **⚠ Tune / FP** | Review daily — look for odd schedule times and unknown binaries. |

### `hunting_new_services_installed` — 🟡 MEDIUM — T1543.003

**What It Detects:** [RUN DAILY] New Windows services installed in past 24h via sc.exe create or New-Service.

| Field | Value |
|-------|-------|
| **Match / Window** | `event_type = PROCESS_LAUNCH`, sc.exe create OR New-Service, match over `24h` |
| **Trigger Condition** | `#svc > 0` |
| **Risk Score** | 55 |
| **⚠ Tune / FP** | Maintain a baseline of approved services. Flag non-standard binary paths. |

### `hunting_startup_folder_modifications` — 🟡 MEDIUM — T1547.001

**What It Detects:** [RUN DAILY] Files written to Windows Startup folder in past 24h.

| Field | Value |
|-------|-------|
| **Match / Window** | `event_type = FILE_CREATION`, path matches Startup folder, match over `24h` |
| **Trigger Condition** | `#file > 0` |
| **Risk Score** | 70 |
| **⚠ Tune / FP** | FP: software deployment tools during installation. Correlate with change management. |

### `hunting_rare_process_execution` — 🟢 LOW — T1059

**What It Detects:** [RUN WEEKLY] Processes executed on fewer than 3 hosts in 7 days.

| Field | Value |
|-------|-------|
| **Match / Window** | `event_type = PROCESS_LAUNCH`, path NOT System32/ProgramFiles, match over `7d` |
| **Trigger Condition** | `count_distinct(hostname) < 3` |
| **Risk Score** | 40 |
| **⚠ Tune / FP** | Start with high-confidence non-system paths. Feed results to case management. |

### `hunting_unusual_outbound_connections` — 🟡 MEDIUM — T1105

**What It Detects:** [RUN DAILY] External IPs contacted by fewer than 3 internal hosts in 24h.

| Field | Value |
|-------|-------|
| **Match / Window** | `event_type = NETWORK_CONNECTION`, src = RFC1918, dst = external, match over `24h` |
| **Trigger Condition** | `count_distinct(src_ip) < 3` |
| **Risk Score** | 45 |
| **⚠ Tune / FP** | Integrate with threat intel IP feeds for automated reputation scoring. |

### `hunting_dll_sideloading_candidates` — 🟡 MEDIUM — T1574.002

**What It Detects:** [RUN WEEKLY] DLLs loaded from non-standard paths by known sideloading-vulnerable apps.

| Field | Value |
|-------|-------|
| **Match / Window** | `event_type = FILE_READ`, .dll NOT in Windows/ProgramFiles, loaded by vulnerable apps, match over `7d` |
| **Trigger Condition** | `#load > 0` |
| **Risk Score** | 65 |
| **⚠ Tune / FP** | FP: portable applications, legitimate plugin DLLs. Verify with hash. |

### `hunting_unsigned_executables` — 🟢 LOW — T1036

**What It Detects:** [RUN WEEKLY] Unsigned or expired/revoked-signature executables in non-dev environments.

| Field | Value |
|-------|-------|
| **Match / Window** | `event_type = PROCESS_LAUNCH`, signature = false or untrusted, match over `7d` |
| **Trigger Condition** | `#proc > 0` |
| **Risk Score** | 35 |
| **⚠ Tune / FP** | FP: developer machines. Suppress for known dev hosts. |

---

## MITRE ATT&CK Coverage Matrix

| Tactic | Techniques Covered |
|--------|-------------------|
| Initial Access | T1566.001, T1566.002, T1598 |
| Execution | T1059, T1204, T1218 |
| Persistence | T1053.005, T1547.001, T1543.003, T1574.002 |
| Privilege Escalation | T1068, T1548.002, T1134, T1078.002 |
| Defense Evasion | T1070.001, T1562.001, T1036.005, T1027 |
| Credential Access | T1003.001, T1558.003, T1555, T1552 |
| Discovery | T1595, T1592, T1589, T1590 |
| Lateral Movement | T1021.001, T1021.002, T1021.006, T1570 |
| Collection | T1114.003 |
| Command & Control | T1071.001, T1071.004, T1573, T1105 |
| Exfiltration | T1048.001, T1048.002, T1567, T1041 |
| Impact / Identity | T1078, T1078.004 (cross-tactic) |

---

**Author:** Christian M. Njodzela · [github.com/njodzela/soc-query-library](https://github.com/njodzela/soc-query-library) · MIT License · © 2026
