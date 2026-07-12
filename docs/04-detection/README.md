# Level 4 — Detection

> **Prerequisite:** Levels 1–3 complete. Detection assumes you've already closed the easy paths — otherwise you're just watching attackers walk through open doors.

Prevention fails. Not always, but often enough that a mature domain must assume compromise and be able to *see* it. Levels 1–3 raise the cost of attack; Level 4 ensures that when someone pays that cost, you find out — ideally while they're still in the early, recoverable stages rather than reading about it in a ransom note.

This level adds no new locks. It adds **eyes**: the audit policy that generates the right events, the specific Event IDs that signal the attacks from earlier levels, host telemetry via Sysmon, and honeypot accounts that turn an attacker's own reconnaissance against them.

A critical framing: **default Windows auditing is not enough.** Many of the events that reveal AD attacks are off by default or too coarse. You must deliberately configure advanced audit policy, then know which of the resulting events actually matter — because the volume is enormous and drowning in noise is the same as seeing nothing.

---

## Table of contents

- [4.1 Advanced Audit Policy — generating the right events](#41-advanced-audit-policy)
- [4.2 The critical Event IDs — what to actually alert on](#42-the-critical-event-ids)
- [4.3 Sysmon — host telemetry the OS doesn't give you](#43-sysmon)
- [4.4 Honeypot accounts — detection that attackers trigger themselves](#44-honeypot-accounts)
- [4.5 Getting events off the box — central collection](#45-central-collection)

---

## 4.1 Advanced Audit Policy

### Why the default isn't enough

The legacy audit settings (the nine basic categories) are too blunt for threat detection. Windows has a much finer **Advanced Audit Policy** with ~60 subcategories, letting you turn on exactly the signal you need without generating unmanageable noise. But most of the security-relevant subcategories — Kerberos ticket operations, directory service changes, detailed process creation — are **not enabled by default**.

The strategy: enable the subcategories that reveal the attacks you hardened against in Levels 1–3, at the tier where they occur (Kerberos events on DCs, process/logon events on all hosts). Configure this via GPO so it applies consistently and can't drift.

### Deploy

**GPO path:** `Computer Configuration > Policies > Windows Settings > Security Settings > Advanced Audit Policy Configuration > Audit Policies`

Key subcategories to enable (Success and Failure unless noted):

Account Logon:
- *Audit Credential Validation* — NTLM auth attempts (4776)
- *Audit Kerberos Authentication Service* — TGT requests (4768), catches AS-REP roasting
- *Audit Kerberos Service Ticket Operations* — TGS requests (4769), catches kerberoasting

Account Management:
- *Audit Security Group Management* — group membership changes (4728/4732/4756), catches privilege escalation
- *Audit User Account Management* — account creation/changes (4720/4738)

DS Access:
- *Audit Directory Service Changes* — object modifications (5136), catches ACL tampering
- *Audit Directory Service Access* — object access (4662), catches DCSync

Logon/Logoff:
- *Audit Logon* — (4624/4625), catches lateral movement and password spraying
- *Audit Special Logon* — privileged logon (4672)

Detailed Tracking:
- *Audit Process Creation* — (4688) — **also enable command-line capture** (see below)

Enable command-line auditing so 4688 events include the full command line:
`Computer Configuration > Administrative Templates > System > Audit Process Creation > Include command line in process creation events` → **Enabled**.

**Set an adequate Security log size** so events aren't overwritten before collection. Default (often 20 MB) is far too small on a DC. Set to at least a few hundred MB, or forward events centrally (4.5).

### Verify

```powershell
# Confirm effective audit policy on a DC
auditpol /get /category:* | Select-String 'Kerberos|Directory Service|Credential Validation|Logon'

# Confirm command-line capture is on
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' `
    -Name ProcessCreationIncludeCmdLine_Enabled -ErrorAction SilentlyContinue
```

---

## 4.2 The critical Event IDs

Enabling auditing generates millions of events. Detection is knowing which handful signal the attacks from earlier levels. These are the ones worth building alerts on, each tied to a technique you've already studied.

### Credential and Kerberos attacks

- **4769** (Kerberos service ticket requested) — the signal for **kerberoasting** (Level 3.1). One user account requesting service tickets for *many* SPNs in a short window, especially with **RC4 encryption type (0x17)** requested, is the classic kerberoasting fingerprint. Alert on: high volume of 4769 with encryption type 0x17 from a single account.
- **4768** (Kerberos TGT requested) — reveals **AS-REP roasting** (Level 3.3) when pre-auth type is 0 (no pre-authentication), and reveals password-spraying patterns.
- **4776** (credential validation, NTLM) — a burst of failures across many accounts from one source is **password spraying**; NTLM use by an account that should be Kerberos-only (Protected Users, Level 2.2) is an anomaly worth flagging.

### Privilege escalation

- **4728 / 4732 / 4756** (member added to a global / local / universal security group) — **alert immediately** when the group is privileged (Domain Admins, Enterprise Admins, Schema Admins). Legitimate additions to these groups are rare and planned; an unexpected one is an incident.
- **4672** (special privileges assigned at logon) — a logon that was granted admin-equivalent privileges. Correlate with *where* it happened — a Tier 0 privilege on a Tier 2 machine is a red flag (Level 5).

### Directory attacks

- **4662** (operation on an AD object) — the signal for **DCSync**. When a non-DC account requests the replication rights GUIDs (`DS-Replication-Get-Changes` / `-All`, GUIDs `1131f6aa-...` and `1131f6ad-...`), someone is attempting to replicate password hashes. **A DCSync from anything other than a Domain Controller is almost always an attack.** This is one of the highest-fidelity alerts you can build.
- **5136** (directory object modified) — catches **ACL tampering** (Level 3.5). An attacker granting themselves rights (WriteDacl abuse) shows up here. Alert on modifications to the ACLs of privileged objects.

### Persistence and forging

- **4738** (user account changed) and **4724** (password reset attempt) on privileged accounts.
- Anomalous **4624** (logon) — a Domain Admin logon to a workstation should be *impossible* after Level 2.6; if you see one, either the control failed or you're watching an attack.

**The discipline:** you cannot manually watch these. Build alerts (in your SIEM, or even scheduled PowerShell in a small environment) for the high-fidelity ones — DCSync from a non-DC (4662), privileged group changes (4728/4732), kerberoasting bursts (4769 + RC4). Start with those four; they have low false-positive rates and catch the crown-jewel attacks.

### A ready-made hunt

```powershell
# Kerberoasting hunt: accounts requesting many RC4 service tickets
Get-WinEvent -ComputerName DC01 -FilterHashtable @{LogName='Security'; Id=4769} -MaxEvents 1000 |
    Where-Object { $_.Message -match 'Ticket Encryption Type:\s+0x17' } |
    ForEach-Object {
        if ($_.Message -match 'Account Name:\s+(\S+)') { $matches[1] }
    } | Group-Object | Where-Object Count -gt 10 | Sort-Object Count -Descending
# An account with dozens of RC4 TGS requests is likely being used to kerberoast.
```

---

## 4.3 Sysmon

### What the OS doesn't tell you

Windows' built-in auditing is good for authentication and directory events but weak on **host behavior** — process ancestry, network connections, file and registry changes made by malware, credential-dumping tool signatures. **Sysmon** (System Monitor, a free Sysinternals tool) fills that gap. It runs as a driver+service and logs richly detailed events to its own log, driven by a configuration file that tells it what to capture and what to ignore.

Why it matters for AD defense specifically: the attacks from Levels 1–3 are executed by *tools* running on hosts — Mimikatz dumping LSASS, Rubeus requesting tickets, SharpHound collecting the graph, Impacket relaying. Sysmon can catch their behavioral signatures:
- **Event 1** (process creation) with full command line and hashes — catches known offensive tooling and suspicious parent/child chains (e.g., Office spawning PowerShell).
- **Event 10** (process access) targeting **lsass.exe** — the signature of credential dumping. Very high fidelity: legitimate processes rarely open a handle to LSASS memory.
- **Event 3** (network connection) — catches beaconing and lateral-movement connections.
- **Event 8** (CreateRemoteThread) and **Event 11** (file creation) — injection and dropper behavior.

### Deploy

```powershell
# Download Sysmon from Sysinternals. Use a curated config as your starting point
# (the widely-used SwiftOnSecurity/sysmon-config or Olaf Hartong's modular config)
# rather than an empty one — a good config is the difference between signal and noise.

sysmon64.exe -accepteula -i sysmonconfig.xml

# Update the config later without reinstalling:
sysmon64.exe -c sysmonconfig.xml
```

Deploy the same config fleet-wide via GPO or your management tool so telemetry is consistent. The LSASS-access rule (Event 10 → lsass.exe) alone justifies the deployment — it's one of the most reliable credential-theft detections available.

### Verify

```powershell
# Confirm Sysmon is running and logging
Get-Service Sysmon64 | Select-Object Status
Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents 5 |
    Select-Object TimeCreated, Id, Message

# Hunt for LSASS access (potential credential dumping)
Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -FilterXPath "*[System[EventID=10]]" -MaxEvents 50 |
    Where-Object { $_.Message -match 'lsass\.exe' }
```

---

## 4.4 Honeypot accounts

### Detection that attackers trigger for you

A honeypot (or "canary") account is a decoy: a user account crafted to look attractive to an attacker but never used by any legitimate person or service. Because *nothing legitimate ever touches it*, **any** interaction with it is, by definition, suspicious — which gives you an extremely low false-positive alert.

The elegance is that it turns the attacker's own methodology against them. An attacker's early moves include enumerating the domain and looking for weak, privileged, or kerberoastable accounts. So you build a honeypot that is exactly what they're hunting for:

- Give it an **old-looking, privileged-seeming name** (e.g., `svc_backup_admin`, `sqladmin_old`) and a description suggesting access.
- Make it a member of a group that looks valuable but grants nothing real, or leave it looking over-privileged while actually having no usable rights.
- Set an **SPN** on it so it appears in kerberoasting enumeration — and give it a genuinely strong random password so it can't actually be cracked.
- Set a plausible-looking old `PasswordLastSet`.
- **Never log in with it. Never use it for anything.**

Then alert on **any** authentication event referencing it — a **4768/4769** for the honeypot account means someone requested a ticket for it, which no legitimate process ever does. That's an attacker performing kerberoasting or credential access, caught in the reconnaissance phase, before they've cracked anything.

### Deploy

```powershell
# Create the honeypot to look like an attractive, kerberoastable service admin
New-ADUser -Name 'svc_sql_backup' -SamAccountName 'svc_sql_backup' `
    -Description 'SQL backup service account' `
    -AccountPassword (ConvertTo-SecureString ([System.Web.Security.Membership]::GeneratePassword(40,10)) -AsPlainText -Force) `
    -Enabled $true -PasswordNeverExpires $true

# Add an SPN so it shows up in kerberoasting scans
Set-ADUser 'svc_sql_backup' -ServicePrincipalNames @{Add='MSSQLSvc/decoy.corp.lab:1433'}

# Make it look old and privileged (appearance only — grant no real rights)
# Consider nesting into a decoy group; do NOT put it in real privileged groups.
```

### Verify / alert

```powershell
# Any Kerberos ticket request for the honeypot is an alert. There should be ZERO
# under normal operation — a single hit is high-signal.
Get-WinEvent -ComputerName DC01 -FilterHashtable @{LogName='Security'; Id=4768,4769} -MaxEvents 2000 |
    Where-Object { $_.Message -match 'svc_sql_backup' } |
    Select-Object TimeCreated, Id, @{n='Detail';e={($_.Message -split "`n" | Select-String 'Account Name|Client Address') -join ' | '}}
```

Wire this into a scheduled task or SIEM rule that fires on the first hit. It is one of the cheapest, highest-fidelity detections you can deploy.

---

## 4.5 Central collection

Events sitting in each machine's local log are useless if that machine gets wiped by ransomware or cleaned by an attacker. You need them **off the box** and centralized:

- **Windows Event Forwarding (WEF)** — built into Windows, free. Configure DCs and key servers to forward the critical Event IDs to a collector. No agent required.
- **A SIEM** (commercial or open-source like the Elastic stack, Wazuh) — ingests WEF/Sysmon output, correlates across hosts, and runs the alert rules. This is where the honeypot and DCSync alerts actually fire.

Even in a small environment, forwarding to a single hardened collector means an attacker who clears local logs hasn't erased the evidence. Log integrity is part of detection.

---

## Level 4 exit criteria

- [ ] Advanced audit policy deployed via GPO; command-line capture on; Security log sized adequately.
- [ ] Alerts built for the high-fidelity events: DCSync from non-DC (4662), privileged group changes (4728/4732), kerberoasting bursts (4769+RC4), honeypot ticket requests.
- [ ] Sysmon deployed fleet-wide with a curated config; LSASS-access detection confirmed.
- [ ] At least one honeypot account live and alerting.
- [ ] Critical events forwarded off-host to a central collector.

This is the last level before the destination. Proceed to [Level 5 — Tiering Model](../05-tiering-model/README.md).

---

## References

- [Microsoft — Advanced security audit policy settings](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/advanced-security-audit-policy-settings)
- [Microsoft — Events to monitor (Appendix L)](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/appendix-l--events-to-monitor)
- [Sysmon — Sysinternals](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [Microsoft — Windows Event Forwarding](https://learn.microsoft.com/en-us/windows/security/threat-protection/use-windows-event-forwarding-to-assist-in-intrusion-detection)
