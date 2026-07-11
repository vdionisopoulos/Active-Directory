# Level 1 — Baseline Hygiene

> **Prerequisite:** Level 0 (assessment) complete — you have a PingCastle or Purple Knight report and know your starting score.

This is the least glamorous level and the most important one. The overwhelming majority of real-world AD compromises don't start with a zero-day — they start with an unpatched DC, a Domain Admin browsing the web, or SMBv1 still enabled from 2015. Fix these before touching anything more advanced.

Nothing here requires a budget. All of it requires discipline.

---

## 1.1 Patch domain controllers — and prove backups restore

**Attack it blocks:** wormable RCE (ZeroLogon CVE-2020-1472, PrintNightmare CVE-2021-34527, and the steady stream that follows), plus ransomware that targets DCs specifically.

- Patch DCs on a defined cadence. DCs are Tier 0 — treat their patch SLA as tighter than member servers, not looser.
- Maintain **system state backups** of at least two DCs, stored offline / immutable so ransomware can't encrypt them.
- **Test a restore.** An untested backup is a hope, not a control. Do an authoritative restore drill in a lab at least once. If you have never restored a DC, you do not have DC backups — you have files.

**Verify:**
```powershell
# Last successful backup timestamp per DC
Get-WinEvent -LogName 'Microsoft-Windows-Backup' -MaxEvents 20 |
    Where-Object Id -eq 4 | Select-Object TimeCreated, Message

# Confirm ZeroLogon enforcement mode is on (DCs reject vulnerable Netlogon)
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' `
    -Name FullSecureChannelProtection -ErrorAction SilentlyContinue
```

---

## 1.2 Stop using Domain Admin for daily work

**Attack it blocks:** credential theft. If a Domain Admin logs on to a workstation or member server, their credentials are cached in LSASS on that machine. One Mimikatz run on a compromised endpoint = full domain.

- Admins get **two accounts**: a normal account for email/browsing, and a separate privileged account used only on secured admin hosts.
- Privileged accounts **never** log on to workstations or general-purpose servers. This is the seed of the tiering model you build in Level 5 — start the habit now.
- Remove standing membership from Domain Admins / Enterprise Admins for anyone who doesn't strictly need it. These groups should be nearly empty day-to-day.

**Verify:**
```powershell
Get-ADGroupMember 'Domain Admins'  | Select-Object name, distinguishedName
Get-ADGroupMember 'Enterprise Admins' | Select-Object name, distinguishedName
# Anyone on this list who logs on to a laptop is a domain-wide liability.
```

---

## 1.3 Kill legacy authentication protocols

**Attack it blocks:** trivial credential cracking (LM/NTLMv1 hashes fall in minutes) and SMBv1 wormable exploits (EternalBlue).

- Disable **SMBv1** everywhere. It has no legitimate use in a modern domain.
- Refuse **LM and NTLMv1**. Set LmCompatibilityLevel to 5 (send NTLMv2 only, refuse LM & NTLM) via GPO.
- Begin **auditing NTLM** usage so you can plan its eventual restriction — don't block it blind, you'll break things you didn't know depended on it.

**Verify:**
```powershell
# SMBv1 server component — should be Disabled/Absent
Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol

# LmCompatibilityLevel — target value is 5
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name LmCompatibilityLevel
```

**GPO path:** `Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > Security Options`
- *Network security: LAN Manager authentication level* → **Send NTLMv2 response only. Refuse LM & NTLM**
- *Network security: Do not store LAN Manager hash value on next password change* → **Enabled**

---

## 1.4 Harden the Print Spooler on DCs

**Attack it blocks:** PrintNightmare and the MS-RPRN "Printer Bug" coercion technique used to relay DC authentication.

- The Print Spooler service has **no reason to run on a domain controller**. Disable it.

**Verify:**
```powershell
Invoke-Command -ComputerName (Get-ADDomainController -Filter *).HostName {
    Get-Service Spooler | Select-Object MachineName, Status, StartType
}
# Target: Status Stopped, StartType Disabled on every DC.
```

---

## 1.5 Baseline account hygiene

**Attack it blocks:** password spraying and stale-account abuse.

- Enforce a modern password policy (length over rotation-frequency; align with current NIST guidance).
- Find and disable **stale accounts** (no logon in 90+ days) and accounts with **password-never-expires** that aren't managed service accounts.
- Audit accounts with **PasswordNotRequired** or reversible encryption — both should be zero.

**Verify:**
```powershell
# Stale enabled accounts
$cutoff = (Get-Date).AddDays(-90)
Get-ADUser -Filter {Enabled -eq $true} -Properties LastLogonTimestamp |
    Where-Object { [datetime]::FromFileTime($_.LastLogonTimestamp) -lt $cutoff } |
    Select-Object Name, SamAccountName

# Dangerous flags
Get-ADUser -Filter 'PasswordNotRequired -eq $true' -Properties PasswordNotRequired |
    Select-Object Name, SamAccountName
```

---

## Level 1 exit criteria

You are done with Level 1 when:

- [ ] All DCs are on a defined patch cadence, with a **tested** restore under your belt.
- [ ] No privileged account logs on to workstations or general-purpose servers.
- [ ] SMBv1 is gone; LM/NTLMv1 are refused domain-wide.
- [ ] Print Spooler is disabled on every DC.
- [ ] Stale and misconfigured accounts are cleaned up.

Re-run your Level 0 assessment. The score should move measurably. Then proceed to [Level 2 — Quick Wins](../02-quick-wins/README.md).
