# Level 2 — Quick Wins

> **Prerequisite:** Level 1 (baseline hygiene) complete. In particular, no privileged account should be logging on to workstations, and legacy protocols (SMBv1, LM/NTLMv1) should already be gone.

Level 1 stopped the bleeding. Level 2 is where you close the specific attack techniques that appear in almost every real-world AD compromise. Each control here is a few days of work at most, requires no licensing, and blocks a named technique used by real adversaries.

This guide goes deeper than a checklist. For each control you'll find **how the attack actually works** at the protocol level — because if you understand *why* NTLM relay is possible, you'll configure signing correctly the first time instead of cargo-culting a GPO setting.

---

## Table of contents

- [2.1 Windows LAPS — kill the shared local admin password](#21-windows-laps)
- [2.2 Protected Users — armor for privileged accounts](#22-protected-users)
- [2.3 LDAP signing + channel binding — stop LDAP relay](#23-ldap-signing--channel-binding)
- [2.4 SMB signing — stop SMB relay](#24-smb-signing)
- [2.5 krbtgt double-reset — close the golden-ticket window](#25-krbtgt-double-reset)
- [2.6 Admin logon-rights restrictions — the seed of tiering](#26-admin-logon-rights-restrictions)

---

## 2.1 Windows LAPS

### The attack: pass-the-hash across identical local admin passwords

Every Windows machine has a local Administrator account with its own password hash, stored in the local SAM database. In most organizations these passwords are set once — from a golden image or a build script — and **never changed**. The result: 500 workstations, one identical local Administrator password, one identical NTLM hash.

Here's why that's catastrophic. When an attacker compromises a single workstation (phishing, a malicious document, whatever), they run a credential-dumping tool against LSASS or the local SAM and extract the local Administrator's NTLM hash. They don't need to crack it. NTLM authentication accepts the *hash itself* as proof of identity — this is **pass-the-hash**. The attacker takes that hash and authenticates to every other machine that shares it. One compromised laptop becomes local admin on all 500. From there they hunt for a logged-on domain admin's cached credentials, and the domain is gone.

The shared password is the single point of failure. Break the sharing and pass-the-hash against local accounts collapses — a dumped hash only unlocks the one machine it came from.

### The fix: Windows LAPS

Windows LAPS (Local Administrator Password Solution) sets a **unique, random, regularly-rotated password** on each machine's local admin account and stores it securely in Active Directory (or Entra ID), readable only by authorized principals. Every machine gets a different password; a dumped hash is worthless anywhere else.

There are two versions, and this matters:

- **Legacy LAPS** — the original Microsoft MSI download from ~2015. Requires an AD schema extension (`ms-Mcs-AdmPwd` attributes), a client-side MSI on every machine, and stores passwords in *cleartext* in AD (protected only by ACLs).
- **Windows LAPS** — built directly into Windows 10/11 and Server 2019+ (via the April 2023 update onward). No MSI. Supports password **encryption** in AD, password history, and Entra ID storage. This is the version you deploy for anything new.

**Migration note (legacy → Windows LAPS):** If you already run legacy LAPS, the two can coexist during transition. Windows LAPS has a legacy-emulation mode that reads/writes the old `ms-Mcs-AdmPwd` attributes, so you can flip clients over without a flag day. Plan to: (1) update the AD schema for Windows LAPS with `Update-LapsADSchema`, (2) deploy the new policy targeting the modern attributes, (3) decommission the legacy MSI and its GPO once all clients report in. Do not run both policies writing to different attributes on the same machine long-term — pick the modern attributes and retire the old ones.

### Deploy Windows LAPS

```powershell
# 1. Extend the AD schema (run once, as Schema Admin)
Update-LapsADSchema

# 2. Grant a target OU's computers the right to write their own password
Set-LapsADComputerSelfPermission -Identity "OU=Workstations,DC=corp,DC=local"

# 3. Optionally, restrict who can READ the passwords (default: Domain Admins)
Find-LapsADExtendedRights -Identity "OU=Workstations,DC=corp,DC=local"
```

**GPO path:** `Computer Configuration > Policies > Administrative Templates > System > LAPS`
- *Configure password backup directory* → **Active Directory** (or Entra ID)
- *Password Settings* → length 20+, complexity all-character-types, age 30 days
- *Enable password encryption* → **Enabled** (requires Windows Server 2016 DFL or higher)
- *Configure authorized password decryptors* → a dedicated group, not Domain Admins broadly

### Verify

```powershell
# On a client: confirm policy is applied and a password is managed
Get-LapsADPassword -Identity "WORKSTATION01" -AsPlainText

# Confirm rotation is happening — check the expiration timestamp moves
Get-LapsADPassword -Identity "WORKSTATION01" | Select-Object ExpirationTimestamp

# Event log on the client — successful update is event 10018 in the LAPS operational log
Get-WinEvent -LogName 'Microsoft-Windows-LAPS/Operational' -MaxEvents 5
```

If `Get-LapsADPassword` returns a password and the expiration timestamp is in the future, LAPS is working. Confirm two different machines return **different** passwords — that's the whole point.

---

## 2.2 Protected Users

### The attack: harvesting privileged credentials from memory and weak protocols

When a user authenticates, Windows caches credential material to enable single sign-on — so you don't retype your password for every network resource. For a normal user this is a convenience. For a Domain Admin it's a liability, because that cached material (NTLM hashes, Kerberos keys, sometimes reversibly-cached secrets with older protocols) sits in LSASS memory and can be dumped by anyone with admin rights on that machine.

The attack chain: attacker gets admin on a server → dumps LSASS → finds a Domain Admin's cached credentials because that admin logged on there → replays them (pass-the-hash or pass-the-ticket) → domain compromise. The problem is compounded by *downgrade* attacks: if an account can still authenticate with NTLM or weak Kerberos encryption (RC4), an attacker can force the weaker protocol and attack that instead of the hardened one.

### The fix: the Protected Users group

Protected Users is a built-in security group (Server 2012 R2+) that applies **non-configurable, aggressive protections** to its members:

- **No NTLM** — members can only authenticate via Kerberos. Pass-the-hash against these accounts stops working, because there's no NTLM hash to pass.
- **No RC4 or DES for Kerberos** — only AES. Kills Kerberos encryption-downgrade attacks.
- **No credential caching** — members can't log on offline, and their credentials aren't cached in a form that survives for dumping.
- **No unconstrained delegation** — their TGT can't be delegated, blocking a class of delegation-abuse attacks.
- **Short TGT lifetime** — TGTs are capped at 4 hours instead of 10, shrinking the replay window.

The critical rule: **add privileged accounts (Domain Admins, Enterprise Admins, tier-0 service admins), never regular users or service accounts.** The protections that make it powerful will break anything that relies on NTLM, RC4, offline logon, or delegation. That's the point for admins — it's a disaster for a service account that needs NTLM.

### Deploy

```powershell
# Add a privileged admin account to Protected Users
Add-ADGroupMember -Identity 'Protected Users' -Members 'admin.vassilis'

# Roll out gradually — start with a test admin account, confirm nothing breaks,
# then add the rest. NEVER bulk-add all admins on day one.
```

**Pre-flight check — will anything break?** Before adding an account, confirm it does not depend on NTLM (check NTLM audit logs from Level 1.3), does not need to log on to machines while a DC is unreachable, and is not used for a service. Domain Controllers must be at a functional level that supports Protected Users (2012 R2 DFL minimum).

### Verify

```powershell
# Confirm membership
Get-ADGroupMember 'Protected Users' | Select-Object Name, objectClass

# On a protected account, confirm NTLM is refused: a logon attempt that would
# fall back to NTLM should fail. Check DC Security log for event 4625 with an
# NTLM package, or 4776 audit failures for the account.
Get-WinEvent -ComputerName DC01 -FilterHashtable @{LogName='Security'; Id=4625} -MaxEvents 20 |
    Where-Object { $_.Message -match 'admin.vassilis' }
```

---

## 2.3 LDAP signing + channel binding

### The attack: NTLM relay to LDAP

This is one of the most impactful attacks against a default AD, and understanding it explains half of AD hardening.

NTLM authentication is a challenge-response handshake, but it has a fatal flaw: **it does not bind the authentication to the channel it travels over.** When a client authenticates to a server with NTLM, the server can take that authentication material and *forward it to a third server*, impersonating the client. This is **NTLM relay**.

The attack against LDAP works like this. The attacker positions themselves to receive an authentication from a victim — often by *coercing* it. Coercion techniques (PetitPotam / MS-EFSRPC, the PrinterBug / MS-RPRN, and others) trick a machine — frequently a Domain Controller itself — into authenticating to an attacker-controlled host. The attacker relays that authentication to a Domain Controller's LDAP service. If the coerced victim was a DC's machine account, the relayed session has enormous privilege. The classic escalation: relay a DC's authentication to LDAP, then use it to grant the attacker DCSync rights (the ability to replicate password hashes for the entire domain), which yields every credential including krbtgt. Full domain compromise, no password ever cracked.

The defense is to make the LDAP server **refuse unsigned connections** and **bind authentication to the TLS channel**:

- **LDAP signing** requires the session to be cryptographically signed, which a relayed session cannot produce (the attacker doesn't have the session key). This kills relay over plain LDAP.
- **Channel binding (LDAPS / EPA)** ties the authentication to the specific TLS channel, so authentication captured on one channel can't be replayed on another. This kills relay over LDAPS.

You need **both**, because signing protects plain LDAP (389) and channel binding protects LDAPS (636). Fixing only one leaves the other open.

### Deploy

**GPO path (Domain Controllers policy):** `Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > Security Options`
- *Domain controller: LDAP server signing requirements* → **Require signing**
- *Domain controller: LDAP server channel binding token requirements* → **Always**

Registry equivalent on each DC (what the GPO sets):
```
HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters\LDAPServerIntegrity = 2   (require signing)
HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters\LdapEnforceChannelBinding = 2   (always)
```

**Roll out carefully.** Before enforcing, set the DCs to *audit* mode and watch for event ID **2889** (clients making unsigned LDAP binds) in the Directory Service log. Each 2889 event names a client IP still using unsigned binds — fix those clients (usually legacy apps or appliances with hardcoded simple binds) before you flip to Require, or you'll break them.

### Verify

```powershell
# Confirm the registry enforcement on every DC
Invoke-Command -ComputerName (Get-ADDomainController -Filter *).HostName {
    Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' |
        Select-Object PSComputerName, LDAPServerIntegrity, LdapEnforceChannelBinding
}
# Target: LDAPServerIntegrity = 2, LdapEnforceChannelBinding = 2

# Hunt for remaining unsigned binds before/after enforcement
Get-WinEvent -ComputerName DC01 -LogName 'Directory Service' -MaxEvents 50 |
    Where-Object Id -eq 2889
```

---

## 2.4 SMB signing

### The attack: NTLM relay to SMB

Same relay principle as LDAP (see 2.3), different target service. If SMB doesn't require signing, an attacker can relay a coerced or captured NTLM authentication to a target machine's SMB service and execute commands or access files as the victim.

The classic scenario: an attacker on the network runs a poisoning tool (LLMNR/NBT-NS/mDNS spoofing via Responder) to capture authentication attempts from machines looking for resources, then relays those to other machines over SMB. If the captured credential belongs to an account that's local admin on the target — and shared local admin passwords make this common (see 2.1) — the attacker gets code execution. Chain SMB relay with the coercion techniques from 2.3 and you have lateral movement and privilege escalation without ever touching a password.

SMB signing defeats this the same way LDAP signing does: a signed session requires the session key, which the relaying attacker doesn't possess. The relayed session fails signature validation and is rejected.

Modern Windows (Windows 11 24H2 and recent Server builds) has begun **requiring SMB signing by default**, but you should not assume your estate is there — enforce it explicitly.

### Deploy

**GPO path:** `Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > Security Options`
- *Microsoft network server: Digitally sign communications (always)* → **Enabled** (server side)
- *Microsoft network client: Digitally sign communications (always)* → **Enabled** (client side)

Apply to **all** machines, not just DCs — the target of an SMB relay is usually a member server or workstation, not a DC.

**Performance note:** SMB signing has a measurable CPU/throughput cost on very high-volume file servers. On modern hardware with SMB encryption offload it's usually negligible, but test on your busiest file server if you have one under heavy load. The security benefit almost always outweighs it; don't let a hypothetical performance worry leave relay open.

### Verify

```powershell
# Check effective SMB signing config on a machine
Get-SmbServerConfiguration | Select-Object RequireSecuritySignature, EnableSecuritySignature
Get-SmbClientConfiguration | Select-Object RequireSecuritySignature, EnableSecuritySignature
# Target: RequireSecuritySignature = True on both

# Audit connections that are NOT signed (server side)
Get-SmbConnection | Select-Object ServerName, ShareName, Signed, Encrypted
```

---

## 2.5 krbtgt double-reset

### The attack: the golden ticket

Kerberos is the primary authentication protocol in AD, and its trust model has a keystone: the **krbtgt account**. Every Ticket-Granting Ticket (TGT) issued by a Domain Controller is encrypted and signed with the password hash of the krbtgt account. When a user presents their TGT to request access to a service, the DC validates it using that same krbtgt key. In effect, the krbtgt hash is the master signing key for the entire domain's Kerberos trust.

Now the attack. If an attacker achieves domain dominance even once — via DCSync, a DC compromise, or a backup restore — they can extract the krbtgt hash. With that hash, they can forge a **golden ticket**: a completely valid TGT for *any* user (including a non-existent one), with *any* group memberships (Domain Admins, Enterprise Admins), and an arbitrary lifetime. The DC will accept it as genuine because it's signed with the real krbtgt key. This is the ultimate persistence mechanism — the attacker can return to the domain as any identity, at will, even after you've reset every user password, rebuilt servers, and thought you'd evicted them.

The only way to invalidate golden tickets is to **change the krbtgt password**. And here's the subtle part: AD keeps the **current and previous** krbtgt password (`N` and `N-1`) valid simultaneously, so tickets issued under the old key don't instantly break during normal rotation. That's good for availability but means a **single** reset does *not* invalidate existing golden tickets — they're still valid against the `N-1` key. You must reset **twice**, with an interval between resets long enough for legitimate tickets to be re-issued under the new key (at least the maximum TGT lifetime, typically 10 hours; a common safe interval is 10–24 hours). The first reset moves the compromised key to `N-1`; the second reset finally purges it.

### Deploy

Do **not** reset krbtgt twice in quick succession — that breaks Kerberos domain-wide because tickets in flight lose both valid keys. Use Microsoft's guided reset script, which handles replication checks between resets.

```powershell
# Recommended: Microsoft's New-KrbtgtKeys.ps1 (from the Microsoft AD reset guidance)
# It resets once, waits for replication to all DCs, verifies, then you run it again
# after the safe interval.

# Manual single reset (then wait the interval, then repeat) — advanced use only:
# Reset via ADUC or:
$krbtgt = Get-ADUser krbtgt
Set-ADAccountPassword -Identity $krbtgt -Reset -NewPassword `
    (ConvertTo-SecureString -AsPlainText ([System.Web.Security.Membership]::GeneratePassword(32,8)) -Force)
# The actual password value is irrelevant — the system generates the real key.
# Wait >= max TGT lifetime (default 10h) and confirm replication, THEN reset again.
```

**When to do this:** proactively on a defined cadence (every 180 days is a reasonable posture), and **immediately** (both resets, spaced by the interval) after any suspected domain compromise.

### Verify

```powershell
# Check krbtgt password age — this is what the maturity script flags
Get-ADUser krbtgt -Properties PasswordLastSet | Select-Object PasswordLastSet

# After a reset, confirm the change replicated to all DCs (metadata should match)
Get-ADReplicationAttributeMetadata -Object (Get-ADUser krbtgt).DistinguishedName `
    -Server (Get-ADDomainController -Filter *).HostName -Properties pwdLastSet |
    Select-Object Server, AttributeName, LastOriginatingChangeTime
```

---

## 2.6 Admin logon-rights restrictions

### The attack: credential theft via privileged logon on the wrong machine

This is the conceptual bridge to the full tiering model (Level 5), started here as a quick win.

The core problem, restated from 2.2: when a privileged account logs on to a machine, credential material lands in that machine's memory. If a Domain Admin logs on to a helpdesk technician's workstation to "quickly fix something," and that workstation is compromised, the attacker harvests Domain Admin credentials. **The privilege of the account is only as safe as the least-trusted machine it touches.**

You already established the *policy* in Level 1.2 ("admins don't log on to workstations"). Now you enforce it *technically* with logon rights, so it doesn't depend on discipline. The mechanism is the **"Deny log on" user rights**, assigned via GPO, which the OS enforces regardless of the account's group memberships.

### Deploy

Create a GPO that **denies** privileged groups the right to log on to lower-trust machines. The standard pattern (a simplified two-tier version of what you'll formalize in Level 5):

**GPO linked to Workstation and Member-Server OUs**, path: `Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > User Rights Assignment`
- *Deny log on locally* → add **Domain Admins**, **Enterprise Admins**
- *Deny log on through Remote Desktop Services* → add **Domain Admins**, **Enterprise Admins**
- *Deny access to this computer from the network* → add **Domain Admins**, **Enterprise Admins** (prevents pass-the-hash *to* these machines using DA credentials)
- *Deny log on as a batch job* / *Deny log on as a service* → add **Domain Admins**, **Enterprise Admins**

The effect: a Domain Admin *physically cannot* log on to a workstation, even by mistake, even if someone tries to force it. The credentials never reach the untrusted machine.

**Critical caution:** apply these deny-rights **only to workstation and member-server OUs — never to the Domain Controllers OU.** Denying Domain Admins logon to DCs locks you out of your own domain. This OU-scoping discipline is exactly what the tiering model formalizes: Tier 0 accounts log on to Tier 0 machines only, and the deny-rights enforce the boundaries between tiers.

### Verify

```powershell
# On a workstation, confirm the deny rights are effective
# (requires the Carbon module or secedit export)
secedit /export /areas USER_RIGHTS /cfg C:\temp\rights.txt
Select-String -Path C:\temp\rights.txt -Pattern 'SeDenyInteractiveLogonRight|SeDenyNetworkLogonRight'
# The Domain Admins / Enterprise Admins SIDs should appear in the deny entries.

# Functional test: attempt an interactive logon to a workstation with a DA account.
# It should be refused with "The sign-in method you're trying to use isn't allowed."
```

---

## Level 2 exit criteria

- [ ] Windows LAPS deployed; two machines confirmed to have different, rotating local admin passwords.
- [ ] Privileged accounts added to Protected Users (gradually, with no breakage).
- [ ] LDAP signing = Require and channel binding = Always on all DCs; event 2889 clean.
- [ ] SMB signing required on all machines (clients and servers, not just DCs).
- [ ] krbtgt reset twice with a safe interval; password age tracked going forward.
- [ ] Deny-logon rights enforce that privileged accounts cannot log on to workstations/member servers.

Re-run `Test-ADMaturityLevel.ps1` — several of these controls are checked directly. Then proceed to [Level 3 — Credential Hardening](../03-credential-hardening/README.md).

---

## References

- [Microsoft — Windows LAPS overview](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview)
- [Microsoft — Protected Users security group](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group)
- [Microsoft — LDAP channel binding and signing requirements (ADV190023)](https://support.microsoft.com/en-us/topic/2020-ldap-channel-binding-and-ldap-signing-requirements-ef185fb8-00f7-167d-744c-f299a66fc00a)
- [Microsoft — AD Forest Recovery: resetting the krbtgt password](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/ad-forest-recovery-resetting-the-krbtgt-password)
- [Microsoft — Enterprise Access Model](https://learn.microsoft.com/en-us/security/privileged-access-workloads/privileged-access-access-model)
