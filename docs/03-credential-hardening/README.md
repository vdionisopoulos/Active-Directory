# Level 3 — Credential Hardening

> **Prerequisite:** Levels 1 and 2 complete. In particular, LAPS is deployed, Protected Users holds your admins, and signing/relay protections are in place.

Levels 1 and 2 closed the loud, well-known holes. Level 3 goes after the credential material itself — the service-account passwords, Kerberos keys, and delegation rights that attackers harvest to move from "foothold" to "domain admin" without ever touching a password prompt.

This level requires more care than the previous ones. Some of these changes (removing RC4, migrating service accounts) can break legacy applications if you move without auditing first. The deep-dives below explain not just the fix but the failure modes, so you enforce without an outage.

---

## Table of contents

- [3.1 Kerberoasting — why service accounts are crackable, and how gMSA ends it](#31-kerberoasting)
- [3.2 gMSA — Group Managed Service Accounts](#32-gmsa)
- [3.3 AS-REP roasting — the pre-auth trap](#33-as-rep-roasting)
- [3.4 Kerberos encryption hardening — kill RC4 and DES](#34-kerberos-encryption-hardening)
- [3.5 ACL hygiene with BloodHound — finding the hidden paths to Domain Admin](#35-acl-hygiene-with-bloodhound)

---

## 3.1 Kerberoasting

### The attack: cracking service-account passwords offline

This is one of the most reliable privilege-escalation techniques in AD, and it works because of a design decision in Kerberos that predates modern threat models.

When a user wants to access a network service (a SQL Server, a web app, a file share running under a domain account), they request a **service ticket** (TGS) from the Domain Controller for that service's **Service Principal Name (SPN)**. Here's the critical part: the DC encrypts a portion of that service ticket with the **password hash of the account that owns the SPN**. The DC hands this ticket to the requesting user. And *any* authenticated user can request a service ticket for *any* SPN — that's how Kerberos is supposed to work.

Now the attack. An attacker with any low-privilege domain account enumerates all user accounts that have an SPN set (these are almost always service accounts). For each one, they request a service ticket. They now hold a blob encrypted with the service account's password hash. They take that blob **offline** — to their own hardware, a GPU cracking rig, hashcat — and brute-force it. There's no lockout, no logging of the crack attempt, no rate limit, because the cracking happens entirely off the DC. If the service account has a weak or human-chosen password (and many do — set once, years ago, "because the app needed it"), it falls in hours or minutes.

Why it's so dangerous: service accounts are frequently **over-privileged**. That SQL service account is often a member of a privileged group, or has admin rights on many servers, or — worst case — is in Domain Admins. Crack one weak service-account password and you've escalated straight to the top.

The two defenses, in order of strength:
1. **If the account can be a gMSA, make it one** (see 3.2). gMSA passwords are 240+ characters, random, and auto-rotated — uncrackable in any practical sense. This eliminates the attack rather than mitigating it.
2. **For accounts that can't be gMSA yet**, enforce very long (25+ character) random passwords, and ensure AES encryption (see 3.4) so the attacker at least can't fall back to the weaker RC4-encrypted ticket, which is faster to crack.

### Find your exposure

```powershell
# Every enabled USER account with an SPN — these are kerberoastable
Get-ADUser -Filter {ServicePrincipalName -like '*' -and Enabled -eq $true} `
    -Properties ServicePrincipalName, PasswordLastSet, MemberOf |
    Select-Object SamAccountName, PasswordLastSet,
        @{n='SPNs';e={$_.ServicePrincipalName -join '; '}},
        @{n='Groups';e={($_.MemberOf | ForEach-Object {($_ -split ',')[0] -replace 'CN='}) -join '; '}} |
    Format-Table -AutoSize
# Pay special attention to any that are members of privileged groups.
```

### Verify (after remediation)

```powershell
# Ideal end state: zero enabled USER accounts with SPNs (all migrated to gMSA/machine accounts)
(Get-ADUser -Filter {ServicePrincipalName -like '*' -and Enabled -eq $true}).Count
# For any that remain, confirm AES is enabled (see 3.4) and passwords are long/rotated.
```

---

## 3.2 gMSA

### What it is and why it ends kerberoasting

A **Group Managed Service Account (gMSA)** is a special AD account type where **Active Directory itself owns and rotates the password**. No human ever knows it. The password is 240 bytes of random data, rotated automatically every 30 days by default, and retrieved on demand by authorized hosts using their own machine-account credentials.

This defeats kerberoasting completely: even if an attacker kerberoasts the gMSA's service ticket, the underlying password is 240 random characters — it will not fall to any offline cracking within the lifetime of the universe. And because it rotates automatically, there's no stale, human-chosen password sitting unchanged for five years.

The mechanism: a gMSA is tied to a set of authorized principals (the hosts allowed to use it). When a service on an authorized host needs the password, the host authenticates with its own machine account and AD hands it the current gMSA password. When AD rotates the password, authorized hosts transparently pick up the new one. No config file with a plaintext password, no password-change ticket to the helpdesk, no service outage on rotation.

**What can and can't become a gMSA:** gMSA works for Windows services, IIS app pools, and scheduled tasks that support it. It does *not* work for every legacy application — some apps demand an interactive password they can store, or don't support the gMSA retrieval mechanism. Audit before migrating; keep a rollback account ready.

### Deploy

```powershell
# 1. One-time per forest: create the KDS root key (the master key AD uses to
#    generate gMSA passwords). In production, wait 10 hours for replication.
#    In a single-DC lab you can back-date it to use immediately:
Add-KdsRootKey -EffectiveTime ((Get-Date).AddHours(-10))

# 2. Create a security group for the hosts allowed to use this gMSA
New-ADGroup -Name 'gMSA_SQL_Hosts' -GroupScope Global -GroupCategory Security
Add-ADGroupMember -Identity 'gMSA_SQL_Hosts' -Members 'SQL01$'   # note the $ — machine account

# 3. Create the gMSA, authorizing that group to retrieve the password
New-ADServiceAccount -Name 'gmsa-sql' -DNSHostName 'gmsa-sql.corp.lab' `
    -PrincipalsAllowedToRetrieveManagedPassword 'gMSA_SQL_Hosts' `
    -ServicePrincipalNames 'MSSQLSvc/SQL01.corp.lab:1433'

# 4. On the service host, install and test the account
Install-ADServiceAccount -Identity 'gmsa-sql'
Test-ADServiceAccount -Identity 'gmsa-sql'   # should return True

# 5. Configure the service to log on as  corp\gmsa-sql$  with a BLANK password
#    (the OS retrieves it automatically).
```

### Verify

```powershell
# Confirm the account exists and is managed
Get-ADServiceAccount -Identity 'gmsa-sql' -Properties PrincipalsAllowedToRetrieveManagedPassword,
    msDS-ManagedPasswordInterval

# On the host, confirm it can retrieve the password
Test-ADServiceAccount -Identity 'gmsa-sql'
```

---

## 3.3 AS-REP roasting

### The attack: cracking accounts that don't require pre-authentication

Kerberos normally protects against offline password attacks on the *initial* authentication with a feature called **pre-authentication**. When you request your first ticket (the TGT via an AS-REQ), you must prove you know your password by encrypting a timestamp with your password-derived key. The DC verifies it before sending anything crackable back. This is what stops an attacker from simply asking the DC for your encrypted credential material.

But pre-authentication can be **disabled** per-account with the flag "Do not require Kerberos preauthentication." When it's off, an attacker can send an AS-REQ for that account *without knowing the password*, and the DC replies (AS-REP) with material encrypted using the account's password hash. The attacker takes that offline and cracks it — exactly like kerberoasting, but targeting user logon accounts instead of service accounts, and requiring no prior authentication at all.

Why does the flag ever get set? Occasionally for old Unix/Linux Kerberos integrations or legacy apps that couldn't do pre-auth. Almost always, in a modern domain, it's a mistake or a leftover — and it's a gift to attackers, who scan for it as a first move.

### Find and fix

```powershell
# Any enabled account with pre-auth disabled — these are AS-REP roastable
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true -and Enabled -eq $true} `
    -Properties DoesNotRequirePreAuth | Select-Object SamAccountName

# Fix: re-enable pre-authentication (clear the flag)
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} |
    Set-ADAccountControl -DoesNotRequirePreAuth $false
```

### Verify

```powershell
# Should return zero
(Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true -and Enabled -eq $true}).Count
```

If a genuine legacy dependency forces pre-auth off on one account, isolate it: give it a very long random password, monitor it closely, and plan its replacement.

---

## 3.4 Kerberos encryption hardening

### The attack: forcing the weak cipher

Kerberos tickets are encrypted, but with which algorithm depends on what the account supports. The options, weakest to strongest: **DES** (broken, should never appear), **RC4-HMAC** (weak, fast to crack offline), and **AES** (128/256, strong). The problem: for backward compatibility, accounts often advertise support for RC4, and an attacker performing kerberoasting or AS-REP roasting will specifically **request the RC4-encrypted version** of a ticket because it cracks far faster than AES.

So even if you've enforced long passwords, leaving RC4 enabled hands attackers the faster attack path. Hardening means telling accounts (and the domain) to use **AES only** and to stop offering RC4 and DES.

**This is the change most likely to break something**, because some old service or trust may genuinely still need RC4. The discipline: audit which accounts still use RC4 *before* you disable it, fix or replace them, then enforce.

### Audit, then enforce

```powershell
# Which accounts still allow RC4 / DES? (msDS-SupportedEncryptionTypes)
# Value meanings: 0x1=DES-CRC, 0x2=DES-MD5, 0x4=RC4, 0x8=AES128, 0x10=AES256
Get-ADObject -Filter "objectClass -eq 'user' -or objectClass -eq 'computer'" `
    -Properties msDS-SupportedEncryptionTypes, samAccountName |
    Where-Object {
        $e = $_.'msDS-SupportedEncryptionTypes'
        $null -eq $e -or ($e -band 0x4) -or ($e -band 0x3)   # RC4 or DES bits, or unset (defaults include RC4)
    } |
    Select-Object samAccountName, @{n='EncTypes';e={$_.'msDS-SupportedEncryptionTypes'}}

# For an account confirmed AES-capable, set AES128+AES256 only (0x18 = 24)
Set-ADUser -Identity 'someservice' -Replace @{ 'msDS-SupportedEncryptionTypes' = 24 }
```

**Domain-wide enforcement (GPO):** `Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > Security Options`
- *Network security: Configure encryption types allowed for Kerberos* → check **AES128**, **AES256**; **uncheck** RC4, DES.

Roll this out in a controlled fashion: audit first, remediate the RC4-dependent stragglers, then apply the GPO. Watch for Kerberos errors (event IDs around ticket encryption) after enforcement.

### Verify

```powershell
# Confirm no enabled account still defaults to RC4/DES after remediation
Get-ADObject -Filter "objectClass -eq 'user'" -Properties msDS-SupportedEncryptionTypes, samAccountName |
    Where-Object { $e = $_.'msDS-SupportedEncryptionTypes'; ($e -band 0x4) -or ($e -band 0x3) } |
    Select-Object samAccountName
```

---

## 3.5 ACL hygiene with BloodHound

### The attack: the hidden paths to Domain Admin

Everything above targets credentials. This targets **permissions** — and it's where most "how did they get Domain Admin?" stories actually end.

Active Directory is a giant permission system. Every object (users, groups, OUs, the domain itself) has an ACL controlling who can do what to it. Over years of delegation, help-desk shortcuts, and "just give them access to unblock the project," domains accumulate thousands of ACL entries. Buried in them are **attack paths**: chains of individually-reasonable permissions that combine into a route from a low-privilege account to full domain control.

Concrete examples of dangerous ACLs:
- **GenericAll / GenericWrite** on a user or group — lets the holder reset that user's password or add themselves to that group.
- **WriteDacl / WriteOwner** — lets the holder rewrite the object's permissions, granting themselves anything.
- **AddMember** on a privileged group — direct path into Domain Admins.
- **ForceChangePassword** — reset a privileged user's password and log in as them.
- Dangerous **Kerberos delegation** rights (unconstrained/constrained/resource-based) — impersonate other users to services.

The problem is that no human can see these paths by reading ACLs one at a time. There are too many, and the danger is in the *chains*: account A can reset B's password, B is in a group that can write to C, C can add members to Domain Admins. Each link looks fine alone.

### The tool: BloodHound

**BloodHound** ingests the entire domain's users, groups, sessions, and ACLs and builds a **graph**. Then it answers the question that matters: *"What is the shortest path from this account (or from any account) to Domain Admin?"* It surfaces the chains automatically. This is what red teams run first — so you should run it first too, and cut the paths before they do.

Workflow:
1. **Collect** with SharpHound (the collector) against your domain — it gathers objects, ACLs, sessions, and group memberships.
2. **Import** into BloodHound (Community Edition is free and current).
3. **Analyze** — use the built-in queries ("Shortest Paths to Domain Admins", "Find Principals with DCSync Rights", "Dangerous ACLs") to see the graph.
4. **Remediate** — remove the offending ACL, or the excessive group membership, that forms each path. Re-run to confirm the path is gone.

```powershell
# SharpHound collection (run from a domain-joined host with a domain account).
# Download SharpHound from the official BloodHound project releases.
# Example — all standard collection methods:
.\SharpHound.exe -c All -d corp.lab
# Produces a .zip of JSON to import into BloodHound.
```

### What "good" looks like

There is no single command to "verify" ACL hygiene — it's iterative. The end state is: the "Shortest Path to Domain Admins" queries return only the paths you *expect* (your actual admins), with no surprise routes through service accounts, help-desk groups, or forgotten delegations. Re-run BloodHound after any significant delegation change.

**Lab tie-in:** this is the control best demonstrated in the lab (see `../../lab/`). Deliberately create a dangerous ACL (e.g., give a normal user GenericAll on a privileged group), run SharpHound, watch BloodHound light up the path to Domain Admin, remove the ACL, and confirm the path disappears. It's the most visually compelling demo in the whole roadmap.

---

## Level 3 exit criteria

- [ ] Kerberoastable user accounts eliminated (migrated to gMSA) or hardened (long password + AES).
- [ ] gMSA in use for service accounts that support it; KDS root key created.
- [ ] No enabled account has "do not require pre-authentication" set.
- [ ] RC4/DES audited and disabled; AES enforced domain-wide via GPO.
- [ ] BloodHound run; unexpected shortest-paths-to-DA identified and cut.

Re-run `Test-ADMaturityLevel.ps1` — Kerberoasting and AS-REP checks are covered directly. Then proceed to [Level 4 — Detection](../04-detection/README.md).

---

## References

- [Microsoft — Group Managed Service Accounts overview](https://learn.microsoft.com/en-us/windows-server/security/group-managed-service-accounts/group-managed-service-accounts-overview)
- [Microsoft — Decrypting the Selection of Supported Kerberos Encryption Types](https://techcommunity.microsoft.com/t5/core-infrastructure-and-security/decrypting-the-selection-of-supported-kerberos-encryption-types/ba-p/1628797)
- [BloodHound Community Edition](https://github.com/SpecterOps/BloodHound)
- [Microsoft — Service Principal Names](https://learn.microsoft.com/en-us/windows/win32/ad/service-principal-names)
