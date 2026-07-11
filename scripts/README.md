# Scripts

Read-only and remediation helpers referenced by the maturity guides.

| Script | Level | Type | Description |
|--------|-------|------|-------------|
| `Test-ADMaturityLevel.ps1` | All | **Read-only** | Assesses the domain against the documented controls and reports pass/fail per maturity level. Makes no changes. |

## Test-ADMaturityLevel.ps1

Non-invasive assessment across Levels 1–3. Run it, fix the failures, run it again to prove progress.

```powershell
# Basic run
.\Test-ADMaturityLevel.ps1

# Custom staleness threshold, verbose, export to CSV
.\Test-ADMaturityLevel.ps1 -StaleDays 60 -Verbose | Export-Csv .\ad-maturity.csv -NoTypeInformation
```

**Requirements:** RSAT ActiveDirectory module; an account with read access to AD. Some checks (Print Spooler, LDAP signing) query DCs remotely and will report WARN if remoting is unavailable.

**Scope:** covers the controls this repo documents. It is a companion to — not a replacement for — PingCastle and BloodHound.
