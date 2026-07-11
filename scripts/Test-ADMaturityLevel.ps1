#Requires -Modules ActiveDirectory
<#
.SYNOPSIS
    Read-only assessment of an on-prem Active Directory domain against the
    maturity levels defined in this repository.

.DESCRIPTION
    Runs a series of non-invasive checks (no writes, no changes) and reports
    pass/fail per control, grouped by maturity level. Use it to find your
    current level and to prove progress after remediation.

    This is a helper, not a substitute for PingCastle/BloodHound. It covers the
    controls this repo documents — not the full AD attack surface.

.PARAMETER StaleDays
    Days of inactivity before an enabled account is considered stale. Default 90.

.EXAMPLE
    .\Test-ADMaturityLevel.ps1

.EXAMPLE
    .\Test-ADMaturityLevel.ps1 -StaleDays 60 -Verbose

.NOTES
    Run as an account that can read AD. Read-only: makes no modifications.
#>
[CmdletBinding()]
param(
    [int]$StaleDays = 90
)

$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory

$results = [System.Collections.Generic.List[object]]::new()

function Add-Check {
    param(
        [string]$Level,
        [string]$Control,
        [ValidateSet('PASS', 'FAIL', 'WARN', 'INFO')][string]$Status,
        [string]$Detail
    )
    $results.Add([pscustomobject]@{
        Level   = $Level
        Control = $Control
        Status  = $Status
        Detail  = $Detail
    })
}

Write-Verbose "Gathering domain information..."
$domain = Get-ADDomain
$dcs    = Get-ADDomainController -Filter *

# ---------------------------------------------------------------------------
# LEVEL 1 — Baseline Hygiene
# ---------------------------------------------------------------------------

# 1.2 Privileged group sprawl
try {
    $da = @(Get-ADGroupMember 'Domain Admins' -ErrorAction Stop)
    $ea = @(Get-ADGroupMember 'Enterprise Admins' -ErrorAction SilentlyContinue)
    $daCount = $da.Count
    if ($daCount -le 3) {
        Add-Check 'L1' 'Domain Admins membership' 'PASS' "$daCount members"
    } elseif ($daCount -le 6) {
        Add-Check 'L1' 'Domain Admins membership' 'WARN' "$daCount members — review for standing access"
    } else {
        Add-Check 'L1' 'Domain Admins membership' 'FAIL' "$daCount members — far too many for standing privilege"
    }
    Add-Check 'L1' 'Enterprise Admins membership' 'INFO' "$($ea.Count) members"
} catch {
    Add-Check 'L1' 'Privileged group enumeration' 'WARN' $_.Exception.Message
}

# 1.3 LmCompatibilityLevel (check on the machine running the script as a proxy)
try {
    $lmc = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name LmCompatibilityLevel -ErrorAction SilentlyContinue).LmCompatibilityLevel
    if ($null -eq $lmc) {
        Add-Check 'L1' 'LmCompatibilityLevel (local host)' 'WARN' 'Not set explicitly — defaults are OS-dependent; enforce level 5 via GPO'
    } elseif ($lmc -ge 5) {
        Add-Check 'L1' 'LmCompatibilityLevel (local host)' 'PASS' "Level $lmc (NTLMv2 only, LM & NTLM refused)"
    } else {
        Add-Check 'L1' 'LmCompatibilityLevel (local host)' 'FAIL' "Level $lmc — should be 5"
    }
} catch {
    Add-Check 'L1' 'LmCompatibilityLevel (local host)' 'WARN' $_.Exception.Message
}

# 1.4 Print Spooler on DCs
foreach ($dc in $dcs) {
    try {
        $svc = Get-Service -ComputerName $dc.HostName -Name Spooler -ErrorAction Stop
        if ($svc.Status -eq 'Stopped') {
            Add-Check 'L1' "Print Spooler on $($dc.Name)" 'PASS' 'Stopped'
        } else {
            Add-Check 'L1' "Print Spooler on $($dc.Name)" 'FAIL' "$($svc.Status) — disable on DCs (PrintNightmare / printer-bug coercion)"
        }
    } catch {
        Add-Check 'L1' "Print Spooler on $($dc.Name)" 'WARN' "Could not query: $($_.Exception.Message)"
    }
}

# 1.5 Stale accounts
try {
    $cutoff = (Get-Date).AddDays(-$StaleDays)
    $stale = @(Get-ADUser -Filter {Enabled -eq $true} -Properties LastLogonTimestamp |
        Where-Object { $_.LastLogonTimestamp -and [datetime]::FromFileTime($_.LastLogonTimestamp) -lt $cutoff })
    if ($stale.Count -eq 0) {
        Add-Check 'L1' "Stale enabled accounts (>$StaleDays d)" 'PASS' 'None found'
    } else {
        Add-Check 'L1' "Stale enabled accounts (>$StaleDays d)" 'WARN' "$($stale.Count) enabled accounts inactive"
    }
} catch {
    Add-Check 'L1' 'Stale account enumeration' 'WARN' $_.Exception.Message
}

# 1.5 Dangerous account flags
try {
    $pwNotReq = @(Get-ADUser -Filter 'PasswordNotRequired -eq $true' -ErrorAction SilentlyContinue)
    if ($pwNotReq.Count -eq 0) {
        Add-Check 'L1' 'Accounts with PasswordNotRequired' 'PASS' 'None'
    } else {
        Add-Check 'L1' 'Accounts with PasswordNotRequired' 'FAIL' "$($pwNotReq.Count) accounts — remove this flag"
    }
} catch {
    Add-Check 'L1' 'PasswordNotRequired check' 'WARN' $_.Exception.Message
}

# ---------------------------------------------------------------------------
# LEVEL 2 — Quick Wins
# ---------------------------------------------------------------------------

# 2.x Protected Users group populated
try {
    $pu = @(Get-ADGroupMember 'Protected Users' -ErrorAction Stop)
    if ($pu.Count -gt 0) {
        Add-Check 'L2' 'Protected Users group in use' 'PASS' "$($pu.Count) members"
    } else {
        Add-Check 'L2' 'Protected Users group in use' 'WARN' 'Empty — add privileged accounts (blocks credential caching, NTLM, weak Kerberos)'
    }
} catch {
    Add-Check 'L2' 'Protected Users group' 'WARN' $_.Exception.Message
}

# 2.x krbtgt password age (golden-ticket exposure window)
try {
    $krbtgt = Get-ADUser krbtgt -Properties PasswordLastSet
    $age = (New-TimeSpan -Start $krbtgt.PasswordLastSet -End (Get-Date)).Days
    if ($age -le 180) {
        Add-Check 'L2' 'krbtgt password age' 'PASS' "$age days"
    } elseif ($age -le 365) {
        Add-Check 'L2' 'krbtgt password age' 'WARN' "$age days — rotate (twice, with interval) toward a <=180d cadence"
    } else {
        Add-Check 'L2' 'krbtgt password age' 'FAIL' "$age days — long golden-ticket exposure window; double-reset needed"
    }
} catch {
    Add-Check 'L2' 'krbtgt password age' 'WARN' $_.Exception.Message
}

# 2.x LDAP signing requirement on DCs (registry proxy check on reachable DCs)
foreach ($dc in $dcs) {
    try {
        $val = Invoke-Command -ComputerName $dc.HostName -ScriptBlock {
            (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -Name 'LDAPServerIntegrity' -ErrorAction SilentlyContinue).LDAPServerIntegrity
        } -ErrorAction Stop
        if ($val -eq 2) {
            Add-Check 'L2' "LDAP signing required on $($dc.Name)" 'PASS' 'Require signing (2)'
        } else {
            Add-Check 'L2' "LDAP signing required on $($dc.Name)" 'WARN' "Value=$val — set to 2 to block LDAP relay"
        }
    } catch {
        Add-Check 'L2' "LDAP signing on $($dc.Name)" 'WARN' "Could not query remotely"
    }
}

# ---------------------------------------------------------------------------
# LEVEL 3 — Credential Hardening
# ---------------------------------------------------------------------------

# 3.x Kerberoastable accounts (user accounts with SPNs)
try {
    $spnUsers = @(Get-ADUser -Filter {ServicePrincipalName -like '*' -and Enabled -eq $true} -Properties ServicePrincipalName, PasswordLastSet |
        Where-Object { $_.SamAccountName -ne 'krbtgt' })
    if ($spnUsers.Count -eq 0) {
        Add-Check 'L3' 'Kerberoastable user accounts' 'PASS' 'None (SPNs only on machine/gMSA accounts)'
    } else {
        Add-Check 'L3' 'Kerberoastable user accounts' 'WARN' "$($spnUsers.Count) user accounts have SPNs — migrate to gMSA, ensure long/complex passwords"
    }
} catch {
    Add-Check 'L3' 'Kerberoasting exposure' 'WARN' $_.Exception.Message
}

# 3.x AS-REP roastable accounts (Kerberos preauth disabled)
try {
    $asrep = @(Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true -and Enabled -eq $true} -ErrorAction SilentlyContinue)
    if ($asrep.Count -eq 0) {
        Add-Check 'L3' 'AS-REP roastable accounts' 'PASS' 'None'
    } else {
        Add-Check 'L3' 'AS-REP roastable accounts' 'FAIL' "$($asrep.Count) accounts without Kerberos pre-auth"
    }
} catch {
    Add-Check 'L3' 'AS-REP roasting check' 'WARN' $_.Exception.Message
}

# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

$order = @{ PASS = 0; INFO = 1; WARN = 2; FAIL = 3 }
$sorted = $results | Sort-Object { $_.Level }, { $order[$_.Status] }

Write-Host ""
Write-Host "=== AD Maturity Assessment — $($domain.DNSRoot) ===" -ForegroundColor Cyan
Write-Host ""

foreach ($r in $sorted) {
    $color = switch ($r.Status) {
        'PASS' { 'Green' }
        'INFO' { 'Gray' }
        'WARN' { 'Yellow' }
        'FAIL' { 'Red' }
    }
    Write-Host ("[{0}] {1,-4} {2,-40} {3}" -f $r.Status, $r.Level, $r.Control, $r.Detail) -ForegroundColor $color
}

# Level pass = no FAILs at that level (WARN/INFO tolerated)
Write-Host ""
Write-Host "=== Level summary ===" -ForegroundColor Cyan
$currentLevel = 0
foreach ($lvl in @('L1','L2','L3')) {
    $checks = $results | Where-Object Level -eq $lvl
    $fails  = @($checks | Where-Object Status -eq 'FAIL')
    $warns  = @($checks | Where-Object Status -eq 'WARN')
    if ($fails.Count -eq 0 -and $checks.Count -gt 0) {
        Write-Host "$lvl : PASS (no hard failures; $($warns.Count) warnings)" -ForegroundColor Green
        $currentLevel = [int]($lvl -replace 'L','')
    } else {
        Write-Host "$lvl : NOT MET ($($fails.Count) failures, $($warns.Count) warnings)" -ForegroundColor Red
        break
    }
}

Write-Host ""
Write-Host "Highest level with no hard failures: $currentLevel" -ForegroundColor Cyan
Write-Host "Note: this tool covers documented controls only. Run PingCastle and BloodHound for full coverage." -ForegroundColor DarkGray
Write-Host ""

# Emit objects too, for piping to Export-Csv etc.
$results
