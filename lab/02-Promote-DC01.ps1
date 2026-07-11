#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Lab setup — Step 2 (run INSIDE the DC01 VM, elevated).
    Installs the AD DS role and promotes DC01 to the first Domain Controller
    of a new forest: corp.lab

.DESCRIPTION
    Run this only AFTER the OS is installed, the machine is renamed to DC01,
    and a static IP (10.0.0.10) is set. The script installs AD DS + DNS and
    creates the forest. The VM reboots automatically on success.

.NOTES
    Domain     : corp.lab
    NetBIOS    : CORP
    This is a LAB. The DSRM password below is prompted, not hardcoded.
#>

[CmdletBinding()]
param(
    [string]$DomainName    = "corp.lab",
    [string]$NetbiosName   = "CORP",
    [string]$ExpectedName  = "DC01",
    [string]$ExpectedIP    = "10.0.0.10"
)

$ErrorActionPreference = 'Stop'

function Write-Step { param($m) Write-Host "`n=== $m ===" -ForegroundColor Cyan }
function Write-Ok   { param($m) Write-Host "[OK]  $m" -ForegroundColor Green }
function Fail       { param($m) Write-Host "[XX]  $m" -ForegroundColor Red; exit 1 }

# ---------------------------------------------------------------------------
# 0. SANITY CHECKS — don't promote a misconfigured box
# ---------------------------------------------------------------------------
Write-Step "Pre-promotion checks"

if ($env:COMPUTERNAME -ne $ExpectedName) {
    Fail "Computer name is '$env:COMPUTERNAME', expected '$ExpectedName'. Run: Rename-Computer -NewName '$ExpectedName' -Restart"
}
Write-Ok "Hostname is $ExpectedName"

$ip = (Get-NetIPAddress -AddressFamily IPv4 |
       Where-Object { $_.IPAddress -notlike '169.*' -and $_.IPAddress -ne '127.0.0.1' } |
       Select-Object -First 1).IPAddress
Write-Host "Primary IPv4 : $ip"
if ($ip -ne $ExpectedIP) {
    Write-Host "[!!]  IP is '$ip', expected '$ExpectedIP'. A static IP is strongly recommended for a DC." -ForegroundColor Yellow
    $ans = Read-Host "Continue anyway? (y/N)"
    if ($ans -ne 'y') { Fail "Set a static IP first, then re-run." }
}

# A DC should point DNS at itself (127.0.0.1) — DNS role will be local.
Write-Ok "Proceeding to install AD DS"

# ---------------------------------------------------------------------------
# 1. INSTALL THE ROLE
# ---------------------------------------------------------------------------
Write-Step "Installing AD-Domain-Services role"
$feat = Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools
if (-not $feat.Success) { Fail "Role install failed." }
Write-Ok "AD DS role installed (with RSAT tools: ADUC, GPMC, etc.)"

# ---------------------------------------------------------------------------
# 2. PROMOTE TO FIRST DC OF A NEW FOREST
# ---------------------------------------------------------------------------
Write-Step "Promoting to first Domain Controller of forest '$DomainName'"
Write-Host "You will be prompted for the DSRM (Directory Services Restore Mode) password." -ForegroundColor Yellow
Write-Host "Write it down — it is your break-glass recovery password for this DC." -ForegroundColor Yellow

Import-Module ADDSDeployment

# Domain and forest functional level: WinThreshold (2016) is the safe modern floor
# that still supports every feature this lab needs (Protected Users, etc.).
Install-ADDSForest `
    -DomainName $DomainName `
    -DomainNetbiosName $NetbiosName `
    -ForestMode 'WinThreshold' `
    -DomainMode 'WinThreshold' `
    -InstallDns:$true `
    -CreateDnsDelegation:$false `
    -DatabasePath 'C:\Windows\NTDS' `
    -LogPath 'C:\Windows\NTDS' `
    -SysvolPath 'C:\Windows\SYSVOL' `
    -NoRebootOnCompletion:$false `
    -Force:$true

# Install-ADDSForest reboots the machine automatically on success.
# After reboot, you'll log in as CORP\Administrator.
Write-Ok "Promotion initiated — the VM will reboot into the new domain."
