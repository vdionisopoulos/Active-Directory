#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Lab setup — Step 3 (run on the HOST laptop, elevated).
    Provisions the remaining three lab VMs: WS01, WS02 (Windows 11 victims)
    and ATTACK (Kali Linux), all attached to the isolated AD-Lab-Net switch.

.DESCRIPTION
    Creates the VM shells and boots each from its ISO. OS installation is manual
    (click-through), same as DC01. This does NOT domain-join the workstations —
    that's done after install (instructions printed at the end).

    Prerequisite: DC01 exists and the AD-Lab-Net switch is present
    (created by 01-Create-DC01-VM.ps1).

.NOTES
    Author : AD Security Roadmap lab
#>

[CmdletBinding()]
param(
    [string]$Win11IsoPath = "C:\Lab\ISO\Windows11-Enterprise-Eval.iso",
    [string]$KaliIsoPath  = "C:\Lab\ISO\kali-linux.iso",
    [string]$VmRoot       = "C:\Lab\VMs",
    [string]$SwitchName   = "AD-Lab-Net",
    [int64]$WorkstationMemory = 4GB,
    [int64]$AttackMemory      = 4GB,
    [int64]$DiskSizeBytes     = 60GB
)

$ErrorActionPreference = 'Stop'

function Write-Step { param($m) Write-Host "`n=== $m ===" -ForegroundColor Cyan }
function Write-Ok   { param($m) Write-Host "[OK]  $m" -ForegroundColor Green }
function Write-Warn2{ param($m) Write-Host "[!!]  $m" -ForegroundColor Yellow }
function Fail       { param($m) Write-Host "[XX]  $m" -ForegroundColor Red; exit 1 }

# ---------------------------------------------------------------------------
# 0. PRECONDITIONS
# ---------------------------------------------------------------------------
Write-Step "Checking prerequisites"
Import-Module Hyper-V -ErrorAction Stop

try { Get-VMHost -ErrorAction Stop | Out-Null; Write-Ok "Hyper-V host operational" }
catch { Fail "Hyper-V host not reachable: $($_.Exception.Message)" }

if (-not (Get-VMSwitch -Name $SwitchName -ErrorAction SilentlyContinue)) {
    Fail "Switch '$SwitchName' not found. Run 01-Create-DC01-VM.ps1 first."
}
Write-Ok "Lab switch '$SwitchName' present"

if (-not (Get-VM -Name DC01 -ErrorAction SilentlyContinue)) {
    Write-Warn2 "DC01 not found — the workstations will have nothing to join. Continue anyway."
}

# ---------------------------------------------------------------------------
# Helper: create one Gen2 Windows-style VM booting from an ISO
# ---------------------------------------------------------------------------
function New-LabVM {
    param(
        [string]$Name,
        [string]$IsoPath,
        [int64]$Memory,
        [bool]$SecureBoot = $true,
        [string]$SecureBootTemplate = 'MicrosoftWindows'
    )

    if (-not (Test-Path $IsoPath)) {
        Write-Warn2 "ISO not found for $Name at: $IsoPath  — SKIPPING this VM."
        return
    }
    if (Get-VM -Name $Name -ErrorAction SilentlyContinue) {
        Write-Warn2 "$Name already exists — SKIPPING."
        return
    }

    Write-Step "Creating $Name"
    $vmDir  = Join-Path $VmRoot $Name
    $vhd    = Join-Path $vmDir "$Name.vhdx"
    New-Item -ItemType Directory -Path $vmDir -Force | Out-Null

    New-VM -Name $Name -MemoryStartupBytes $Memory -Generation 2 `
           -Path $VmRoot -SwitchName $SwitchName | Out-Null
    New-VHD -Path $vhd -SizeBytes $DiskSizeBytes -Dynamic | Out-Null
    Add-VMHardDiskDrive -VMName $Name -Path $vhd
    Add-VMDvdDrive -VMName $Name -Path $IsoPath
    $dvd = Get-VMDvdDrive -VMName $Name
    Set-VMFirmware -VMName $Name -FirstBootDevice $dvd
    Set-VMProcessor -VMName $Name -Count 2
    Set-VMMemory -VMName $Name -DynamicMemoryEnabled $true `
                 -MinimumBytes 2GB -StartupBytes $Memory -MaximumBytes ($Memory + 2GB)

    if ($SecureBoot) {
        Set-VMFirmware -VMName $Name -EnableSecureBoot On -SecureBootTemplate $SecureBootTemplate
        # Windows 11 requires TPM 2.0. In Hyper-V a TPM needs a key protector first.
        Set-VMKeyProtector -VMName $Name -NewLocalKeyProtector
        Enable-VMTPM -VMName $Name
    } else {
        # Kali / Linux: Secure Boot with the MS template will fail. Use the UEFI
        # 'MicrosoftUEFICertificateAuthority' template, or disable Secure Boot.
        # No TPM needed for Linux.
        Set-VMFirmware -VMName $Name -EnableSecureBoot Off
    }

    Set-VM -Name $Name -CheckpointType Production -AutomaticCheckpointsEnabled $false
    Write-Ok "$Name created ($([math]::Round($Memory/1GB)) GB, $([math]::Round($DiskSizeBytes/1GB)) GB disk, Secure Boot $([bool]$SecureBoot))"
}

# ---------------------------------------------------------------------------
# 1. CREATE THE VMs
# ---------------------------------------------------------------------------
New-LabVM -Name 'WS01'   -IsoPath $Win11IsoPath -Memory $WorkstationMemory -SecureBoot $true
New-LabVM -Name 'WS02'   -IsoPath $Win11IsoPath -Memory $WorkstationMemory -SecureBoot $true

# Kali: Secure Boot off (Linux images generally don't boot under the MS template)
New-LabVM -Name 'ATTACK' -IsoPath $KaliIsoPath  -Memory $AttackMemory      -SecureBoot $false

# ---------------------------------------------------------------------------
# 2. START THEM
# ---------------------------------------------------------------------------
Write-Step "Starting VMs"
foreach ($n in 'WS01','WS02','ATTACK') {
    if (Get-VM -Name $n -ErrorAction SilentlyContinue) {
        Start-VM -Name $n
        Write-Ok "$n started"
    }
}

# ---------------------------------------------------------------------------
# 3. POST-INSTALL GUIDANCE
# ---------------------------------------------------------------------------
Write-Host @"

=== Next: install each OS, then configure networking ===

WS01 / WS02 (Windows 11):
  - During OOBE, you can create a LOCAL account (no Microsoft account needed for
    Enterprise eval; use the 'domain join instead' / offline path).
  - After install, set a static IP and DNS pointing at the DC, then join:

      # WS01
      New-NetIPAddress -InterfaceAlias 'Ethernet' -IPAddress 10.0.0.20 ``
          -PrefixLength 24 -DefaultGateway 10.0.0.1
      Set-DnsClientServerAddress -InterfaceAlias 'Ethernet' -ServerAddresses 10.0.0.10
      Rename-Computer -NewName 'WS01' -Restart
      # after reboot:
      Add-Computer -DomainName 'corp.lab' -Credential (Get-Credential CORP\Administrator) -Restart

      # WS02 — identical but IP 10.0.0.21 and name WS02

  IMPORTANT for the pass-the-hash demo: give WS01 and WS02 the SAME local
  Administrator password initially (that shared password is the vulnerability
  you'll demonstrate, then fix with LAPS).

ATTACK (Kali):
  - Install normally. Set a static IP in the same subnet:
      sudo ip addr add 10.0.0.50/24 dev eth0
      # or configure via the GUI network manager, gateway 10.0.0.1, DNS 10.0.0.10
  - Kali needs internet ONCE to update tools (apt update; impacket, responder,
    etc.). Temporarily attach an External switch, update, then move it back to
    AD-Lab-Net for isolated attacks.

NETWORK ISOLATION NOTE:
  AD-Lab-Net is an INTERNAL switch — no route to your real LAN or the internet.
  This is deliberate. To give a VM temporary internet (Windows Update / apt):
    1. Create an external switch once:
       New-VMSwitch -Name 'Lab-External' -NetAdapterName '<your NIC>' -AllowManagementOS `$true
    2. Add a second NIC to the VM:  Add-VMNetworkAdapter -VMName WS01 -SwitchName 'Lab-External'
    3. Remove it again when done, to re-isolate.
"@ -ForegroundColor Gray

Write-Host "`nAll lab VMs provisioned. Install the OSes, then tell me and we pick the first demo." -ForegroundColor Green
