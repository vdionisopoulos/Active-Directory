#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Lab setup — Step 1 (run on the HOST laptop, elevated).
    Validates Hyper-V prerequisites, creates the lab virtual switch, and
    provisions the DC01 virtual machine ready for OS installation.

.DESCRIPTION
    This script does NOT install the operating system — after it finishes,
    you connect to the VM and click through Windows Server 2025 Setup manually
    (choosing "Desktop Experience" so you get the GUI for screenshots).

    Idempotent-ish: it checks for existing switch/VM and skips re-creating them.

.NOTES
    Author : AD Security Roadmap lab
    Target : Windows 10/11 Pro/Enterprise host with Hyper-V, 32 GB RAM
#>

[CmdletBinding()]
param(
    # Full path to the Windows Server 2025 evaluation ISO you downloaded.
    [string]$IsoPath = "C:\Lab\ISO\WindowsServer2025.iso",

    # Where VM disks live. Pick a drive with >= 80 GB free.
    [string]$VmRoot  = "C:\Lab\VMs",

    [string]$VmName  = "DC01",
    [string]$SwitchName = "AD-Lab-Net",

    [int64]$MemoryStartupBytes = 4GB,
    [int64]$MemoryMaxBytes     = 6GB,
    [int64]$DiskSizeBytes      = 80GB,
    [int]$ProcessorCount       = 2
)

$ErrorActionPreference = 'Stop'

function Write-Step  { param($m) Write-Host "`n=== $m ===" -ForegroundColor Cyan }
function Write-Ok    { param($m) Write-Host "[OK]  $m" -ForegroundColor Green }
function Write-Warn2 { param($m) Write-Host "[!!]  $m" -ForegroundColor Yellow }
function Fail        { param($m) Write-Host "[XX]  $m" -ForegroundColor Red; exit 1 }

# ---------------------------------------------------------------------------
# 0. PRECONDITIONS — this is the "which edition am I on" check you asked about
# ---------------------------------------------------------------------------
Write-Step "Checking host prerequisites"

$os = Get-CimInstance Win32_OperatingSystem
$edition = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').EditionID
Write-Host "Host OS      : $($os.Caption)"
Write-Host "Edition ID   : $edition"

# Hyper-V is NOT available on Home editions. Detect and stop early.
if ($edition -match 'Core|Home') {
    Fail @"
This host is a HOME edition of Windows. Hyper-V is not available here.
Options:
  1. Upgrade this machine to Windows Pro (Settings > System > Activation).
  2. Use VirtualBox instead (free, works on Home) — tell me and I'll adjust the lab.
"@
}
Write-Ok "Edition supports Hyper-V"

# Is the Hyper-V feature actually installed & the module present?
$hv = Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All -ErrorAction SilentlyContinue
if (-not $hv -or $hv.State -ne 'Enabled') {
    Write-Warn2 "Hyper-V feature is not enabled yet."
    Write-Host "Enable it with (REQUIRES A REBOOT), then re-run this script:" -ForegroundColor Yellow
    Write-Host '  Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All -All' -ForegroundColor Gray
    Fail "Hyper-V not enabled — enable, reboot, re-run."
}
Write-Ok "Hyper-V feature enabled"

if (-not (Get-Module -ListAvailable -Name Hyper-V)) {
    Fail "Hyper-V PowerShell module missing. Install 'Hyper-V Module for Windows PowerShell' feature."
}
Import-Module Hyper-V
Write-Ok "Hyper-V PowerShell module loaded"

# Confirm Hyper-V is actually operational.
# NOTE: we deliberately do NOT test $os.HypervisorPresent here. That WMI property
# can report $false on a perfectly working host when Virtualization-Based Security
# (VBS) / memory integrity is enabled, because VBS changes how the hypervisor is
# surfaced to the OS. Instead we ask Hyper-V directly whether it can act as a host.
try {
    Get-VMHost -ErrorAction Stop | Out-Null
    Write-Ok "Hyper-V host is operational"
} catch {
    Fail @"
Hyper-V host is not reachable: $($_.Exception.Message)
Check that:
  - The hypervisor launches at boot:  bcdedit /set hypervisorlaunchtype auto  (then reboot)
  - Virtualization (VT-x/AMD-V) is enabled in BIOS/UEFI.
"@
}

# RAM sanity — we want to run 4 VMs eventually
$totalRamGB = [math]::Round($os.TotalVisibleMemorySize / 1MB, 0)
Write-Host "Total host RAM : $totalRamGB GB"
if ($totalRamGB -lt 16) {
    Write-Warn2 "Less than 16 GB detected — the full 4-VM lab may swap. DC-only is fine."
}

# ISO present?
if (-not (Test-Path $IsoPath)) {
    Fail @"
ISO not found at: $IsoPath
Download the Windows Server 2025 evaluation ISO from the Microsoft Evaluation
Center, place it there (or pass -IsoPath), then re-run.
"@
}
Write-Ok "ISO found: $IsoPath"

# ---------------------------------------------------------------------------
# 1. FOLDERS
# ---------------------------------------------------------------------------
Write-Step "Preparing folders"
$vmPath  = Join-Path $VmRoot $VmName
$vhdPath = Join-Path $vmPath "$VmName.vhdx"
New-Item -ItemType Directory -Path $vmPath -Force | Out-Null
Write-Ok "VM folder: $vmPath"

# ---------------------------------------------------------------------------
# 2. VIRTUAL SWITCH — internal (isolated lab network, no internet by default)
# ---------------------------------------------------------------------------
Write-Step "Ensuring internal virtual switch '$SwitchName'"
# Internal (not Private) so the HOST can also reach the lab for file copy / RSAT,
# but the lab is NOT bridged to your real LAN. This keeps attack traffic contained.
if (Get-VMSwitch -Name $SwitchName -ErrorAction SilentlyContinue) {
    Write-Ok "Switch already exists"
} else {
    New-VMSwitch -Name $SwitchName -SwitchType Internal | Out-Null
    Write-Ok "Created internal switch"
    Write-Warn2 "Lab network is ISOLATED (no internet). That is deliberate for a security lab."
    Write-Host "  If a VM needs updates later, temporarily attach an External switch." -ForegroundColor Gray
}

# ---------------------------------------------------------------------------
# 3. CREATE THE VM
# ---------------------------------------------------------------------------
Write-Step "Creating VM '$VmName'"
if (Get-VM -Name $VmName -ErrorAction SilentlyContinue) {
    Fail "A VM named '$VmName' already exists. Remove it first or choose another name."
}

# Generation 2 = UEFI, Secure Boot, modern. Required for a clean 2025 install.
New-VM -Name $VmName -MemoryStartupBytes $MemoryStartupBytes `
       -Generation 2 -Path $VmRoot -SwitchName $SwitchName | Out-Null
Write-Ok "VM shell created (Gen 2, UEFI)"

# Disk
New-VHD -Path $vhdPath -SizeBytes $DiskSizeBytes -Dynamic | Out-Null
Add-VMHardDiskDrive -VMName $VmName -Path $vhdPath
Write-Ok "Dynamic $([math]::Round($DiskSizeBytes/1GB)) GB disk attached"

# DVD with the ISO, set as first boot device
Add-VMDvdDrive -VMName $VmName -Path $IsoPath
$dvd = Get-VMDvdDrive -VMName $VmName
Set-VMFirmware -VMName $VmName -FirstBootDevice $dvd
Write-Ok "ISO mounted and set as first boot device"

# CPU + dynamic memory
Set-VMProcessor -VMName $VmName -Count $ProcessorCount
Set-VMMemory -VMName $VmName -DynamicMemoryEnabled $true `
             -MinimumBytes 2GB -StartupBytes $MemoryStartupBytes -MaximumBytes $MemoryMaxBytes
Write-Ok "$ProcessorCount vCPU, dynamic memory 2–$([math]::Round($MemoryMaxBytes/1GB)) GB"

# Secure Boot with the Microsoft UEFI template (needed for Windows Gen2)
Set-VMFirmware -VMName $VmName -EnableSecureBoot On -SecureBootTemplate 'MicrosoftWindows'
Write-Ok "Secure Boot on (Microsoft template)"

# Checkpoints: use Production checkpoints (VSS-consistent), keep them manual so a
# stray auto-checkpoint doesn't interfere with your attack/verify snapshots.
Set-VM -Name $VmName -CheckpointType Production -AutomaticCheckpointsEnabled $false
Write-Ok "Production checkpoints enabled; automatic checkpoints OFF"

# ---------------------------------------------------------------------------
# 4. START + GUIDANCE
# ---------------------------------------------------------------------------
Write-Step "Starting VM and opening console"
Start-VM -Name $VmName
Start-Sleep -Seconds 2
vmconnect.exe localhost $VmName

Write-Host ""
Write-Host "DC01 is booting from the ISO. Now, in the VM console window:" -ForegroundColor Cyan
Write-Host @"
  1. Press a key when prompted to boot from DVD.
  2. In Setup, choose:  Windows Server 2025 Standard (Desktop Experience)
       -> 'Desktop Experience' gives you the GUI (ADUC, GPMC) for screenshots.
       -> Do NOT pick the plain 'Standard' (that is Server Core, no GUI).
  3. Custom install -> the 80 GB disk -> Next.
  4. Set the local Administrator password (write it down; lab-only).
  5. After first logon, set a static IP and rename to DC01:

     Rename-Computer -NewName 'DC01' -Restart
     # after reboot, then:
     New-NetIPAddress -InterfaceAlias 'Ethernet' -IPAddress 10.0.0.10 ``
         -PrefixLength 24 -DefaultGateway 10.0.0.1
     Set-DnsClientServerAddress -InterfaceAlias 'Ethernet' -ServerAddresses 127.0.0.1

  6. Then run Script 2 (02-Promote-DC01.ps1) INSIDE the VM.
"@ -ForegroundColor Gray

Write-Host "`nDone. When the OS is installed and IP set, tell me and run Script 2." -ForegroundColor Green
