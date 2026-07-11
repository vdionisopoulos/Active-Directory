# Lab — a reproducible AD environment for testing the controls

The guides in this repository describe attacks and defenses. This directory builds a **safe, isolated lab** where you can reproduce each attack, apply the corresponding control, and confirm it works — with screenshots or video for your own notes.

> **Isolation first.** The lab uses an **internal** Hyper-V switch with no bridge to your real network. Attack traffic (Responder poisoning, relay, credential dumping) stays contained. Never run these techniques against production or any network you don't own.

## What you'll build

| VM | OS | Role | RAM | IP |
|----|----|----|-----|-----|
| **DC01** | Windows Server 2025 (Desktop Experience) | Domain Controller, DNS — forest `corp.lab` | 4–6 GB | 10.0.0.10 |
| **WS01** | Windows 11 Enterprise (eval) | Domain-joined workstation (victim) | 4 GB | 10.0.0.20 |
| **WS02** | Windows 11 Enterprise (eval) | Second workstation (pass-the-hash target) | 4 GB | 10.0.0.21 |
| **ATTACK** | Kali Linux | Responder, impacket, offensive tooling | 4 GB | 10.0.0.50 |

Two workstations are needed because lateral-movement demos (pass-the-hash, LAPS) require at least two machines that initially share a local admin password.

On a 32 GB host all four run comfortably. For DC-only work, DC01 alone is enough.

## Requirements

- Windows 10/11 **Pro or Enterprise** host (Hyper-V is not available on Home editions).
- Hyper-V feature enabled: `Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All -All` (requires a reboot).
- Hardware virtualization (VT-x/AMD-V) enabled in BIOS/UEFI.
- Evaluation ISOs (all free, no product key needed for the eval period):
  - Windows Server 2025 — Microsoft Evaluation Center (180 days)
  - Windows 11 Enterprise — Microsoft Evaluation Center (90 days)
  - Kali Linux — kali.org (a prebuilt Hyper-V image is available)

## Scripts

| Script | Runs on | Purpose |
|--------|---------|---------|
| `01-Create-DC01-VM.ps1` | **Host** (elevated) | Validates Hyper-V prerequisites, creates the internal switch, provisions the DC01 VM, boots it from the ISO. |
| `02-Promote-DC01.ps1` | **Inside DC01** (elevated) | Installs AD DS + DNS and promotes DC01 to the first DC of forest `corp.lab`. |

### Step 1 — create the VM (on the host)

```powershell
# Unblock the scripts (they came from the internet) and allow this session to run them
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
Unblock-File .\01-Create-DC01-VM.ps1
Unblock-File .\02-Promote-DC01.ps1

# Place the Server 2025 ISO at C:\Lab\ISO\WindowsServer2025.iso (or pass -IsoPath)
.\01-Create-DC01-VM.ps1
```

The script stops early with a clear message if any prerequisite is missing (wrong edition, Hyper-V not enabled, ISO not found). When it finishes, the VM is booting from the ISO.

### Manual OS install

In the VM console:

1. Press a key to boot from DVD when prompted.
2. Choose **Windows Server 2025 Standard (Desktop Experience)** — the Desktop Experience gives you the GUI (ADUC, GPMC) you need for screenshots. Do **not** pick the plain edition (that is Server Core, no GUI).
3. Custom install → the 80 GB disk → Next.
4. Set the local Administrator password (lab-only; write it down).
5. Rename and set a static IP:

   ```powershell
   Rename-Computer -NewName 'DC01' -Restart
   # after reboot:
   New-NetIPAddress -InterfaceAlias 'Ethernet' -IPAddress 10.0.0.10 -PrefixLength 24 -DefaultGateway 10.0.0.1
   Set-DnsClientServerAddress -InterfaceAlias 'Ethernet' -ServerAddresses 127.0.0.1
   ```

### Step 2 — promote to Domain Controller (inside DC01)

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
.\02-Promote-DC01.ps1
```

It checks the hostname and IP, installs AD DS, prompts for a DSRM password, creates the `corp.lab` forest, and reboots. After reboot you log in as `CORP\Administrator` to a working domain.

## Snapshots — the key to clean demos

Take a Hyper-V **checkpoint** at each meaningful state so you can capture "before" and "after" cleanly and roll back instantly:

```powershell
Checkpoint-VM -Name DC01 -SnapshotName '01-clean-domain'
# ...introduce a weak configuration, capture the attack succeeding...
Checkpoint-VM -Name DC01 -SnapshotName '02-vulnerable'
# ...apply the control, capture the attack failing...
Checkpoint-VM -Name DC01 -SnapshotName '03-hardened'
```

## A note on execution policy

`Set-ExecutionPolicy -Scope Process Bypass` relaxes script execution **for the current window only** — it reverts when you close it and changes nothing permanently. Execution policy is a safety rail against accidental double-clicks, not a security boundary; relaxing it per-session for scripts you've read is the correct approach.

## Roadmap

Attack/defense walkthroughs (mapped to each maturity level, with capture points) will be added here as `demos/`. Planned first: pass-the-hash across a shared local admin password → defeated by Windows LAPS (Level 2.1).
