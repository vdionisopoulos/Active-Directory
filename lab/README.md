# Lab — a reproducible AD environment for testing the controls

The guides in this repository describe attacks and defenses. This directory builds a **safe, isolated lab** where you can reproduce each attack, apply the corresponding control, and confirm it works — with screenshots or video for your own notes.

> **Isolation first.** The lab uses an **internal** Hyper-V switch with no bridge to your real network. Attack traffic (poisoning, relay, credential dumping) stays contained. Never run these techniques against production or any network you don't own.

---

## Table of contents

- [What you'll build](#what-youll-build)
- [Requirements](#requirements)
- [Scripts](#scripts)
- [Part A — Build DC01 (the domain controller)](#part-a--build-dc01)
- [Part B — Build the workstations (WS01, WS02)](#part-b--build-the-workstations)
- [Part C — Build the attacker (Kali)](#part-c--build-the-attacker-kali)
- [Part D — Arm the deliberate vulnerability](#part-d--arm-the-deliberate-vulnerability)
- [Snapshots](#snapshots)
- [Troubleshooting reference](#troubleshooting-reference)
- [Demos](#demos)

---

## What you'll build

| VM | OS | Role | RAM | IP |
|----|----|----|-----|-----|
| **DC01** | Windows Server 2025 (Desktop Experience) | Domain Controller, DNS — forest `corp.lab` | 4–6 GB | 10.0.0.10 |
| **WS01** | Windows 11 Enterprise (eval) | Domain-joined workstation (first victim) | 4 GB | 10.0.0.20 |
| **WS02** | Windows 11 Enterprise (eval) | Domain-joined workstation (lateral-movement target) | 4 GB | 10.0.0.21 |
| **ATTACK** | Kali Linux | Attacker (impacket and offensive tooling) | 4 GB | 10.0.0.50 |

Network: a single isolated internal switch, `AD-Lab-Net`, subnet `10.0.0.0/24`, gateway `10.0.0.1` (nominal — there is no real gateway in an isolated lab).

Two workstations are required because lateral-movement demos (pass-the-hash, LAPS) need at least two machines that initially share a local admin password. On a 32 GB host all four run comfortably; for DC-only work, DC01 alone suffices.

---

## Requirements

- Windows 10/11 **Pro or Enterprise** host — Hyper-V is not available on Home editions.
- Hyper-V enabled: `Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All -All` (requires a reboot).
- Hardware virtualization (VT-x/AMD-V) enabled in BIOS/UEFI.
- Evaluation ISOs (all free, no product key for the eval period):
  - **Windows Server 2025** — Microsoft Evaluation Center (180 days)
  - **Windows 11 Enterprise** — Microsoft Evaluation Center (90 days)
  - **Kali Linux** — kali.org (installer ISO, or a prebuilt Hyper-V image)

Place the ISOs under `C:\Lab\ISO\` (the scripts default to that path):
`WindowsServer2025.iso`, `Windows11-Enterprise-Eval.iso`, `kali-linux.iso`.

---

## Scripts

| Script | Runs on | Purpose |
|--------|---------|---------|
| `01-Create-DC01-VM.ps1` | **Host** (elevated) | Validates Hyper-V prerequisites, creates the internal switch, provisions DC01, boots it from the ISO. |
| `02-Promote-DC01.ps1` | **Inside DC01** (elevated) | Installs AD DS + DNS and promotes DC01 to the first DC of forest `corp.lab`. |
| `03-Create-Lab-VMs.ps1` | **Host** (elevated) | Provisions WS01, WS02 (Windows 11, TPM 2.0 enabled) and ATTACK (Kali), all on the isolated switch. |

Before running any script, unblock it and allow the current session to execute it:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
Unblock-File .\01-Create-DC01-VM.ps1   # repeat per script
```

`Set-ExecutionPolicy -Scope Process Bypass` relaxes execution **for the current window only** — it reverts on close and changes nothing permanently. Execution policy is a safety rail against accidental double-clicks, not a security boundary; relaxing it per-session for scripts you've read is the correct approach.

---

## Part A — Build DC01

### A.1 Create the VM (host)

```powershell
.\01-Create-DC01-VM.ps1
```

The script validates edition/Hyper-V/virtualization/RAM/ISO and stops early with a clear message if anything is missing, then creates the `AD-Lab-Net` internal switch, provisions DC01 (Gen 2 / UEFI, 4–6 GB dynamic RAM, 80 GB dynamic disk, Secure Boot, production checkpoints), and boots it from the ISO.

### A.2 Install the OS (in the VM console)

1. Press a key to boot from DVD when prompted.
2. Choose **Windows Server 2025 Standard (Desktop Experience)** — the Desktop Experience gives you the GUI (ADUC, GPMC) needed for screenshots. Do **not** pick the plain edition (Server Core, no GUI).
3. Custom install → the 80 GB disk → Next.
4. Set the local Administrator password (lab-only; write it down).
5. Rename and set a static IP; a DC points DNS at itself:

   ```powershell
   Rename-Computer -NewName 'DC01' -Restart
   # after reboot:
   New-NetIPAddress -InterfaceAlias 'Ethernet' -IPAddress 10.0.0.10 -PrefixLength 24 -DefaultGateway 10.0.0.1
   Set-DnsClientServerAddress -InterfaceAlias 'Ethernet' -ServerAddresses 127.0.0.1
   ```

### A.3 Promote to Domain Controller (inside DC01)

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
.\02-Promote-DC01.ps1
```

It checks hostname and IP, installs AD DS, prompts for a DSRM (Directory Services Restore Mode) password, creates the `corp.lab` forest, and reboots. The DNS-delegation warning during promotion is expected and harmless in an isolated lab. After reboot, log in as `CORP\Administrator`.

Confirm the domain is live:

```powershell
Get-ADDomain | Select-Object DNSRoot, NetBIOSName, DomainMode
Get-ADForest | Select-Object RootDomain, ForestMode
```

Expected: `corp.lab`, `CORP`, `Windows2016Domain` / `Windows2016Forest`.

---

## Part B — Build the workstations

### B.1 Create WS01 and WS02 (host)

```powershell
.\03-Create-Lab-VMs.ps1
```

This provisions WS01, WS02 (and ATTACK — see Part C) on `AD-Lab-Net`. The Windows VMs are created Gen 2 with Secure Boot **and TPM 2.0 enabled** — both are mandatory or Windows 11 Setup refuses to install with *"This PC doesn't currently meet Windows 11 system requirements."*

> **If you built the workstations before TPM was enabled** (or by hand), enable it while the VM is **off**:
> ```powershell
> Stop-VM -Name WS01,WS02 -Force
> foreach ($vm in 'WS01','WS02') {
>     Set-VMKeyProtector -VMName $vm -NewLocalKeyProtector   # TPM needs a key protector first
>     Enable-VMTPM -VMName $vm
>     Get-VMSecurity -VMName $vm | Select-Object @{n='VM';e={$vm}}, TpmEnabled
> }
> Start-VM -Name WS01,WS02
> ```
> `TpmEnabled : True` on both, and Setup proceeds.

### B.2 Install Windows 11 (in each VM console)

- Watch for **"Press any key to boot from CD or DVD"** — press one within ~5 seconds or the VM falls through to PXE (which fails on the isolated network). If it does, `Stop-VM` / `Start-VM` and try again.
- During OOBE, create a **local account** (Enterprise eval doesn't require a Microsoft account — use the offline / "domain join instead" path).

### B.3 Network each workstation (in each VM, elevated)

DNS **must** point at the DC (`10.0.0.10`) or domain join fails.

```powershell
# WS01
New-NetIPAddress -InterfaceAlias 'Ethernet' -IPAddress 10.0.0.20 -PrefixLength 24 -DefaultGateway 10.0.0.1
Set-DnsClientServerAddress -InterfaceAlias 'Ethernet' -ServerAddresses 10.0.0.10

# WS02 — identical but 10.0.0.21
```

Verify each workstation can see the DC before joining:

```powershell
Test-NetConnection 10.0.0.10 -Port 389   # TcpTestSucceeded : True
Resolve-DnsName corp.lab                 # returns 10.0.0.10
```

### B.4 Join the domain (in each VM, elevated)

```powershell
# WS01 (use 'WS02' for the second machine)
Add-Computer -DomainName 'corp.lab' -NewName 'WS01' -Credential (Get-Credential CORP\Administrator) -Restart
```

`Add-Computer -NewName` joins and renames in one step. After reboot, confirm:

```powershell
(Get-WmiObject Win32_ComputerSystem).Domain   # corp.lab
```

### B.5 Open the firewall for the lab (in each VM, elevated)

Windows 11 blocks inbound SMB and ICMP by default, which prevents the attacks from reaching the victim. For a lab, allow them explicitly:

```powershell
New-NetFirewallRule -DisplayName "Lab-Allow-ICMP" -Protocol ICMPv4 -IcmpType 8 -Action Allow -Profile Any
New-NetFirewallRule -DisplayName "Lab-Allow-SMB" -Direction Inbound -Protocol TCP -LocalPort 445 -Action Allow -Profile Any
```

(Alternatively, for lab speed, disable the firewall entirely: `Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False`. The targeted rules are more realistic — SMB *is* open between machines in real networks.)

### B.6 Allow remote local-admin logon (in each VM, elevated)

By default Windows filters the token of a **local** admin authenticating remotely (UAC remote restriction), so pass-the-hash with a local account fails at logon. Setting `LocalAccountTokenFilterPolicy = 1` reflects the many real environments where management tooling has already enabled it, and is required for the pass-the-hash demo:

```powershell
New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' `
    -Name 'LocalAccountTokenFilterPolicy' -Value 1 -PropertyType DWord -Force
```

No reboot needed.

---

## Part C — Build the attacker (Kali)

### C.1 Create the VM (host)

`03-Create-Lab-VMs.ps1` also provisions **ATTACK**. Kali is created with Secure Boot **off** (the Microsoft UEFI template won't boot Linux) and **no TPM**. Install Kali normally from the ISO.

### C.2 Give Kali the lab IP (in Kali)

There is no DHCP on the isolated network, so set the lab address statically on the lab NIC (`eth0`):

```bash
sudo ip addr add 10.0.0.50/24 dev eth0
ip addr show eth0 | grep inet          # inet 10.0.0.50/24
```

### C.3 Install tooling — needs internet once (host + Kali)

Kali needs internet **once** to install/update tools. Attach a second NIC on Hyper-V's NAT-capable **Default Switch**, install, then remove it to re-isolate.

On the **host**:

```powershell
Add-VMNetworkAdapter -VMName ATTACK -SwitchName 'Default Switch'
```

In **Kali** (the new interface is usually `eth1`, DHCP):

```bash
sudo dhclient -v
ping -c 2 8.8.8.8                       # confirm internet

sudo apt update
sudo apt install -y python3-impacket
which impacket-secretsdump impacket-psexec impacket-wmiexec
```

The tools this lab uses from **impacket**:

| Tool | Used for |
|------|----------|
| `impacket-secretsdump` | Remotely dump the SAM / LSA secrets (NTLM hashes) from a target. |
| `impacket-psexec` | Execute commands on a target via SMB + a temporary service — supports pass-the-hash (`-hashes`). |
| `impacket-wmiexec` | Command execution over WMI (alternative to psexec). |

Kali also ships with the broader offensive toolset (Responder, CrackMapExec/NetExec, Rubeus via wine, BloodHound collectors, hashcat) used by later demos.

### C.4 Re-isolate Kali (host)

Once tooling is installed, remove the internet NIC so all attacks run on the isolated network:

```powershell
Get-VMNetworkAdapter -VMName ATTACK | Where-Object SwitchName -eq 'Default Switch' | Remove-VMNetworkAdapter
```

Confirm from Kali that it still reaches the lab (the SMB port is the meaningful test, since Windows may not answer ping):

```bash
nc -zv 10.0.0.20 445                    # (UNKNOWN) [10.0.0.20] 445 (microsoft-ds) open
```

---

## Part D — Arm the deliberate vulnerability

The pass-the-hash demo (Demo 1) requires WS01 and WS02 to share the **same** local Administrator password — the exact misconfiguration LAPS eliminates. Enable the account first, then set the password (order matters: after domain join, the domain password policy can reject `net user /active:yes` if the password is set first).

On **both** WS01 and WS02 (elevated):

```powershell
Enable-LocalUser -Name Administrator
$pw = ConvertTo-SecureString "Lab-Shared-P@ss123" -AsPlainText -Force
Set-LocalUser -Name Administrator -Password $pw
Get-LocalUser Administrator | Select-Object Name, Enabled     # Enabled : True
```

> On some builds `Get-LocalUser` / `Set-LocalUser` may be unavailable in the default shell; use `net user` instead:
> ```powershell
> net user Administrator /active:yes
> net user Administrator "Lab-Shared-P@ss123"
> net user Administrator | Select-String "Account active"     # Yes
> ```

**Same password on both** — that shared value is the vulnerability. The lab is now complete.

---

## Snapshots

Take a Hyper-V **checkpoint** at each meaningful state so you can capture "before"/"after" cleanly and roll back instantly. Snapshot all four VMs together at each milestone:

```powershell
Checkpoint-VM -Name DC01,WS01,WS02,ATTACK -SnapshotName '01-clean-domain'
Checkpoint-VM -Name DC01,WS01,WS02,ATTACK -SnapshotName '02-lab-ready'
Checkpoint-VM -Name DC01,WS01,WS02,ATTACK -SnapshotName '03-demo1-complete'
```

The scripts set VMs to **Production** checkpoints with **automatic** checkpoints off, so a stray auto-checkpoint doesn't interfere with your attack/verify snapshots.

---

## Troubleshooting reference

Issues encountered building this lab, and their fixes — so you don't have to rediscover them.

| Symptom | Cause | Fix |
|---------|-------|-----|
| *"This PC doesn't currently meet Windows 11 system requirements"* | TPM 2.0 not enabled on the VM | Stop the VM; `Set-VMKeyProtector -NewLocalKeyProtector` then `Enable-VMTPM` (Part B.1) |
| VM boots to `Start PXE over IPv4` | Missed the "press any key" boot-from-DVD prompt | `Stop-VM` / `Start-VM`, press a key within ~5 s |
| `01-Create-DC01-VM.ps1` fails "No hypervisor present" although Hyper-V works | Buggy `HypervisorPresent` check with VBS/memory-integrity enabled | Fixed in current script (uses `Get-VMHost`); ensure `bcdedit /enum` shows `hypervisorlaunchtype Auto` |
| Domain join fails to find the domain | Workstation DNS not pointing at the DC | `Set-DnsClientServerAddress ... -ServerAddresses 10.0.0.10` (Part B.3) |
| Attacker can't reach WS (`ping`/`nc 445` fail) | Windows 11 firewall blocks SMB/ICMP | Allow rules on the WS (Part B.5) |
| `impacket-psexec` with a hash → `STATUS_LOGON_FAILURE` | UAC remote-restriction filters the local-admin token | `LocalAccountTokenFilterPolicy = 1` on the target (Part B.6) |
| `impacket-psexec` with a **local** account → `STATUS_LOGON_FAILURE` even with correct hash | recent impacket needs the local-account marker | prefix the username: `./Administrator@10.0.0.21` |
| psexec authenticates but `Error performing the uninstallation` | Windows Defender quarantined the default impacket service binary | Expected — see the "defense in depth" note in Demo 1; not an auth failure |
| `Set-MpPreference -DisableRealtimeMonitoring $true` has no effect | Tamper Protection blocks programmatic disable | Expected on modern Win11; disable via Windows Security UI + reboot if truly needed |
| Kali `eth0` has no IP | No DHCP on the isolated switch | `sudo ip addr add 10.0.0.50/24 dev eth0` (Part C.2) |
| After a reboot, Kali `eth0` has no IPv4 and a second `eth1` sits on `192.168.178.x`; attacks time out | ATTACK came back up with an external adapter (e.g. `Cable Switch`) still attached — this is why a previously "re-isolated" box loses isolation across reboots | On the host: `Get-VMNetworkAdapter -VMName ATTACK \| ? SwitchName -eq 'Cable Switch' \| Remove-VMNetworkAdapter`, then re-add the lab IP on `eth0` |
| Kali: `ping ... Network is unreachable` even though `eth0` shows `10.0.0.50` | No connected route for the subnet (IP added without a matching route, or NetworkManager cleared it) | `sudo ip route add 10.0.0.0/24 dev eth0` |
| Host `ssh <kali>` times out after isolating Kali | Host has no interface on the internal switch's subnet, so no path to `10.0.0.50` | `New-NetIPAddress -InterfaceAlias 'vEthernet (AD-Lab-Net)' -IPAddress 10.0.0.1 -PrefixLength 24` (elevated) — this is the correct way to SSH an internet-less Kali |
| `New-NetIPAddress ... Access is denied` (error 5) | PowerShell not elevated; Hyper-V / NetTCPIP cmdlets need admin | Run PowerShell as Administrator |
| `rdate` / `ntpdate: command not found`, and no internet to install them | Isolated Kali can't reach a time source; Kerberos rejects tickets on >5 min clock skew | Set time by hand in UTC from the DC: `(Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss")` on DC01, then `sudo date -u -s "..."` on Kali |
| hashcat: `No OpenCL ... platform found` | A Hyper-V VM exposes no GPU/OpenCL runtime | Crack with John the Ripper on CPU instead (`john --format=krb5tgs ...`) |

---

## Demos

Attack/defense walkthroughs, each mapped to a maturity level, with proof screenshots:

| Demo | Maps to | Shows |
|------|---------|-------|
| [01 — Pass-the-Hash vs LAPS](demos/01-pass-the-hash-laps/) | [Level 2.1](../docs/02-quick-wins/README.md#21-windows-laps) | Shared local admin password → lateral movement; unique passwords (LAPS) stop it. |
| [02 — Kerberoasting vs gMSA](demos/02-kerberoasting-gmsa/) | [Level 3](../docs/03-credential-hardening/README.md) | Any authenticated user roasts a weak service account offline; a gMSA + AES-only makes the same attack find nothing. |

More demos planned: DCSync / BloodHound attack paths (Level 3.5), and tier-violation detection (Level 4).
