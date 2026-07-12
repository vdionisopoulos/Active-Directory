# Level 5 — Tiering Model

> **Prerequisite:** Levels 1–4 complete. Tiering is the capstone, not the starting point. Deploying it on an unhardened domain — kerberoastable service accounts, no LAPS, no detection — is theater: you've drawn boundaries around a domain that's already compromisable by other means.

This is the destination of the entire roadmap, and the part most guides get wrong. They describe the *model* — Tier 0, Tier 1, Tier 2 — as a static picture, copied from Microsoft's diagrams, and stop there. They never tell you the thing that actually matters: **how to get there from a flat domain without breaking production.** That migration is where every real tiering project lives or dies. This guide covers both.

A note on terminology, because you will encounter the old material: the legacy **ESAE / "Red Forest"** architecture (a separate hardened admin forest) is **retired** by Microsoft. Do not build one. The current guidance is the **Enterprise Access Model**, which achieves the same isolation through tiering, Privileged Access Workstations, and — where possible — cloud-based privileged identity. This guide follows the current model.

---

## Table of contents

- [5.1 The core idea — why tiering exists](#51-the-core-idea)
- [5.2 The three tiers defined](#52-the-three-tiers)
- [5.3 The building blocks — OUs, groups, logon restrictions, PAWs, silos](#53-the-building-blocks)
- [5.4 The migration path — flat to tiered without an outage](#54-the-migration-path)
- [5.5 What breaks, and in what order to expect it](#55-what-breaks)

---

## 5.1 The core idea

Every attack in this roadmap ultimately relies on one thing: **credential material ending up on a machine the attacker can reach.** Pass-the-hash, kerberoasting, DCSync — they all come down to harvesting a powerful credential from somewhere it shouldn't have been exposed.

Tiering is the structural answer. It divides identities and systems into **trust levels** and enforces one rule with absolute rigidity:

> **A credential is only ever exposed on systems at its own tier or higher. It never touches a lower tier.**

The reasoning is a containment argument. A Tier 2 workstation is the *most* likely thing to be compromised — it runs email, browsers, documents, the whole phishing attack surface. A Domain Controller (Tier 0) is the *most* protected. If a Domain Admin credential is *never* present on a Tier 2 workstation, then compromising that workstation — however easy — yields nothing that reaches Tier 0. The blast radius of a workstation compromise is contained to the workstation tier. You've broken the chain from "phished laptop" to "domain owned" at the structural level, not by hoping every control holds.

This is why tiering is the capstone: it doesn't add a new lock to pick. It removes the *reason* the earlier attacks lead anywhere. But it only works if the earlier levels hold — hence the strict prerequisite.

---

## 5.2 The three tiers

- **Tier 0 — the keys to the kingdom.** Identities and systems that control the identity infrastructure itself: Domain Controllers, the AD database, Domain/Enterprise Admins, ADFS/Entra Connect servers, PKI/CA, and any system that can gain administrative control over them. Compromise of Tier 0 = compromise of everything. This tier is tiny and fiercely guarded.

- **Tier 1 — servers and applications.** The member servers, applications, and their service/admin accounts — file servers, databases, business applications. A Tier 1 admin manages servers but has *no* control over the identity infrastructure. Compromise of Tier 1 loses data and services, but not the domain itself.

- **Tier 2 — workstations and users.** End-user devices and the help-desk/desktop-support accounts that manage them. The largest, most exposed tier. Compromise here is contained to user devices.

The enforced rule between them:

| Account tier | May log on to | May NOT log on to |
|--------------|---------------|-------------------|
| Tier 0 admin | Tier 0 systems only (DCs, Tier 0 PAWs) | Tier 1 servers, Tier 2 workstations |
| Tier 1 admin | Tier 1 servers, Tier 1 PAWs | Tier 0 systems, Tier 2 workstations |
| Tier 2 admin | Tier 2 workstations, Tier 2 PAWs | Tier 0 and Tier 1 systems |

The direction that matters most: **higher-tier accounts never log on to lower-tier machines.** That's the rule that contains blast radius. (Lower-tier accounts obviously can't log on to higher-tier machines either, but that's the easy half.)

---

## 5.3 The building blocks

Tiering is enforced by combining several mechanisms you've already met in earlier levels, now organized into a coherent structure.

### OU structure

Create a dedicated OU hierarchy that separates the tiers, so you can target GPOs and delegation cleanly:

```
Admin (Tier 0)
  ├── Tier 0 Accounts
  ├── Tier 0 Groups
  └── Tier 0 Servers (DCs live in the default Domain Controllers OU)
Tier 1
  ├── Tier 1 Accounts
  ├── Tier 1 Groups
  └── Tier 1 Servers
Tier 2
  ├── Tier 2 Accounts
  ├── Tier 2 Groups
  └── Tier 2 Workstations
```

### Logon-restriction GPOs (the enforcement)

This is the technical heart, and it's an extension of Level 2.6. For each tier's machine OU, a GPO assigns **"Deny log on"** user rights to the tiers that must not appear there. Using the User Rights Assignment settings:

- *Deny log on locally*, *Deny log on through Remote Desktop Services*, *Deny access to this computer from the network*, *Deny log on as a batch job*, *Deny log on as a service*.

Applied so that, for example, the **Tier 2 Workstations** GPO denies all of the above to **Tier 0** and **Tier 1** admin groups — making it structurally impossible for a Domain Admin to log on to a workstation. Repeat the pattern per tier.

**The absolute rule, restated because it's the classic self-inflicted outage:** never apply Tier-restriction deny-rights to the **Domain Controllers OU** in a way that locks out Tier 0 admins. Denying Domain Admins logon to DCs locks you out of your own domain.

### Authentication Policies and Silos (the hard enforcement)

Deny-rights are good; **Authentication Policies and Authentication Policy Silos** are stronger. A silo is a container for Tier 0 accounts, computers, and services, enforced by the DC itself through Kerberos. With a silo, a Tier 0 account's TGT can be restricted so it is **only issuable to, and usable from, Tier 0 machines** — enforced at ticket-issuance time by the KDC, not just by the target machine's logon rights. This closes gaps that deny-rights alone can leave (e.g., certain service/network logon paths). Requires 2012 R2+ DFL and that protected accounts are in **Protected Users** (Level 2.2).

### Privileged Access Workstations (PAWs)

A **PAW** is a dedicated, hardened workstation used *only* for privileged administration of a given tier — never for email or browsing. A Tier 0 admin does their work from a Tier 0 PAW, which is itself a Tier 0 system. This solves the "but the admin needs a machine to work from" problem without dragging Tier 0 credentials onto a general-purpose, internet-facing device. The PAW is locked down: no internet, restricted apps, strong device controls.

### Separate accounts per tier

An administrator who works across tiers has **separate accounts for each** — `alice` (Tier 2 daily-use), `alice-t1` (Tier 1 admin), `alice-t0` (Tier 0 admin) — and uses each only from that tier's systems. This began as the Level 1.2 habit; tiering formalizes it.

---

## 5.4 The migration path

This is the part no one writes down. You cannot flip a flat domain to full tiering overnight — you'll cause outages and get the project cancelled. Migrate in stages, each independently safe and reversible.

### Stage 0 — Discover (do not change anything yet)

You cannot draw tier boundaries until you know reality. Map:
- **What is actually Tier 0?** DCs, yes — but also: PKI/CA servers, Entra Connect / ADFS, any server whose admins can reach a DC, any account with DCSync or unconstrained delegation. BloodHound (Level 3.5) is how you find the non-obvious Tier 0 (the forgotten server with DA-equivalent rights).
- **Where do privileged accounts currently log on?** Audit 4624 logon events for your admin accounts. This reveals the dependencies that will break — the service accounts logging on everywhere, the DA that RDPs to a file server nightly.
- **What do service accounts touch?** These are the landmines (see 5.5).

Output: an inventory of Tier 0 systems, and a list of every place a privileged credential currently lands.

### Stage 1 — Build the structure (still no enforcement)

Create the OU hierarchy, the tier groups, and the PAW(s) for Tier 0. Create the *separate* tiered admin accounts (`-t0`, `-t1`). Do **not** apply deny-rights yet. Nothing is enforced; nothing breaks. You're laying track.

### Stage 2 — Secure Tier 0 first (smallest, highest value)

Tier 0 is the smallest tier and the one that matters most, so tier it first:
- Move DCs' effective admin accounts to Tier 0 accounts; start using the Tier 0 PAW for DC administration.
- Put Tier 0 accounts in **Protected Users** and an **Authentication Policy Silo**.
- Apply deny-rights so Tier 0 accounts **cannot** log on to Tier 1/Tier 2 machines, and so **only** Tier 0 accounts can log on to DCs and Tier 0 PAWs.
- Verify you can still administer your DCs from the PAW *before* you remove the old access paths.

Tier 0 done and stable is already the majority of the security benefit — the crown jewels are now contained.

### Stage 3 — Tier 1, application by application

Now the long tail. For each server/application group:
- Identify its admins; give them `-t1` accounts.
- **Migrate its service accounts to gMSA** (Level 3.2) so they stop logging on interactively and stop being kerberoastable.
- Apply Tier 1 logon restrictions.
- Move in waves — a business unit or app cluster at a time — not all at once. Each wave is reversible.

### Stage 4 — Tier 2 and lock the doors

Apply Tier 2 restrictions to workstation OUs (the Level 2.6 deny-rights, now as part of the full model). Confirm no higher-tier account can log on to a workstation. Remove the now-unused old broad-access group memberships.

### Stage 5 — Enforce and monitor

With all tiers in place, tighten Authentication Policy Silos to hard-enforce, and wire the Level 4 detections to alert on **any tier violation** — a Tier 0 account authenticating from a Tier 2 machine is now both impossible *and* alerted, defense in depth.

**Reversibility is the whole point of staging.** At every stage, the change is scoped (one tier, one app wave) and the old path isn't removed until the new one is verified. If a stage breaks something, you roll back that stage alone, not the whole project.

---

## 5.5 What breaks

Forewarned is forearmed. These are the things that predictably break during tiering, roughly in order of how often they bite:

1. **Service accounts that log on everywhere.** The single biggest cause of tiering pain. A service account used across Tier 1 *and* Tier 2, or one that logs on interactively to install/update software, will break when tier restrictions land. This is exactly why **gMSA migration (Level 3.2) should precede or accompany Tier 1 tiering** — it untangles these dependencies. Audit service-account logons in Stage 0; expect surprises.

2. **Admins who "just RDP everywhere."** The DA who administers file servers, workstations, and DCs with one account will find their workflow deliberately broken. This is the point — but it's a people problem as much as a technical one. Provision their tiered accounts and PAW *before* you cut the old access, and communicate.

3. **Scheduled tasks and services running as privileged users.** A backup job running as a Domain Admin on a Tier 1 server violates tiering and will break (or must be flagged) when Tier 0 accounts are denied Tier 1 logon. Find these via the *batch* and *service* logon audits.

4. **Management/monitoring tools with god-mode accounts.** SCCM/ConfigMgr, backup software, monitoring agents often run with sweeping privileges across tiers. Each needs its access re-scoped to a single tier or split.

5. **Nested group memberships that cross tiers.** A group that grants both workstation and server admin, or that's nested into a privileged group unexpectedly (BloodHound territory). Untangle before enforcing.

The pattern in all of them: **something legitimate currently relies on a privileged credential crossing a tier boundary.** Tiering surfaces every one of these. That discovery — knowing exactly where your privilege sprawls — is itself a security win, independent of the final model.

---

## Level 5 exit criteria

- [ ] Tier 0 fully defined (including non-obvious systems found via BloodHound) and contained: separate accounts, PAW, Protected Users, Authentication Policy Silo, deny-rights enforced.
- [ ] Tier 1 migrated in waves; service accounts on gMSA; logon restrictions enforced.
- [ ] Tier 2 workstation restrictions enforced; no higher-tier account can log on to a workstation.
- [ ] Authentication Policy Silos hard-enforcing; Level 4 alerts fire on any tier violation.
- [ ] Old cross-tier access paths removed after new paths verified.

You've reached the destination: a domain where compromising the most-exposed systems no longer leads to the most-privileged ones. That's not a checklist item — it's a different security posture.

---

## References

- [Microsoft — Enterprise Access Model](https://learn.microsoft.com/en-us/security/privileged-access-workloads/privileged-access-access-model)
- [Microsoft — Securing privileged access](https://learn.microsoft.com/en-us/security/privileged-access-workloads/overview)
- [Microsoft — Privileged Access Workstations](https://learn.microsoft.com/en-us/security/privileged-access-workloads/privileged-access-devices)
- [Microsoft — Authentication policies and authentication policy silos](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/how-to-configure-protected-accounts)
- [Microsoft — Why the ESAE/Red Forest is retired](https://learn.microsoft.com/en-us/security/privileged-access-workloads/esae-retirement)
