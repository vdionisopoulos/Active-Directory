# Level 3 — Credential Hardening

> **Status: planned.** This guide is on the roadmap. See the [root README](../../README.md) for the full progression.

gMSA to replace static service accounts, Kerberos AES-only + SPN/kerberoasting audit, Credential Guard, and ACL hygiene driven by BloodHound.

Each control in this level will follow the repo's standard format: the attack it blocks, the exact configuration (GPO path / PowerShell), and a verification step.

**Prerequisite:** all previous levels complete. Deploying this on an unhardened domain is security theater.
