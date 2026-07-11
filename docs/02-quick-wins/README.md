# Level 2 — Quick Wins

> **Status: planned.** This guide is on the roadmap. See the [root README](../../README.md) for the full progression.

Windows LAPS, Protected Users group, LDAP signing + channel binding, SMB signing, krbtgt double-reset, and admin logon-rights restrictions. High value, low effort, blocks lateral movement and NTLM relay.

Each control in this level will follow the repo's standard format: the attack it blocks, the exact configuration (GPO path / PowerShell), and a verification step.

**Prerequisite:** all previous levels complete. Deploying this on an unhardened domain is security theater.
