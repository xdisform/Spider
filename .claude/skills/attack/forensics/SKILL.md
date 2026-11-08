---
name: attack-forensics
description: Solve a provided forensics challenge — run the triage carve plan (volatility3 plugin chain / tshark filters + export-objects / foremost / bulk_extractor); a carve that yields a nested artifact provides it for the next stage. Oracle = the exact command re-extracts the flag bytes.
category: ctf-forensics
tags: [ctf, forensics, pcap, memory, carve, foothold]
cwe_ids: [CWE-312, CWE-319, CWE-532]
chains_with: [ctf-forensics-triage, attack-stego]
tools: [volatility3, tshark, foremost, bulk_extractor, binwalk]
version: "1.0"
---

# CTF forensics — artifact extraction

## Objective
Execute the `ctf-forensics-triage` carve plan to pull the flag (or the nested artifact that leads to it)
out of the provided, in-scope forensic artifact. A carve that yields an inner file is a **foothold
producer** — it `provides` that `artifact:` token so the next stage characterises/solves it. The proof is
the exact re-runnable command that re-extracts the flag bytes, not a narrated finding.

## Methodology
The artifact under `targets/<t>/artifacts/` (or `raw/` if a prior stage carved it) is processed
**locally and offline** — **no leash, no network**. `tshark`/`volatility3`/`binwalk` run natively on
Windows; `foremost`/`bulk_extractor` run under WSL if absent (see `arsenal/manifest.json`).
1. **pcap/pcapng.** Apply the triage filter: `tshark -r f.pcap -Y '<display filter>' -T fields ...`,
   `-z follow,tcp,ascii,<n>` to reassemble a stream, `--export-objects http,out/` (or `smb`/`tftp`/`ftp-data`)
   to pull transferred files. Decode any carried encoding ladder (base64/hex/gzip) to the flag.
2. **Memory image.** Run the plugin chain on the triage-confirmed OS build:
   `vol -f mem.dmp windows.pslist` → `windows.netscan` → `windows.filescan` →
   `vol -f mem.dmp windows.dumpfiles --virtaddr <addr>` (or `-r`), `windows.cmdline`, `hashdump`/`lsadump`.
   Target the process/file triage flagged; dump and read it.
3. **Disk image / blob.** `foremost -t <type> -i image.dd -o out/`, `photorec`, or
   `binwalk -e <blob>` (and `bulk_extractor` to sweep for keys/URLs/PII). Mount read-only where needed.
4. **Chain carves.** If the extract is itself a container (a dumped PNG, a nested ZIP, an embedded
   binary), emit/continue it as the inner `artifact:` so the right triage/solve pack takes it — this is
   the F4 multi-stage chain (`forensics-carve` → inner solve).

## What counts as a finding
- **Finding (the solve):** the command re-extracts the flag bytes from the artifact, with
  `execution_evidence` = the flag and `poc_path`/`repro` = the exact command + its output
  (`proven_state:'impact_proven'`). A carve that yields a nested file but not yet the flag is still a win:
  set `provides:["artifact:<carved>@<chal>"]` (stage foothold) so the next wave solves it.
- **Lead / N/A:** the plan did not surface the flag — an honest negative; re-triage with a different
  plugin/filter, or pivot to `attack-stego` if the carved file is a media carrier.

## Oracle (load-bearing — a narrated extraction is NOT proof)
Per `proof/oracles/SKILL.md` (CTF forensics): **the exact plugin/filter re-run (volatility3/tshark/
foremost) re-extracts the flag bytes from the artifact.** Evidence to capture: **the command + the
extracted bytes**, under `raw/attack-<id>/`. The flag must reappear when the recorded command is re-run
against the artifact; a remembered value fails.

## Evidence
Under `raw/attack-<id>/`: the exact command(s), the exported objects / dumped files, and the extracted
flag bytes. Local and offline — no leash, no target packets (the artifact is a captured file, not a live
network).

## Red line
Authorised solving of a **provided, in-scope** capture analysed **locally/offline** — a pcap/dump you
were handed is the subject, never a live third-party network or host. Bounded extraction only: no
mass-exfil beyond the challenge, nothing destructive, no persistence. The safeguard red line, the oracle
gate, and the skeptic lenses are unchanged.
