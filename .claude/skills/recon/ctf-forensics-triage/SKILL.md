---
name: ctf-forensics-triage
description: Read-only characterisation of a provided forensic artifact (pcap/memory image/disk image/blob) — ID the container, name the exact plugin/filter, and emit a carve plan as forensics-carve (foothold, nested artifact) / forensics-extract hypotheses. No carving here.
category: recon
tags: [ctf, forensics, pcap, memory, carve, triage, foothold]
chains_with: [attack-forensics, ctf-stego-triage]
tools: [file, tshark, volatility3, binwalk]
version: "1.0"
---

# CTF forensics — artifact characterisation

## Objective
Characterise each provided forensic artifact under `targets/<t>/artifacts/` (a `.pcap`/`.pcapng`, a
memory image, a disk image, or an opaque blob) **read-only**, identify the container, and produce a
concrete **carve plan** naming the exact plugin/filter the attack phase will run. A carve that yields a
**nested artifact** is a FOOTHOLD PRODUCER — model it as such so the next stage fires. **Read-only — the
extraction runs in the attack phase.** Loads only when `ctf-forensics` mode is active.

## Methodology (read-only, local/offline)
The artifact is an operator-supplied file: analyse it **locally** — no network, **no leash**.
Linux-native tools run under WSL if absent (see `arsenal/manifest.json`); `tshark`/`volatility3`/`binwalk`
run natively on Windows.
1. **Identify the container.** `file <artifact>`; for a blob, `binwalk --signature <artifact>` for
   embedded/appended data.
2. **pcap/pcapng.** `tshark -r f.pcap -q -z io,phs` (protocol hierarchy) → which protocols carry the
   payload. Note candidate filters (`-Y 'http'`, `-z follow,tcp,ascii,0`, `--export-objects http,out/`)
   and any obvious transferred file / credential stream. Do NOT export yet — name the filter.
3. **Memory image.** `vol -f mem.dmp windows.info` (or `banners`) to ID the OS build FIRST — v3 uses
   symbol tables, so the build must be known. Then record the plugin chain to run
   (`windows.pslist` → `netscan` → `filescan` → `dumpfiles` → `cmdline`/`hashdump`), targeted at the
   process/file of interest.
4. **Disk image.** `file`/`mmls` for the partition layout; note `foremost -t <type>` / `photorec` /
   `testdisk` as the carve.
5. **Emit the carve plan** (below). A carve that produces an inner file is `forensics-carve`
   (`stage:"foothold"`); a directly-extractable flag is `forensics-extract`.

## What to return
Per artifact: the container verdict, the protocol/OS/partition facts, and the carve-plan hypothesis:
- a **carve** that yields a nested artifact ⇒ `class:forensics-carve`, `stage:"foothold"`,
  `requires:["artifact:<dump>@<chal>"]`, `provides:["artifact:<carved>@<chal>"]` (the inner file the next
  stage characterises/solves);
- a **direct** flag ⇒ `class:forensics-extract`, `provides:["flag:<chal>"]`.
Name the exact plugin/filter in `how_to_prove` (`volatility3 windows.pslist|netscan|filescan|dumpfiles|
cmdline`, `tshark -Y <filter> --export-objects`, `foremost -t`, `bulk_extractor`) + the evidence path.
The outer `artifact:` token is operator-supplied (seeded via `args.prior_capabilities`); a carved inner
`artifact:` is granted only when the carve hypothesis is oracle-proven in attack, which unlocks its
dependent solve next wave (the F4 multi-stage chain).

## Evidence
Under `raw/ctf-forensics-triage/`: the `file`/`binwalk` output, the `tshark -z io,phs` hierarchy, the
`volatility3 windows.info` build ID, and the written carve plan. Local and offline — no leash.

## Red line
Observation only on a **provided, in-scope** artifact analysed **locally/offline**; the carve/extract
runs in the attack `forensics` pack. No third-party system is touched — a captured pcap/dump you were
handed is the subject, not a live network. The safeguard red line and the oracle are unchanged.
