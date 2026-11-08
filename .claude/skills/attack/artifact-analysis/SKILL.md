---
name: attack-artifact-analysis
description: Characterise and extract from a provided, in-scope file/binary artifact locally — libmagic type ID, strings, metadata, embedded/appended data carve — to pull the hidden secret/flag or a nested artifact. Oracle = the re-run command re-produces the extracted bytes.
category: file
tags: [artifact, file, binary, metadata, carve, extract]
cwe_ids: [CWE-312, CWE-311, CWE-215]
chains_with: [artifact-analysis, attack-stego, attack-forensics, objective-capture]
tools: [file, exiftool, binwalk, strings, foremost, imagemagick]
version: "1.0"
---

# Artifact analysis — local file/binary characterisation & extraction

## Objective
Given a provided, in-scope artifact (a downloaded file, an operator-dropped blob, a binary/document/
image carved by a prior stage), identify what it is and pull the secret it carries — a hidden flag, an
embedded credential/key, or a nested artifact to re-triage. This is the generic file/binary-mode
producer behind the `artifact`/`file-analysis`/`artifact-metadata`/`file-metadata` classes; a
carrier that is specifically a stego image/audio routes to `attack-stego`, a disk/memory/pcap capture to
`attack-forensics`. The proof is the exact re-runnable command that re-produces the extracted bytes, not
a narrated "the key is in the file".

## Methodology
The artifact lives under `targets/<t>/artifacts/` (or `raw/` if a prior stage carved it) and is processed
**locally and offline** — **no leash, no network** (only the original download, if any, was leashed).
Treat it as untrusted data: never execute it, pass its path as an argument, and prefer read-only tools.
Linux-native helpers run under WSL if absent (see `arsenal/manifest.json`).
1. **Identify the type.** `file <artifact>` (libmagic) — ELF/PE/document/archive/image/ciphertext. This
   selects the right follow-up and the right sibling pack if it is really stego/forensics.
2. **Cheap wins first.** `strings -n 8 <artifact> | grep -Ei '<flag_format>|key|secret|token|BEGIN '` and
   `exiftool -a -u -g1 <artifact>` (metadata, comments, hidden EXIF/XMP) — a flag or credential is often
   sitting in plain metadata or a string table.
3. **Embedded / appended data.** `binwalk <artifact>` to detect, then `binwalk -e <artifact>` (or
   `foremost -t all -i <artifact>` / a `dd` carve past the carrier EOF) to extract a trailing/embedded
   file. An extracted container is a **nested artifact** — re-triage it from step 1.
4. **Structured documents / archives.** Unzip/unpack office/PDF/jar/apk containers and repeat strings +
   metadata on the inner parts (macros, `/Info` dicts, `xl/` sheets, `META-INF/`, resources).
5. **Images.** `identify -verbose <img>` (ImageMagick) for comments/geometry/profiles; if it looks like
   LSB/spectrogram stego, hand off to `attack-stego`.
6. **Decode the payload** — it is often an encoding ladder (base64/hex/gzip) down to the flag/secret.

## What counts as a finding
- **Finding (the solve):** the re-run command re-produces the extracted secret/flag, with
  `execution_evidence` = the recovered bytes and `poc_path`/`repro` = the exact command
  (`proven_state:'impact_proven'`). Set `provides` to what it yields: `["key:<name>@<chal>"]` (a
  recovered secret/credential), `["artifact:<extracted>@<chal>"]` (a nested file to re-triage), or
  `["flag:<chal>"]`.
- **Lead / N/A:** nothing recovered (the artifact was inert, or the wrong method) — an honest negative;
  pivot to the type-specific sibling pack (`attack-stego` / `attack-forensics`) or re-triage a nested
  container.

## Oracle (load-bearing — a narrated "the flag is embedded" is NOT proof)
Per `proof/oracles/SKILL.md`: **the extractor/decoder re-run re-produces the secret/flag bytes.**
Evidence to capture: **the command + the extracted bytes**, under `raw/attack-<id>/`. The bytes must
reappear when the recorded command is re-run on the same artifact; a remembered value fails.

## Evidence
Under `raw/attack-<id>/`: the `file` type line, the exact strings/exiftool/binwalk/carve command(s), and
the extracted payload/flag bytes. Local and offline — no leash, no target packets.

## Red line
Authorised analysis of a **provided, in-scope** artifact handled **locally/offline**. Extracting a secret
from a file **you were handed** is puzzle-solving on your own copy — **not** auth-cracking of another
party, not a login brute, not a flood. Never execute the artifact; nothing destructive, no persistence.
The safeguard red line, the oracle gate, and the skeptic lenses are unchanged.
