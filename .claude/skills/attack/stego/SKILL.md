---
name: attack-stego
description: Solve a provided stego challenge — steghide extract (with a stegseek-recovered passphrase), zsteg payload pull, exiftool/binwalk extract; re-produce the hidden payload/flag. Oracle = the extractor re-run re-produces the hidden payload.
category: ctf-stego
tags: [ctf, stego, image, audio, steghide, stegseek]
cwe_ids: [CWE-312, CWE-311]
chains_with: [ctf-stego-triage, attack-forensics]
tools: [steghide, stegseek, zsteg, exiftool, binwalk]
version: "1.0"
---

# CTF stego — steganography extraction

## Objective
Execute the `ctf-stego-triage` plan to extract the hidden payload (and from it the flag) from the
provided, in-scope carrier — recovering a steghide passphrase first where the triage flagged one. The
proof is the exact re-runnable extractor command that re-produces the hidden payload, not a narrated
"the data is in the LSB".

## Methodology
The carrier under `targets/<t>/artifacts/` is processed **locally and offline** — **no leash, no
network** (the `rockyou` wordlist is a local file). Linux-native tools (`steghide`/`stegseek`/`zsteg`)
run under WSL if absent (see `arsenal/manifest.json`).
1. **Metadata / appended data.** If triage saw a flag/hint in metadata, pull it with
   `exiftool -a -u -g1 <carrier>`. If `binwalk` saw appended/embedded data, extract it:
   `binwalk -e <carrier>` (or `dd`/`foremost` to carve the trailing file after the carrier EOF).
2. **PNG / BMP (LSB).** `zsteg -a <carrier>` to enumerate, then pull the specific channel/order that
   carries data: `zsteg -E '<payload spec>' <carrier> > out.bin`.
3. **JPEG / WAV / BMP / AU (steghide).**
   - Passphrase needed (triage flag) ⇒ recover it first: `stegseek <carrier> rockyou.txt` (wordlist mode;
     rockyou in < 1.5 s) or `stegseek --seed <carrier>` (seed mode — unencrypted, no passphrase). The
     recovered passphrase is a `key:` capability.
   - Extract: `steghide extract -sf <carrier> -p '<passphrase>' -xf out.bin`.
4. **Audio/visual leads.** A spectrogram-hidden flag ⇒ render the spectrogram and read it; a bit-plane
   image ⇒ extract the plane. Save the rendering step so it re-runs.
5. **Decode the payload** (it is often a further encoding ladder) down to the flag.

## What counts as a finding
- **Finding (the solve):** the extractor re-run re-produces the hidden payload/flag, with
  `execution_evidence` = the flag/payload and `poc_path`/`repro` = the exact command
  (`proven_state:'impact_proven'`). Set `provides` to what it yields: `["key:<name>@<chal>"]` (a recovered
  passphrase), `["artifact:<extracted>@<chal>"]` (a nested file to re-triage), or `["flag:<chal>"]`.
- **Lead / N/A:** no data recovered (the carrier was clean, or the wrong method) — an honest negative;
  re-triage the other carrier method, or pivot to `attack-forensics` if the extract is a container.

## Oracle (load-bearing — a narrated "it's in the LSB" is NOT proof)
Per `proof/oracles/SKILL.md` (CTF stego): **the extractor re-run (steghide/zsteg/stegseek/exiftool)
re-produces the hidden payload/flag.** Evidence to capture: **the command + the extracted payload**,
under `raw/attack-<id>/`. The payload must reappear when the recorded command (with the recovered
passphrase) is re-run; a remembered flag fails.

## Evidence
Under `raw/attack-<id>/`: the exact extractor command(s), any `stegseek`-recovered passphrase, and the
extracted payload/flag bytes. Local and offline — no leash, no target packets.

## Red line
Authorised solving of a **provided, in-scope** carrier analysed **locally/offline**. A `stegseek`/
`steghide` passphrase recovered against a file **you were handed** is puzzle-solving on your own copy —
**not** auth-cracking of another party, not a login brute, not a flood. Nothing destructive, no
persistence. The safeguard red line, the oracle gate, and the skeptic lenses are unchanged.
