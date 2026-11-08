---
name: ctf-stego-triage
description: Read-only triage of a provided stego carrier (image/audio) — exiftool + binwalk, then carrier-specific detection (zsteg for PNG/BMP, steghide info for JPEG/WAV), and emit stego-<carrier> hypotheses flagging whether a stegseek passphrase recovery applies. No extraction here.
category: recon
tags: [ctf, stego, image, audio, exiftool, triage]
chains_with: [attack-stego, ctf-forensics-triage]
tools: [exiftool, binwalk, zsteg, steghide]
version: "1.0"
---

# CTF stego — carrier triage

## Objective
Triage each provided stego carrier under `targets/<t>/artifacts/` (an image or audio file) **read-only**
and determine whether data is hidden, by which method, and which extractor the attack phase should run —
including whether a steghide passphrase must be recovered first. Emit `class:stego-<carrier>` hypotheses.
**Read-only — the extraction runs in the attack phase.** Loads only when `ctf-stego` mode is active.

## Methodology (read-only, local/offline)
The carrier is an operator-supplied file: analyse it **locally** — no network, **no leash**. Linux-native
tools (`zsteg`/`steghide`/`stegseek`) run under WSL if absent (see `arsenal/manifest.json`). Standard
loop: **exiftool → binwalk → carrier-specific**.
1. **Metadata + anomalies.** `exiftool -a -u -g1 <carrier>` — a flag or a hint often sits in a comment /
   artist / software field; note dimension/size anomalies. (Reuses the F7 metadata entry.)
2. **Appended / embedded files.** `binwalk <carrier>` — a trailing ZIP/PNG/archive after the carrier's
   real EOF is the most common CTF trick (extract is an attack step, not here).
3. **Carrier-specific detection (READ-ONLY).**
   - PNG / BMP ⇒ `zsteg -a <carrier>` (LSB / bit-plane across all channels/orders).
   - JPEG / WAV / BMP / AU ⇒ `steghide info <carrier>` — does it report embedded data? If yes, a
     passphrase is needed ⇒ flag a `stegseek` rockyou recovery as the first attack step.
   - Audio/visual ⇒ note spectrogram / bit-plane leads (a tone-hidden flag, an LSB plane) for the solver.
4. **Emit the hypothesis** (below), naming the extractor and whether passphrase recovery applies.

## What to return
Per carrier: the metadata findings, the appended-data verdict, the detection result, and a
`class:stego-<carrier>` hypothesis (e.g. `stego-png`, `stego-jpeg`, `stego-wav`, `stego-lsb`,
`stego-exif-hidden`), `requires:["artifact:<carrier>@<chal>"]`, and `provides` set to what the extract
yields: `["key:<name>@<chal>"]` (a recovered steghide passphrase), `["artifact:<extracted>@<chal>"]` (a
nested file to re-triage), or `["flag:<chal>"]` (direct). State in `how_to_prove` the exact extractor and
whether `stegseek <carrier> rockyou.txt` passphrase recovery is the prerequisite. The `artifact:` token is
operator-supplied (seeded via `args.prior_capabilities`), so the solve is ready in wave 1.

## Evidence
Under `raw/ctf-stego-triage/`: the `exiftool -a -u -g1` output, the `binwalk` scan, and the
`zsteg -a` / `steghide info` detection result. Local and offline — no leash.

## Red line
Observation only on a **provided, in-scope** carrier analysed **locally/offline**; the extraction (and
any `stegseek` passphrase recovery) runs in the attack `stego` pack. A passphrase recovered against a file
you were handed is puzzle-solving, not auth-cracking of others. The safeguard red line and the oracle are
unchanged.
