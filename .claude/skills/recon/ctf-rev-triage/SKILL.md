---
name: ctf-rev-triage
description: Read-only triage of a provided rev artifact (ELF/PE/.NET/JVM/.pyc/wasm/packed) — strings-for-the-flag first, detect packer/language, then a static decompile pass to recover the key-check logic, and emit rev-<what> hypotheses. No solving here.
category: recon
tags: [ctf, rev, reverse-engineering, decompile, triage]
chains_with: [attack-rev]
tools: [file, strings, ghidra, radare2, binwalk]
version: "1.0"
---

# CTF rev — binary understanding

## Objective
Understand each provided rev challenge artifact under `targets/<t>/artifacts/` well enough that the
attack `rev` pack can invert the check: recover the language/packer, the flag-check or key-derivation
logic, and the exact comparison to beat. Emit `class:rev-<what>` solve hypotheses. **Read-only — the
solver is written in the attack phase.** Loads only when `ctf-rev` mode is active (a plain web run never
runs it).

## Methodology (read-only, local/offline)
The artifact is an operator-supplied file: analyse it **locally** — no network, **no leash**. Prefer
static first; go dynamic/symbolic only when static stalls (the ljagiello ladder). Linux-native tools run
under WSL if absent (see `arsenal/manifest.json`).
1. **Free win first.** `strings -a <artifact> | grep -E '<flag_format>'` (and base64/hex candidates) — a
   plaintext flag ends the triage. `file <artifact>` for arch; detect packer/language (UPX header, .NET
   `BSJB`/`mscoree`, JVM `CAFEBABE`, `.pyc` magic, wasm `\0asm`).
2. **Unpack / pick the engine.** UPX ⇒ `upx -d` (or `binwalk` to confirm). .NET ⇒ ILSpy/dnSpy-style
   decompile; JVM ⇒ procyon/CFR; `.pyc` ⇒ decompyle3/uncompyle6; native ⇒ Ghidra or radare2.
3. **Static decompile pass.** Native: `ghidra analyzeHeadless <proj> tmp -import <artifact> -postScript
   <script>` for the C pseudocode, or `r2 -A <artifact>` then `aaa; afl; pdf @ main; axt` to read the
   key-check. Locate the comparison that gates the flag (`strcmp`/`memcmp`/a custom transform loop).
4. **Name the inversion + engine.** Say exactly which check to invert and the recommended engine:
   a direct decompile read, a `ghidra`/`radare2` script, or `angr` + `z3` symbolic execution when the
   check is a constraint system. Dynamic (`ltrace`/`strace`/`gdb`) and emulation (Qiling) only on the
   **provided local in-scope** artifact.

## What to return
Per artifact: language/packer, the located flag-check logic, the exact comparison/transform to invert,
and a `class:rev-<what>` hypothesis (e.g. `rev-crackme`, `rev-keygen`, `rev-angr-solve`, `rev-decompile`),
`requires:["artifact:<bin>@<chal>"]`, `provides:["key:<name>@<chal>"]` (a recovered input/key) or
`["flag:<chal>"]` (direct), `how_to_prove` naming the engine, and the evidence path. The `artifact:`
token is operator-supplied (seeded via `args.prior_capabilities`), so the solve is ready in wave 1. If a
quick `strings` win already yields the flag, say so — that is a finding lead, not a gap.

## Evidence
Under `raw/ctf-rev-triage/`: the `file`/`strings` output, the packer verdict, and the decompiled
key-check excerpt (the Ghidra/r2 fragment that names the check to invert). Local and offline — no leash.

## Red line
Observation only on a **provided, in-scope** artifact analysed **locally/offline**; the solver runs in
the attack `rev` pack. No third-party system is touched. Recovering a program's own logic you were handed
is authorised puzzle-solving, not auth-cracking of others; the Anthropic safeguard red line and the
oracle are unchanged.
