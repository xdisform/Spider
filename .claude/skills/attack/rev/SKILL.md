---
name: attack-rev
description: Solve a provided rev challenge — recover and invert the flag-check (decompile read, or angr+z3 symbolic execution when static stalls) into a re-runnable solver that prints the flag / the accepted input. Oracle = the solver re-derives the flag.
category: ctf-rev
tags: [ctf, rev, reverse-engineering, angr, z3, decompile]
cwe_ids: [CWE-656, CWE-798, CWE-489]
chains_with: [ctf-rev-triage, attack-pwn, attack-crypto]
tools: [ghidra, radare2, rizin, angr, z3-solver]
version: "1.0"
---

# CTF rev — reverse engineering solve

## Objective
Turn the `ctf-rev-triage` hypothesis into a **re-runnable solver** that recovers the flag (or the input
the binary accepts as correct) from the provided, in-scope artifact. The proof is a saved script whose
output matches `scope.objective.flag_format` — not a narrated reading of the decompilation.

## Methodology
The artifact under `targets/<t>/artifacts/` is analysed and run **locally and offline** — **no leash, no
network** (static-first; dynamic/symbolic only on the local in-scope copy). Linux-native tools run under
WSL if absent (see `arsenal/manifest.json`).
1. **Confirm the free win.** Re-check `strings` / a decoded-blob ladder for a plaintext flag before
   heavy work (triage may have found it).
2. **Read the check.** From triage's decompile: `ghidra analyzeHeadless <proj> tmp -import <bin>
   -postScript <script>` for the C pseudocode, or `r2 -A <bin>` then `pdf @ sym.check`. Isolate the exact
   comparison/transform that gates success (`strcmp`/`memcmp`/a char-by-char or arithmetic loop).
3. **Invert it.**
   - Direct ⇒ reverse the transform in a short Python script (XOR/add/permute back to the flag).
   - Comparison against a constant ⇒ read the constant out and format it.
   - Constraint system / many branches ⇒ **angr** symbolic execution:
     `p.factory.simulation_manager(state).explore(find=<win-addr>, avoid=<fail-addr>)`, then
     `state.posix.dumps(0)` for the accepted stdin; back it with **z3** for a pure constraint check.
   - Hooks when a check resists static reasoning: `ltrace`/`strace`, or Frida on `strcmp`/`memcmp` — on
     the **local** binary only.
4. **Validate by re-run.** Feed the recovered input back into the binary (locally) and confirm it prints
   the success/flag path; save the solver.

## What counts as a finding
- **Finding (the solve):** a re-runnable solver (or a decompiled-logic derivation) that re-derives the
  flag or the accepted input, with `execution_evidence` = the flag/input and `poc_path` = the saved
  script (`proven_state:'impact_proven'`). If it recovers a key/input a sibling challenge needs, set
  `provides:["key:<name>@<chal>"]` / `["source:<name>@<chal>"]` / `["flag:<chal>"]`.
- **Lead / N/A:** the inversion did not resolve (e.g. angr state explosion) — an honest negative with the
  partial model saved. Pivot to `attack-crypto` (if the check is a cipher) or `attack-pwn` (if it is a
  memory bug) per the triage note.

## Oracle (load-bearing — reading the decompiler is NOT proof)
Per `proof/oracles/SKILL.md` (CTF rev): **a re-runnable solver / decompiled logic that re-derives the
flag or the accepted input.** Evidence to capture: **the script + its output matching `flag_format`**,
under `raw/attack-<id>/`. A flag asserted from a decompilation read, without a script that reproduces it,
fails the oracle.

## Evidence
Under `raw/attack-<id>/`: the solver script, the decompiled key-check excerpt it inverts, the angr/z3
model if used, and the run output showing the flag/input. All local and offline — no leash.

## Red line
Authorised solving of a **provided** binary analysed **locally** — not an attack on a third party.
Recovering a program's own logic you were handed is puzzle-solving, not auth-cracking of others; no
network, nothing destructive, no persistence. The safeguard red line, the oracle gate, and the skeptic
lenses are unchanged.
