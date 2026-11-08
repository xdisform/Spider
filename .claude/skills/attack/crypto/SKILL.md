---
name: attack-crypto
description: Solve a provided crypto challenge — run the weakness-matched attack (RsaCtfTool --attack, or a pycryptodome/sympy/sage script) into a re-runnable solver that recovers plaintext/the private key matching flag_format. Oracle = the script re-derives the flag. factordb opt-in.
category: ctf-crypto
tags: [ctf, crypto, rsa, cipher, pycryptodome]
cwe_ids: [CWE-327, CWE-326, CWE-780, CWE-330]
chains_with: [ctf-crypto-triage, attack-rev]
tools: [RsaCtfTool, pycryptodome, sympy, sagemath, factordb-python]
version: "1.0"
---

# CTF crypto — challenge crypto solve

## Objective
Turn the `ctf-crypto-triage` hypothesis into a **re-runnable recovery script** that produces plaintext
(or the private key that decrypts it) matching `scope.objective.flag_format`, from the provided, in-scope
challenge. This is challenge crypto, not web TLS. The proof is the saved `solve.py`/`solve.sage`, not a
pasted plaintext.

## Methodology
The challenge (source / public key / params / ciphertext) under `targets/<t>/artifacts/` is solved
**locally and offline** — **no leash, no network** (one opt-in egress below). Linux-native/Sage tooling
runs under WSL/Docker if absent (see `arsenal/manifest.json`).
1. **Run the matched attack (from triage).**
   - RSA ⇒ `RsaCtfTool --publickey key.pub --decryptfile ct --attack <wiener|hastad|fermat|roca|
     common_factors|...>` (or `--private --dumpkey` to recover `d`); for a bespoke weakness, a
     `pycryptodome` script (`long_to_bytes`, `RSA.construct`, `inverse`).
   - Symmetric ⇒ a `pycryptodome` script: ECB cut-and-paste, CBC bit-flip / padding-oracle decrypt,
     IV/nonce-reuse keystream recovery.
   - XOR ⇒ repeated-key crib-drag / known-plaintext; recover the key then decrypt.
   - PRNG/LCG ⇒ reconstruct state from observed outputs (`sympy`) and predict.
   - Lattice (Coppersmith/partial-key/LLL), ECC, DLP ⇒ a `sage` script (`sympy` as the pip-only
     substitute where it suffices).
   - Classical ⇒ frequency analysis / key-length search.
2. **Recover and format.** Turn the recovered integer/bytes into the plaintext and confirm it matches
   `flag_format`.
3. **Save a deterministic solver.** The script must re-run end-to-end from the provided params to the
   flag — no manual steps, no remembered intermediate values.

## What counts as a finding
- **Finding (the solve):** `solve.py`/`solve.sage` re-run yields plaintext (or the private key that
  decrypts) matching `flag_format`, with `execution_evidence` = the recovered plaintext/flag and
  `poc_path` = the script (`proven_state:'impact_proven'`). Set `provides:["key:...","plaintext:...",
  "flag:<chal>"]` per what it recovers (feeds a sibling challenge or P1's objective oracle).
- **Lead / N/A:** the weakness did not yield (wrong attack, params not actually weak) — an honest
  negative; re-triage or pivot to `attack-rev` if the scheme was embedded in a binary.

## Oracle (load-bearing — a pasted plaintext is NOT proof)
Per `proof/oracles/SKILL.md` (CTF crypto): **the decrypt/recover script re-run yields plaintext (or the
private key that decrypts) matching `flag_format`.** Evidence to capture: **`solve.py`/`solve.sage` + the
recovered plaintext**, under `raw/attack-<id>/`. A flag not reproducible by re-running the script fails
the oracle.

## Evidence
Under `raw/attack-<id>/`: the solver script, the parsed params / `--dumpkey` output, and the recovered
plaintext/key. Offline — no leash (except the opt-in lookup below).

## Red line
Authorised solving of a **provided** challenge **offline** — RSA "cracking" (RsaCtfTool) is recovering a
key for a puzzle you were handed on your own copy, **not** auth-cracking of a third party.
**factordb / Wolfram / any online lookup is OPT-IN egress** that sends only the **public parameters**
(modulus/ciphertext), never credentials or operator data, and only when the operator approves it per
engagement (the passive-OSINT exception). Nothing destructive, no DoS. The safeguard red line, the oracle
gate, and the skeptic lenses are unchanged.
