---
name: ctf-crypto-triage
description: Offline triage of a provided crypto challenge (source/public key/params/ciphertext) — identify the primitive and the concrete weakness, parse key params, and emit crypto-<weakness> solve hypotheses naming the exact attack. No solving here.
category: recon
tags: [ctf, crypto, rsa, cipher, triage]
chains_with: [attack-crypto]
tools: [RsaCtfTool, pycryptodome, openssl, sympy]
version: "1.0"
---

# CTF crypto — scheme identification

## Objective
Read each provided crypto challenge under `targets/<t>/artifacts/` (a `.py`/`.sage` source, a public key,
scheme parameters, a ciphertext) **offline** and pin down the primitive **and the exact weakness**, so
the attack `crypto` pack runs the one matching attack rather than guessing. Emit `class:crypto-<weakness>`
solve hypotheses. **Read-only — the recovery script is written in the attack phase.** Loads only when
`ctf-crypto` mode is active.

## Methodology (read-only, offline)
Everything is local/offline — **no leash, no network** (one exception below is opt-in). Read the provided
source as the ground truth for the scheme; the math decides the attack.
1. **Identify the primitive.** RSA / Diffie-Hellman / ECC / AES-ECB-or-CBC / a stream or XOR cipher /
   an LCG-or-PRNG / a classical cipher. The source or the param names (`n,e,c`; `p,g,A,B`; `iv`) usually
   say it outright.
2. **Find the weakness (the whole game).** RSA: small `e`/low-exponent (Håstad), Wiener (large `d`),
   common-modulus, shared/close primes (Fermat), ROCA, partial-key; parse params with
   `RsaCtfTool --dumpkey --key key.pub`. Symmetric: ECB block-shuffling, CBC/padding-oracle, IV/nonce
   reuse. XOR: repeated-key (crib-drag). PRNG: predictable seed/LCG state recovery. Classical:
   substitution/Vigenère/rail-fence (frequency analysis).
3. **Parse + record the params** (`n`, `e`, `c`, modulus bit-length, `isroca`) so the solve pack feeds
   them straight into the attack. `RsaCtfTool --publickey key.pub --dumpkey`.
4. **Name the exact attack + the oracle.** State it precisely: `RsaCtfTool --attack wiener`, a
   `pycryptodome`/`sympy` script, or a `sage` lattice (Coppersmith/LLL). The oracle is **recovered
   plaintext matching `flag_format`** (or a private key that decrypts to it).

## What to return
Per challenge: the primitive, the identified weakness, the parsed params, and a `class:crypto-<weakness>`
hypothesis (e.g. `crypto-rsa-ctf`, `crypto-wiener`, `crypto-xor-key`, `crypto-lcg-prng`,
`crypto-classical-cipher`), `requires:["artifact:<params>@<chal>"]`,
`provides:["key:<name>@<chal>","plaintext:<name>@<chal>","flag:<chal>"]`, a `how_to_prove` naming the
exact attack, and the evidence path. The `artifact:` token is operator-supplied (seeded via
`args.prior_capabilities`), so the solve is ready in wave 1.

## Evidence
Under `raw/ctf-crypto-triage/`: the parsed params (`--dumpkey` output), the weakness verdict with the
line of source that proves it, and the chosen-attack note. Offline — no leash.

## Red line
Observation only on a **provided, in-scope** challenge analysed **offline**; the recovery runs in the
attack `crypto` pack. **factordb / Wolfram / any online crypto lookup is OPT-IN egress** that sends only
the **public challenge parameters** (modulus/ciphertext) — never credentials or operator data, and only
when the operator approves it per engagement (treated like the passive-OSINT exception). This is solving a
puzzle you were handed, not cracking another party's live crypto; the safeguard red line and the oracle
are unchanged.
