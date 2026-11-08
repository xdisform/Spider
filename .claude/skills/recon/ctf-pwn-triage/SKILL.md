---
name: ctf-pwn-triage
description: Read-only triage of a provided pwn artifact (ELF/PE) — file + checksec + strings + a ROPgadget inventory + the provided libc, map the bug surface, and emit pwn-<bug> solve hypotheses. No exploitation here.
category: recon
tags: [ctf, pwn, binary, checksec, triage, foothold]
chains_with: [attack-pwn]
tools: [file, checksec, strings, ROPgadget, pwntools]
version: "1.0"
---

# CTF pwn — binary triage

## Objective
Characterise each provided pwn challenge artifact under `targets/<t>/artifacts/` (an ELF/PE binary, plus
any provided libc) **read-only**, so the attack phase knows exactly which bug class and technique to
exploit. Name the vulnerable sink and the mitigation posture, then emit `class:pwn-<bug>` solve
hypotheses the attack `pwn` pack will prove. The flag is the objective. **No exploit is written here —
this lens reads the binary and plans.** Loads only when `ctf-pwn` mode is active (a plain web run never
runs it).

## Methodology (read-only, local/offline)
The artifact is an operator-supplied file on disk: analyse it **locally** — this touches no network and
needs **no leash**. Many tools are Linux-native; run them under WSL if absent on this OS (see
`arsenal/manifest.json` cross-OS notes).
1. **Identify.** `file <artifact>` → arch/bitness, static-vs-dynamic, stripped? This decides the
   toolchain. Note the `challenges[].remote` endpoint and `challenges[].libc` if the scope supplies them.
2. **Mitigations (picks the technique).** `pwn checksec --file <artifact>` (or `checksec.sh`) →
   RELRO / stack-canary / NX / PIE / FORTIFY. No-canary + NX ⇒ ret2libc/ROP; no-PIE ⇒ fixed gadget
   addresses; partial-RELRO ⇒ GOT overwrite; canary present ⇒ a leak is needed first.
3. **Strings + symbols.** `strings -a <artifact> | grep -Ei 'flag|ctf|/bin/sh|system|cat '`; list
   functions for a `win()`/backdoor (⇒ ret2win) and dangerous sinks (`gets`/unbounded `read`/`scanf`,
   `printf(user)` format string, `memcpy`/heap `malloc`+UAF).
4. **Gadget inventory (static).** `ROPgadget --binary <artifact>` and the provided libc → record
   `pop rdi; ret`, `ret`, a `one_gadget` candidate, and useful strings for the attack pack.
5. **Provided libc.** If `challenges[].libc` exists, record its version
   (`strings libc.so.6 | grep -i 'glibc\|GNU C Library'`) — the solve pack will `patchelf` the binary to it.
6. **Map bug → technique and emit the hypothesis** (below). Do NOT attempt the overflow/exploit.

## What to return
Per artifact: arch, mitigation table, the vulnerable sink + a controllable-offset hint, any win-function,
the libc version, and a `class:pwn-<bug>` hypothesis (`pwn-ret2win` | `pwn-ret2libc` | `pwn-rop` |
`pwn-fmt` | `pwn-heap`), `host:<challenges[].remote or name>`, `stage:"post-foothold"`,
`requires:["artifact:<bin>@<chal>"]`, `provides:["flag:<chal>"]`, a concrete `how_to_prove` naming the
technique, and the evidence path. The `artifact:` token is **operator-supplied** (the file is on disk),
so it is seeded into the scheduler's acquired set via `args.prior_capabilities` and the hypothesis is
ready in wave 1. A triage that proves nothing is an honest N/A, not a gap.

## Evidence
Under `raw/ctf-pwn-triage/`: the `file`, `checksec`, `strings`, `ROPgadget` output and the libc-version
note. Local and offline — no leash, no target packets. A claim with no evidence file is a lead, not an asset.

## Red line
Triage is **observation only** on a **provided, in-scope** artifact analysed **locally/offline**. No
exploit here; the solve runs in the attack `pwn` pack. A remote `nc` delivery, if any, happens only in
attack, host-pinned via `tools/guard.py` + `tools/leash-tcp.sh` to the exact `host:port` (never a range) —
never here. This is solving a puzzle you were handed, not an attack on a third party; the Anthropic
safeguard red line and the oracle are unchanged.
