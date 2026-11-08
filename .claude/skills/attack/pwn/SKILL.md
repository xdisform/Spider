---
name: attack-pwn
description: Solve a provided pwn challenge — build a pwntools exploit (cyclic offset, checksec-driven ret2win/ret2libc/ROP with ROPgadget+one_gadget, patchelf to the provided libc), prove it locally then against the authorised remote. Oracle = the exploit re-derives the flag.
category: ctf-pwn
tags: [ctf, pwn, binary-exploitation, pwntools, rop, foothold]
cwe_ids: [CWE-787, CWE-121, CWE-134, CWE-416, CWE-120]
chains_with: [ctf-pwn-triage, attack-rev]
tools: [pwntools, ROPgadget, one_gadget, patchelf, pwndbg]
version: "1.0"
---

# CTF pwn — binary exploitation

## Objective
Turn the `ctf-pwn-triage` hypothesis into a **re-runnable exploit** that recovers the flag from the
provided, in-scope challenge binary — locally first, then against the authorised remote endpoint if the
challenge ships one. The proof is not a crash: it is a saved `exploit.py` that re-derives a string
matching `scope.objective.flag_format`.

## Methodology
The binary under `targets/<t>/artifacts/` is analysed and run **locally and offline** — local analysis
touches no network and needs **no leash**. The only network is (i) a download or (ii) the pwn delivery to
the **in-scope** `engagement.challenges[].remote` endpoint. Many tools are Linux-native — run under WSL
if absent (see `arsenal/manifest.json`).
1. **Match the local binary to its libc.** If a libc was provided, `patchelf --set-interpreter ./ld.so
   --replace-needed libc.so.6 ./libc.so.6 ./chal` (or `pwninit`) so the local run matches the remote.
2. **Find the offset.** `pwntools` `cyclic(200)` → crash → `cyclic_find(<value>)` for the exact
   saved-RIP offset; confirm in `gdb`+`pwndbg` (`context`, `vmmap`, `heap`/`bins` for heap bugs).
3. **Pick the technique from checksec (from triage).**
   - win-function present ⇒ **ret2win** (return straight to it).
   - NX + no-canary, no PIE ⇒ **ret2libc / ROP**: chain `pop rdi; ret` → `system("/bin/sh")` or a
     `one_gadget libc.so.6` address; build with `ROP(elf)` / `ROPgadget --binary`.
   - canary present ⇒ leak it first (format string / partial overwrite), then overflow.
   - format string ⇒ `%n` write / GOT overwrite via `pwntools` `fmtstr_payload`.
   - heap (UAF/overflow) ⇒ tcache/fastbin poisoning to a `__free_hook`/`__malloc_hook` or `system`.
4. **Write ONE script that targets both.** `io = process('./chal')` for local, `io = remote(host, port)`
   for the authorised endpoint — identical body. Drive the remote tube through `tools/leash-sock.py`
   (host-pinned, frame/byte/time-capped, full transcript to `raw/`); a one-shot connectivity/banner check
   is pinned via `tools/guard.py` + `tools/leash-tcp.sh` to the exact `host:port`, never a range.
5. **Capture the flag.** The shell/leak reads the flag (`cat flag.txt`); pull it over the tube and record
   the IO transcript.

## What counts as a finding
- **Finding (the solve):** the exploit returns the flag — a shell that reads it, or a direct leak of it —
  with `execution_evidence` = the flag string and `poc_path` = the saved `exploit.py`. The flag IS the
  impact (`proven_state:'impact_proven'`). If a sub-result unlocks another challenge, set `provides`
  accordingly (`flag:<chal>`, or `artifact:`/`key:` per `brain/schema.md`).
- **Blocked (hand-off):** reaching the flag would require defeating an auth/safeguard control as an attack
  ⇒ `proven_state:'blocked', blocked_reason:'safeguard'`. Never evade. A box-crashing path is a hand-off,
  not a solve.
- **Lead / N/A:** the technique did not land — an honest negative with the attempts saved.

## Oracle (load-bearing — the flag string alone is NOT proof)
Per `proof/oracles/SKILL.md` (CTF pwn): the **exploit script, re-run vs the in-scope remote (or local)
binary, returns the flag / a shell that reads it.** Evidence to capture: `exploit.py` **+ the captured IO
transcript showing the flag**, under `raw/attack-<id>/`. For a remote solve the validator re-connects
through `tools/leash-sock.py`/`leash-tcp.sh` and asserts the flag comes back from the **in-scope origin
IP** (the `origin-check` skeptic veto). A flag typed from memory fails.

## Evidence
Under `raw/attack-<id>/`: `exploit.py`, the `gdb`/`pwndbg` offset session, the `ROPgadget`/`one_gadget`
notes, and the IO transcript with the flag. Local artifact work is offline; the only leashed step is the
remote delivery.

## Red line
This is **authorised solving of a provided puzzle** — not an attack on a third party. Local analysis is
offline; the remote delivery is bounded to recovering the flag, host-pinned, capped (the socket caps make
a logic exploit unable to become a flood). No auth-crack of others, no DoS/flood, nothing destructive, no
persistence; the Anthropic safeguard red line, the oracle gate, and the skeptic lenses are unchanged.
