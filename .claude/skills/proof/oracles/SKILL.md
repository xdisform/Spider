---
name: oracles
description: Deterministic per-class PoC oracles — the machine-checkable proof each vuln class must produce. AI discovers; the oracle validates. No oracle, no finding.
category: proof
tags: [oracle, validation, poc, deterministic, no-false-positives]
chains_with: [poc-standard, oob-interactsh, cors-poc-html]
tools: [interactsh-client, curl, httpx, hurl]
version: "1.0"
---

# Oracles — deterministic validation per class

The single biggest driver of accepted critical findings (XBOW, MAPTA, Strix, Big Sleep) is this: the
LLM **discovers**, but a **deterministic, machine-checkable oracle** confirms. A finding is `confirmed`
ONLY when its class oracle is met with evidence a non-LLM check could re-derive. "The model is sure"
is not an oracle. Re-run the PoC and produce the oracle evidence, in scope, through the leash.

## The oracle per class (black-box, in policy)
| Class | Oracle (machine-checkable) | Evidence to capture |
|---|---|---|
| SSRF / blind RCE / blind XXE / blind SQLi | **OOB callback** for a UNIQUE interactsh subdomain fired by the payload | the `interactsh.jsonl` line (unique token, proto, src-IP, ts) |
| In-band SQLi | DB banner returned: `database()`/`@@version`/`current_user` | request + response showing the real DB string |
| RCE | command output in response (`whoami`/`id`/`hostname`) OR an OOB callback from the command | request + response/callback with the exact output |
| File-read / path-traversal | a file with a KNOWN signature returned (e.g. `root:x:0:0` from `/etc/passwd`, a config key) | request + the signature bytes in the response |
| IDOR / BOLA | account A receives account B's record; the returned owner-id ≠ A | both requests (A→A, A→B) + the owner field proving different ownership |
| CORS | credentialed cross-origin read returns the victim's body (ACAO reflects + ACAC true + body readable) | the `cors-poc.html` result reading a real authenticated response |
| XSS | payload EXECUTES: blind-XSS OOB callback, or a headless-browser assert the JS fired | callback line, or the browser-exec proof — not a reflected string |
| Open redirect | 3xx with `Location` pointing to the attacker-controlled host | the response headers showing the redirect target |
| Auth bypass / ATO | a protected resource/identity reached without proper auth (401/403 → 200 w/ privileged content) | before/after requests showing the boundary crossed |
| Deserialization (Java/.NET/Python/PHP) | **OOB callback** from the gadget, or command output (`id`/`whoami`) — same bar as RCE; a reflected `rO0AB`/accepted blob is NOT proof | the interactsh line (unique token), or the command output; the gadget/library + the exact builder (`ysoserial …`) invocation |
| OGNL / SpEL / EL injection | command output (`id`/`whoami`), or an **OOB callback** the expression fired; a reduced `%{7*7}`→`49` proves server-side eval (high), not yet RCE | the injecting request + the output/callback; the detected engine/version |
| Info-disclosure (secret-that-works) | the LEAKED secret is **exercised and crosses a boundary** (token → 401/403→200 private content; cred logs in; key signs/forges) — a bare 200 / health page / `.map` is NOT the oracle | the exposure request + the request USING the secret (before/after boundary cross) |
| Rate-limit / control defect | N requests with zero `429`/`419`/lockout (via `rate-limit-probe.py`) | the status curve JSON |
| **Objective / flag captured** (P1) | the captured string **matches `scope.objective.flag_format`** (regex) **AND** those exact bytes are **re-derivable from a saved artifact under `raw/`** — the request/response, file read, command output, or local-tool output that produced it. A flag the agent typed from memory, guessed, or not traceable to an artifact **fails**. `oracle_type:'flag-capture'` | the `raw/` artifact path + the matched bytes + the producing request/response/command |
| **CTF pwn** (P3) | the exploit script, re-run vs the in-scope remote (or local) binary, returns the flag / a shell that reads it | `exploit.py` + the captured IO transcript showing the flag |
| **CTF rev** (P3) | a re-runnable solver/decompiled logic that re-derives the flag or the accepted input | the script + its output matching `flag_format` |
| **CTF crypto** (P3) | the decrypt/recover script re-run yields plaintext (or the private key that decrypts) matching `flag_format` | `solve.py`/`solve.sage` + recovered plaintext |
| **CTF forensics** (P3) | the exact plugin/filter re-run (volatility3/tshark/foremost) re-extracts the flag bytes from the artifact | the command + the extracted bytes |
| **CTF stego** (P3) | the extractor re-run (steghide/zsteg/stegseek/exiftool) re-produces the hidden payload/flag | the command + the extracted payload |
| **Local privesc** (P4) | a privileged action demonstrated: `id`→`uid=0`/`root`, or a root-only file read (safe-PoC) | the before/after `id`, or the root-only byte signature, under `raw/validate-<id>/` |
| **Loot / objective** (P4) | the objective artifact (matches `scope.objective.flag_format`/`scope.objective.goal`) re-derivable from a saved file under `raw/` | the looted artifact + the command that retrieved it |
| **Lateral** (P4) | an authenticated action on an **in-scope** neighbour with a looted cred | the cross-host auth proof + the scope assertion |
| **Interactive-protocol exploit** (P5) | the held-socket **transcript under `raw/`** is re-playable (`tools/sock-replay.py`) and shows the claimed effect in recorded frames: command output (`id`/`whoami`), a leaked record, or a **protocol state crossed** (a privileged/denied verb now accepted) — re-derived by replaying the exact send sequence, not narration. `oracle_type:'interactive-transcript'` | the `sock-*.jsonl` transcript path + the exploit script + the send/recv frames proving the effect (+ any interactsh OOB line for a blind trigger) |
| **OTP/2FA logic bypass** (P6) | a protected resource/identity reached with a SERVER-VALID session minted via the OTP step (leaked/predictable/reused code accepted, or an account-binding repoint), 401/403→200 w/ privileged content that RE-FETCHES cleanly in a fresh request — NOT merely an SPA state flip. `oracle_type:'otp-logic-session'` | the OTP submission request/response + the authed-resource re-fetch; for account-binding the content is the VICTIM's (owner-id ≠ you) |
| **Payout-ready (B2, fix3 bounty mode)** | the finding is `verified:true` + `oracle_met` (impact-proven) **AND** host ∈ scope.yaml + policy **AND** class eligible (B4, not P5/excluded) **AND** CVSS 3.1 vector maps to a paying tier ≥ `objective.min_payable_tier` (B5) **AND** dedup-cleared (B3, not duplicate / not could-not-verify) **AND** ISO-29147 report elements present (`/report`). `oracle_type:'payout-ready'`. A finding the model *calls* payable but that fails any sub-gate is NOT payout_ready. This is an ECONOMIC verdict layered ON TOP of the impact oracle — it can never suppress a proven finding, only gate submission. | the finding id + the six sub-gate verdicts (each independently re-derivable; `tools/payout-gate.py` recomputes the composite) |
| **Severity→tier (B5, fix3 bounty mode)** | `cvss_score` is Roundup-derived from `cvss_vector` by the CVSS 3.1 formula (`tools/ev-score.py --self-test` proves the FIRST.org reference vectors), and the vector is bound to the PROVEN impact (the oracle's `execution_evidence`) — never inflated; `tier` = `program.reward_table` lookup of that score cross-checked with VRT `priority`; `expected_value` = reward_value(tier) × novelty_confidence × eligibility_confidence. `oracle_type:'severity-tier'`. A tier the model *claims* but that the vector does not deterministically yield is NOT the tier. | the `cvss_vector` + the `tools/ev-score.py` recomputation (independently re-derivable) |

### Methodology notes for the appended rows (same AI-discovers / oracle-validates discipline)
- **Flag oracle (P1) is a double gate:** (a) format match against the operator-declared regex, (b)
  **provenance** — the bytes appear in a captured `raw/` artifact an independent reader can re-derive
  (re-run the PoC, re-read the file, re-run `exiftool -a -u -g1`). Set `oracle_type:'flag-capture'`.
- **CTF solve oracles (P3):** the flag string alone is NOT proof — a saved, re-runnable derivation from
  the artifact under `raw/` is. For remote pwn, re-connect through `tools/leash-tcp.sh` and assert the
  flag comes back from the **in-scope origin IP** (reuses the existing `origin-check` veto).
- **Interactive oracle (P5):** because the HTTP leash is blind to raw TCP/WS, the wrapper's recorded
  frames ARE the proof — re-run `sock-replay.py` on the saved script and confirm the effect frames
  reappear; a session is only `confirmed` if the effect is re-derivable.
- **OTP-logic oracle (P6):** requires a **server-valid** session — re-fetch the protected resource in a
  fresh request (new client, no SPA state). A client-side flag flip that does not survive a fresh request
  fails the oracle.
- **Payout-ready analog (B2, fix3):** this is NOT a new impact verifier and does NOT gate "proven" — the
  impact oracle alone proves impact. `payout-ready` is a **deterministic composition of existing honest
  verdicts** (impact-proven ∧ in-scope ∧ eligible ∧ paying-tier ∧ dedup-cleared ∧ report-ready) computed
  by the synthesizer (`tools/payout-gate.py`) and enforced at `/triage` before submission. An unmet
  sub-gate is a structured `payout_blocker`, never fabricated; `could-not-verify` dedup is a blocker unless
  `objective.novelty.waive_unverified`. It can never suppress a proven finding — only gate whether it is
  SUBMIT-ready. Bounty-mode only; absent on an impact/flag run.
- **Severity→tier analog (B5, fix3):** `cvss_score` is deterministic (re-derivable by anyone who distrusts
  the model via `tools/ev-score.py`), but the reward amounts are **program policy** (operator-attested) —
  so this row is **audit documentation**, not a hard gate on findings. The vector is bound to the PROVEN
  impact; **never inflate a metric/vector/tier to clear a pay floor or reach a higher tier**; `expected_value`
  is a ranking signal, never a payout claim. Bounty-mode only.

These rows are textually independent and do **not** change `validateMission()`'s flow or the `ORACLE`
schema — `oracle_type`/`oracle_evidence` are already free-string fields. The two fix3 rows
(`payout-ready`, `severity-tier`) are economic/audit analogs layered ABOVE the impact oracle; they add no
verifier and no capability token, and they never override the impact oracle or the origin-check veto.

## How to run an oracle (validator)
1. Read the candidate's `poc_path` + `evidence` under `raw/`.
2. Re-execute the PoC YOURSELF, in scope, through the leash (`tools/leashed.sh`) — do not trust the
   author's narration.
3. Produce the oracle evidence for the class (table above). For OOB classes, start
   `bin/interactsh-client -json` first and inject a UNIQUE token so the callback maps to THIS test.
4. **Verdict:** `oracle_met=true` only if the oracle condition is objectively satisfied with captured
   evidence. Otherwise `oracle_met=false` — the finding does NOT ship (it's a lead).

## Rules
- One unique OOB token per injection (so a callback maps to exactly one payload).
- The oracle must be re-derivable from the captured evidence by someone who distrusts you.
- Stay within the program's safe-PoC limits; the oracle is minimal proof, never mass-exfil.
