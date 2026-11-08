---
name: payout-gate
description: What makes a finding PAYABLE, not just proven — the six composed gates and the 8-rung ladder a bounty finding must clear before /triage may rule SUBMIT. The economic analogue of the oracle. Bounty-mode only.
category: proof
tags: [payout, bounty, gate, dedup, severity, eligibility, submission, deterministic]
chains_with: [oracles, poc-standard]
tools: [payout-gate.py]
version: "1.0"
---

# Payout-ready — the payable verdict (fix3 B2, bounty mode)

Proving impact is the oracle's job (`proof/oracles`). **Payout-ready** is the next question, and only in
**bounty mode**: is this proven finding one a program will actually *pay* for? It is the economic analogue
of the flag-capture oracle — and like the oracle, it is **deterministic and re-derivable by someone who
distrusts the model**. It adds **no new verifier and no capability token**: it is a pure AND over verdicts
the cycle already produced, computed by the synthesizer with `tools/payout-gate.py` and enforced at
`/triage`. It can **never suppress a proven finding** — it only decides whether that finding is
SUBMIT-ready. Absent on an impact/flag run (no `payout_*` field is written; the line is byte-identical).

## The composite — six sub-gates, all must hold
A finding `f` is `payout_ready:true` **iff all six** hold. Each false term appends a structured string to
`f.payout_blockers`, so the brain knows the one thing the finding still needs:

| # | Sub-gate | Owner | True when | Blocker if false |
|---|----------|-------|-----------|------------------|
| 1 | impact-proven | EXISTING oracle | `verified:true` ∧ `refuted≠true` ∧ `oracle_type` set | `impact: not oracle-proven` |
| 2 | in-scope / ROE | EXISTING scope | `target` host ∈ `scope.yaml` hosts/netblocks, not `out_of_scope`, in safe-PoC policy | `scope: host <h> not in scope.yaml / over-policy` |
| 3 | eligible class | **B4** | `eligibility == 'payable'` (not excluded / control-test-only / unknown) | `eligibility: <reason> (B4)` |
| 4 | paying tier | **B5** | `cvss_vector` ∧ `tier` present, `tier` at/above `objective.min_payable_tier` | `tier: no CVSS vector` / `tier: <t> below pay floor <floor>` |
| 5 | dedup-cleared | **B3** | `novelty == 'novel'` | `dedup: likely-duplicate (ref …)` / `dedup: could-not-verify — operator must confirm novelty` |
| 6 | report-ready | ISO-29147 | `repro` ∧ `poc_path` ∧ `detail` ∧ `target` ∧ (`cwe` ∨ `remediation`) | `report: missing <element>` |

`payout_ready === (payout_blockers.length === 0)`. This is exactly the `payout-ready` row in
`proof/oracles/SKILL.md`: `oracle_type:'payout-ready'`, evidence = the finding id + the six sub-gate
verdicts, each independently re-derivable (`tools/payout-gate.py` recomputes the composite).

These are the gates a real triager applies **up front** (HackerOne pulls Informative / Duplicate /
Not-Applicable before anything reaches the program). Computing them *before* submission means the fleet
orients at findings a triager will accept, not impact a triager will bounce.

## The 8-rung ladder — the progress signal
```
signal → reproduced → impact-proven → severity-graded → dedup-cleared → report-ready → submitted → paid
```
`payout_distance` is the **highest rung reached given the fields present** (the brain's "how close to
payable" signal, mirroring the flag-mode `objective.distance`). `payout_ready` ⟺ the ladder reached
**`report-ready`** (all six autonomous gates). The last two rungs, **`submitted` and `paid`, are
operator-attested** (B6) — Spider records them from `targets/<t>/submitted/<id>.json`; this gate never
claims them. A finding graded at a below-floor tier, or blocked on scope/eligibility, honestly shows its
distance capped below `report-ready` with the blocker that says why.

## How to read the blockers (steering)
- `impact: not oracle-proven` — it is a **lead**, not a finding. Back to attack; prove it or drop it.
- `scope: …` — the host is not in `scope.yaml` / over-policy. **Never widen scope to clear it.** Drop.
- `eligibility: … (B4)` — the class is excluded / P5. Keep it as a **noted lead**, never submit it,
  never burn fleet on it — unless it **chains** into a payable impact (then the chain's impact pays).
- `tier: … below pay floor …` — the proven impact is below what the program pays. **Chain it up** to a
  higher end-impact, or drop. **Do NOT inflate the CVSS vector or tier to clear the floor.**
- `dedup: likely-duplicate` — already disclosed/patched/known. Drop, or submit **as a regression** only
  if the current build contradicts the disclosed fix.
- `dedup: could-not-verify` — a private program with no archive. **Not a duplicate and not novel** —
  hand the novelty call to the operator (or set `objective.novelty.waive_unverified` on their waiver).
- `report: missing <element>` — `/report` has an ISO-29147 gap (repro / PoC / impact / host / CWE).
  Fill the element; the report is not submission-ready until it is.

## Red line (non-negotiable)
- **No fabrication.** `payout_ready` is a composition of honest verdicts; an unmet sub-gate is a
  structured blocker, **never** invented. The model *calling* a finding payable does not make it so.
- **Honest dedup.** `could-not-verify` ≠ novel and is **never** auto-promoted to `cleared`. Novelty
  never touches `severity`.
- **Evidence-bound severity.** `tier` comes from the CVSS vector, which comes from the **proven**
  impact. If the proof only supports P4 and the program pays P1–P3, the finding is honestly
  `payout_ready:false` (`tier below pay floor`) — **not** inflated to P3.
- **Scope fidelity is a hard AND term.** `payout_ready` can never be true for a host outside
  `scope.yaml` or safe-PoC policy. The gate **consumes** scope; it never widens it.
- **Spider records; the operator submits.** `submitted`/`paid` come only from operator attestation.
  Spider never auto-submits and never claims a payout it cannot prove.

## Run it (the auditor)
```
python tools/payout-gate.py --finding targets/<t>/findings.jsonl --scope targets/<t>/scope.yaml
python tools/payout-gate.py --finding f.json --scope scope.yaml --explain   # ladder + each sub-gate
python tools/payout-gate.py --self-test                                      # offline self-check
```
The synthesizer runs this per finding as it writes `findings.jsonl` (the single-writer invariant) and
stamps `payout_ready` / `payout_blockers` / `payout_distance`. `/triage` enforces it: a
`payout_ready:false` finding **cannot** be ruled SUBMIT — the hostile triager is forced to FIX and must
state the exact `payout_blockers`. `--fail-unless-ready` (exit 3) is a submission guard for a batch.

## The learning loop
`submitted`/`paid` close the loop: an operator submission archived under `targets/<t>/submitted/` is
**tomorrow's most reliable dedup source** (the duplicate-scout reads it), and the recorded outcome tunes
the per-program acceptance prior and effective pay floor. A finding that is impact-proven but repeatedly
closed informative/duplicate on a program teaches the brain to chain higher next time — the payout gate
turning real outcomes into sharper hunting.
