---
name: ev-score
description: How a PROVEN finding becomes a reward TIER and an expected VALUE — the deterministic CVSS-from-impact score, the band→tier reward lookup, and the honest EV the cycle orders by. The economic analogue of the oracle. Bounty-mode only.
category: proof
tags: [severity, cvss, tier, expected-value, ev, bounty, prioritization, deterministic, evidence-bound]
chains_with: [oracles, payout-gate, poc-standard]
tools: [ev-score.py]
version: "1.0"
---

# Severity → tier → expected value (fix3 B5, bounty mode)

The oracle proves **impact** (`proof/oracles`). **Payout-ready** decides if a proven finding is *payable*
(`proof/payout-gate`). This skill answers the ordering question in between, and only in **bounty mode**:
given a proven finding, what **reward tier** does its evidence land at, and what **expected value** should
the cycle order its work by? Like the oracle, it is **deterministic and re-derivable by someone who
distrusts the model** — `tools/ev-score.py` turns a CVSS vector into a score, a tier, and an EV in code, so
the *economic* layer is an auditable fact, not the model's say-so. It adds **no new verifier and no
capability token**: it is a pure, read-only projection over verdicts the cycle already produced. Absent on
an impact/flag run (no `cvss_*`/`tier`/`ev` field is written; the line is byte-identical to today).

This is the `severity→tier` row in `proof/oracles/SKILL.md` (`oracle_type:'severity-tier'`): a tier the
model *claims* but that the vector does not deterministically yield is **not** the tier.

## 1. The CVSS score comes from PROVEN impact (the evidence-bound rule)
Build the `cvss_vector` **only** from what the oracle actually proved (`execution_evidence`) — the real
confidentiality / integrity / availability impact, the real attack vector, the real privileges needed.
Then `tools/ev-score.py` derives the score deterministically (the CVSS 3.1 base formula —
ISS → Impact → Exploitability → Roundup, scope-aware PR values), pinned in `--self-test` to the FIRST.org
reference vectors. The score is a **pure function of the vector**, so anyone can re-derive it.

> **Never inflate a metric to raise the score.** `AV:N` only if it is reachable from the network you were
> authorized on; `S:C` only if the proof crossed a scope boundary; `C:H/I:H/A:H` only for impact you
> actually demonstrated. A bigger payout is **never** a reason to nudge a vector. If the proof supports
> only a partial impact, the vector says so — and the tier follows the evidence, not the wish.

## 2. The band → reward tier lookup
The score maps to a CVSS **band** (None / Low / Medium / High / Critical), and the band maps to a reward
**tier** (`P1..P5`): Critical→P1 · High→P2 · Medium→P3 · Low→P4 · None/info→P5. The tier is then resolved
through the program's **`program.reward_table`** (transcribed by the operator from the brief, attested like
scope) for its `[min,max]` reward range. `tier` is the **evidence-derived reward tier** — distinct from:
- **`severity`** (the canonical CVSS band enum on every finding), and
- **`priority`** (B4 — the VRT *class* baseline, e.g. IDOR→P2, a lookup on the class, not the evidence).

Usually `tier == priority`. A **>1-band divergence** between the evidence-CVSS band and the VRT baseline
`priority` routes the finding to `human_review` (the **drift guardrail** — it catches *both* inflation
*and* under-grading). The tier is **always** the evidence band; `priority` is only a cross-check that
raises the flag — it never overrides the evidence (that would be inflation).

## 3. The expected-value formula (a ranking signal, never a payout claim)
```
novelty_confidence     = { novel: 1.0, could-not-verify: 0.5, likely-duplicate: 0.1, <absent>: 0.5 }   # B3 novelty
eligibility_confidence = { payable: 1.0, control-test-only: 0.3, unknown: 0.5, excluded: 0.0, <absent>: 1.0 }  # B4 eligibility
reward_value(tier):
    0                                  if tier == P5  OR  tier below objective.min_payable_tier
    midpoint (min+max)/2               if a reward_table lists the tier                       # MONETARY mode
    ordinal rank {P1:4,P2:3,P3:2,P4:1} if no reward_table (a valid order without dollars)     # ORDINAL mode
expected_value = reward_value(tier) × novelty_confidence × eligibility_confidence
```
- **Degrades gracefully.** Most private programs have no transcribed `reward_table`; EV then runs in
  **ordinal mode** (tier-rank proxy) and still yields a valid payout-maximizing *order*. A transcribed
  table upgrades EV to monetary (dollar-midpoint). A payable tier the table *omits* is "unknown range" —
  an ordinal proxy, **not** 0 (so a potential critical is not deprioritized for a transcription gap).
- **Honesty is structural.** `could-not-verify` contributes `0.5` and is **never** promoted to `novel`
  (1.0). A P5 / below-floor / excluded finding is honestly `expected_value:0` — correctly deprioritized,
  but still **recorded** as an honest finding (never deleted). EV is a *ranking scalar*, **never** a
  statement that the program will pay — `submitted`/`paid` stay operator-attested (B6).

## 4. The payout-maximizing ordering (analogous to foothold-first)
In bounty mode the brain orders hypotheses, findings, chains, and the next round by **expected value**.
But **foothold-first stays the PRIMARY key** (an unlocking foothold opens reward, so it precedes EV); EV
is the **secondary** key that orders equally-staged work. The empirical reward curve is steep
(Critical : Medium ≈ 16:1), so ordering by EV pulls a probable critical ahead of three probable mediums —
which raw-severity ordering does not. The F4 wave scheduler is **untouched**: `evOf()` is 0 in
non-bounty mode, and even in bounty mode it only tiebreaks *within* an equal foothold-stage. The
chain-builder is EV-aware: combine toward the highest-paying **eligible** end-impact (a chain is paid at
its proven end-impact tier, not the sum of its legs), and only propose a composite when its chain-EV
**exceeds the sum of its legs' EV**.

## Red line (non-negotiable)
- **Evidence-bound severity.** The `cvss_vector` is from the **proven** impact; `cvss_score` is its
  deterministic Roundup; `tier` is a table lookup of that score. **No path** raises a tier to reach a pay
  floor — a P4 proof under a P3 floor is honestly `expected_value:0`, never bumped to P3.
- **Honest dedup.** `could-not-verify` ≠ novel and is **never** auto-promoted. Novelty changes the EV
  *ranking* only — it **never** touches `severity`/`cvss_score`/`tier`.
- **Scope fidelity is sovereign.** EV/tier only **read** verdicts; they add no host, widen no scope, relax
  no safeguard, touch no leash. An excluded/out-of-scope finding is `eligibility_confidence:0` ⇒ EV 0 —
  deprioritized, still recorded, never "payable".
- **EV is a secondary key, under every safety gate.** It reorders only which *already-authorized,
  in-scope, equally-staged* hypothesis runs first. It schedules no blocked/safeguard path, promotes no
  auth-crack, and adds **no attack path** — B5 reads and orders.
- **Spider records; the operator submits.** `expected_value` is a prioritization signal; a payout is only
  real once the operator attests `submitted`/`paid` (B6).

## Run it (the auditor)
```
python tools/ev-score.py --vector CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H \
                         --reward-table targets/<t>/scope.yaml --priority P1 \
                         --dedup novel --eligibility payable --min-payable-tier P3
python tools/ev-score.py --vector <v> --reward-table '{"tiers":{"P1":[5000,20000]}}' --explain
python tools/ev-score.py --finding targets/<t>/findings.jsonl --reward-table scope.yaml   # grade each
python tools/ev-score.py --self-test                                                       # offline self-check
```
The synthesizer runs it per confirmed finding as it writes `findings.jsonl` (the single-writer invariant)
and stamps `cvss_vector` / `cvss_score` / `tier` / `tier_reward` / `expected_value` / `ev_basis`, then sets
`state.objective.ev_ranked` / `expected_value_total` by EV. `/triage` re-derives the tier from the vector
to kill any claimed-but-unproven tier; `/report` orders the submission by `expected_value`. The score is
re-derivable by anyone who distrusts the model (`--self-test` proves the reference vectors) — the oracle
philosophy, applied to the economic layer.
