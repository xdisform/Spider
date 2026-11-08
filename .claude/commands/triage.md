---
description: Adversarial triage — a 3-stage skeptical veto funnel (Reproduce -> Impact -> Severity) that kills anything not truly proven, materially impactful, and honestly scored before you submit. Goal: zero false positives.
argument-hint: <target>
---

Triage the report for: **$ARGUMENTS**

The strictest pass before submission. You are NOT defending the findings — **three hostile triagers** try
to **break** them, staged as a funnel where **each stage is a VETO** and a finding is ruled SUBMIT only if
it survives all three. The two decisive gates are **deterministic** (re-derivable by someone who distrusts
the model), so nothing narrates its way to SUBMIT. Read `brain/schema.md`, then:

1. **Load.** Read `targets/<target>/findings.jsonl` (and `report.md` if present) and the evidence under
   `raw/`. Build `args` (per `brain/mission.md`): `{target, target_dir, scope, findings, bin_dir,
   skills_dir, model_tier, fleet}` — plus, in **bounty mode**, `program` and `objective` (with
   `min_payable_tier`), which switch on stage 3's eligibility / dedup / payout-gate leg.
2. **Run the funnel.** `Workflow({scriptPath:"workflows/triage.mjs", args})`. It stages three agents, each a
   veto; the survivors of one stage are the only input to the next:
   - **Stage 1 — Reproduce (`validator`, class-oracle veto).** Re-runs each PoC through the leash and
     produces the machine-checkable class oracle (`.claude/skills/proof/oracles/SKILL.md`). `oracle_met=false`
     — including the **origin-check veto** (a `127.0.0.1` / own-egress callback) — ⇒ **DROP**. No oracle, no
     finding.
   - **Stage 2 — Impact (`verifier-skeptic`, impact veto).** For oracle-met survivors, separates **business
     impact** (what the owner loses) from **attacker impact** (what a real external attacker *gains*, across
     a boundary: another user/tenant, a privilege, money, exec). Self-XSS, own-account-only, a
     victim-impossible interaction, or an out-of-scope target ⇒ `refuted` ⇒ **DROP**.
   - **Stage 3 — Severity (`triage-scorer`, severity/eligibility/payout veto).** Builds the CVSS 3.1 vector
     from the **proven** impact and scores it with the **FIRST calculator** (`tools/ev-score.py` — the
     FIRST.org 3.1 formula, self-tested against the reference vectors; it returns the official
     `first.org/cvss/calculator` link). Corrects any inflation **down**. In bounty mode it also checks
     eligibility (`brain/vrt.md`), dedup (`priorart.json`), and the deterministic `tools/payout-gate.py` —
     **a `payout_ready:false` finding can never be ruled SUBMIT**. Rules **SUBMIT / FIX / DROP**.
3. **Record.** Per finding the workflow returns a verdict with `killed_at` (`reproduce` | `impact` |
   `severity` | `null`) + reason, plus a `funnel` count (in/out per stage) and a `summary`. Write
   `docs/triage.md` with the per-finding rulings and update `findings.jsonl` (`refuted` / downgrades /
   corrected tier). A SUBMIT carries the honest `cvss_vector` / `cvss_score` / `tier` and the `first_url`;
   a FIX cites exactly what is missing (incl. `payout_blockers`).
4. **Report honestly.** How many survived each gate, how many were inflated and corrected, and what to fix
   before submitting. Spider **records**; the operator submits.

**The zero-false-positive contract.** A finding reaches SUBMIT only if it was *reproduced* (deterministic
class oracle), carries *real attacker impact* (a hostile skeptic could not refute it), and is *honestly
scored and payout-clean* (deterministic CVSS + payout-gate). The model cannot narrate past the oracle or the
arithmetic — that is what makes the 0-FP goal structural, not a promise. Be hostile: a finding that cannot
survive your own triage will not survive the program's.
