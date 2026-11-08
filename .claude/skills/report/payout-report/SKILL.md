---
name: payout-report
description: Triager-grade, payout-optimized report methodology — the specific title, CVSS vector with per-metric justification, business-impact framing, honest dedup note, program-template adherence, and one-shot-reproducible PoC a triager accepts without a round-trip. Bounty-mode only.
category: report
tags: [report, bounty, payout, cvss, triage, dedup, submission, poc]
chains_with: [oracles, poc-standard, payout-gate]
tools: [payout-gate.py]
version: "1.0"
---

# Payout-report — the triager-grade report (fix3 B7, bounty mode)

Proving impact is the oracle's job (`proof/oracles`); deciding a finding is *payable* is the gate's job
(`proof/payout-gate`). This skill is the **last mile**: turning a `payout_ready` finding into a report a
real triager accepts on the first read — no clarifying round-trip, no severity haggling, no "cannot
reproduce". It **adds no verifier and no capability token**: it only *renders* the fields the cycle
already produced (B1 `program{}`, B2 `payout_ready`/`payout_blockers`/`payout_distance`, B3
`novelty`/`novelty_ref`/`dedup_coverage`, B4 `eligibility`/`vrt`/`priority`, B5
`cvss_vector`/`cvss_score`/`tier`/`expected_value`). It is **bounty-mode only** — on an impact/flag run
(no `objective`/`program`) `/report` behaves byte-identical to today and this skill is inert.

The platforms all converge on the same contract: a **specific title**, **one-shot reproduction**, a
**class-appropriate minimal PoC**, a **CVSS vector string**, **business-impact framing**, and
**template adherence** (HackerOne Quality Reports; Bugcrowd VRT templates; Intigriti). A proven bug fails
to pay on four orthogonal axes beyond impact — **reproducible, in-scope/eligible, severity-floor,
novel** — the exact four the fix3 upstream gates already settled. The triage team pulls
Informative / Duplicate / Not-Applicable *before the program ever sees them*; this skill writes so none
of those three dead-ends can fire.

## Build order (what to render, and in what order)
1. **Gate to payable.** Build the submission body **only from `payout_ready:true` findings** (B2). A
   `payout_ready:false` finding is **never silently dropped** — list it with its `payout_blockers` so
   the operator sees the one thing it still needs (and whether it chains up).
2. **Order by `expected_value`** (B5), highest first. Submission "signal" is a limited resource on
   H1/Bugcrowd — spend it best-first. `expected_value` is a **ranking scalar, never a payout claim**.
3. **Render each finding** to the program template (below), with the title, CVSS vector + per-metric
   justification, business impact, the one-shot PoC, and the honest dedup note.
4. **Eligibility appendix** for the `eligibility:"excluded"` noted leads.
5. **Pre-submission checklist** — the machine-checkable `report-ready` rung; a report that fails it is
   not submission-ready.
6. **Spider records; the operator submits.** On an operator-attested submit, write the B6 stub
   `targets/<t>/submitted/<finding-id>.json`. Spider **never auto-submits**.

## Program template matrix (pick by `program.platform_taxonomy`)
If `program.report_template` names an operator-transcribed template, **follow it verbatim** — it wins.
Otherwise select by `platform_taxonomy`:

| taxonomy | template sections | severity vocabulary |
|---|---|---|
| `vrt` (Bugcrowd) | **Overview of the Vulnerability · Business Impact · Steps to Reproduce · Proof of Concept** | the `vrt` id + `priority` (P1..P5) |
| `cwe-cvss` (HackerOne / Intigriti / YesWeHack) | **Asset · Weakness (CWE) · Severity (CVSS vector) · Proof of Concept (what / steps / impact)** | the `cwe` + `cvss_vector` + `cvss_score` + `tier` |

The URL goes in the **endpoint/asset field**, not the title (Intigriti rule). Attach any PoC video as a
**file, never a link** (HackerOne rule).

## Title formula
`<vuln type> in <endpoint> [<parameter>] — <concrete impact>`. Carry the parameter + endpoint so a
triager can route it instantly.
- GOOD: ``IDOR in `GET /export/{id}` — cross-tenant document read``
- GOOD: ``SQL injection in `/search` `q=` — DB banner extracted``
- BAD: "IDOR found", "SQLi on this panel" (the LevelUp anti-pattern).

## Per-class minimal-but-sufficient PoC (reuse the oracle shape you already captured)
The report proof form **is** the oracle evidence the finding already produced (`proof/oracles`) — so the
writer recognizes it fast and the triager reproduces it fast. Minimal, never mass-exfil; synthetic
accounts only; the mandatory header (`required_header`) on **every** request; inside the program's
safe-PoC policy.

| Class | Minimal PoC a triager accepts | Source artifact |
|---|---|---|
| SQLi (in-band) | the returned **DB banner** (`database()`/`@@version`/`current_user`) — the real string, not "injectable" | request + response under `raw/` |
| SSRF / blind RCE/XXE/SQLi | the **OOB callback** for a UNIQUE interactsh token fired by the payload | the `interactsh.jsonl` line (token, proto, src-IP, ts) |
| RCE | **command output** (`whoami`/`id`/`hostname`) or the command's OOB callback | request + response/callback with the exact output |
| IDOR / BOLA | **two-tenant record**: A receives B's data, returned owner-id ≠ A | both requests (A→A, A→B) + the owner field |
| File-read / traversal | a file with a **KNOWN signature** (`root:x:0:0`, a config key) | request + the signature bytes |
| CORS | the **runnable `cors-poc.html`** reading a real authenticated cross-origin body (ACAO reflects + ACAC true) | the embedded `poc_path` artifact |
| XSS | **execution proof** — a blind-XSS OOB callback or a headless-browser assert — not a reflected string; demonstrate **data access, not `alert(1)`** | callback line / browser-exec proof / the runnable artifact |
| Open redirect | the **3xx `Location`** pointing to the attacker-controlled host | the response headers |
| Auth bypass / ATO | the boundary crossed: **401/403 → 200** with privileged content that re-fetches cleanly | before/after requests |
| SSTI | **template evaluation** output (a server-side arithmetic/marker eval, or RCE output if reached) | request + the evaluated response |
| GraphQL (alias-batch IDOR/BOLA) | the **batched-alias** response returning multiple tenants' records in one query | the query + the multi-owner response |

For XSS/CORS/open-redirect/upload classes **embed the runnable PoC artifact** (`poc_path` the attack
phase built), not a prose claim.

## One-shot reproducible PoC (the hard bar)
"Something obvious to you may not be obvious to the triager." Give a **copy-paste `curl`/HTTP** sequence
backed by the concrete proof in `raw/` + `execution_evidence`, so the triager reproduces it **without a
single round-trip**:
- Every request shows the **mandatory header**; **synthetic accounts only, never a real login**.
- Specify browser/OS only when it matters.
- Demonstrate **actual impact** (the data row / the `id` output / the OOB callback), never a popup.
- The PoC a triager runs must be the **same PoC the oracle re-derived** — if the oracle could re-run it,
  so can the triager.

## CVSS vector with per-metric justification (defensibility)
Emit the full **`cvss_vector` string** (not a bare word) + `cvss_score` + `tier` + (`tier_reward` when
monetary). A **missing vector is a report blocker** (B2 sub-gate 4), never an assumed tier. Then give a
**one-line evidence justification per load-bearing metric**, so `/triage`'s skeptics and the program's
triager cannot knock the tier down:
- `PR:N` — the endpoint is **pre-auth** (the repro shows the 200 with no session).
- `S:C` — the SSRF **reaches the metadata service** (the callback proves the scope change).
- `C:H` — the leaked record is the **victim's PII** (the two-tenant proof).

The vector is the **B5 recalibration of PROVEN impact** — bound to the oracle's `execution_evidence`.
**Never inflate a metric, vector, or tier to clear a pay floor or reach a higher tier** (B2/B4/B5 red
line). A finding whose proof only supports a sub-floor tier is honestly `payout_ready:false`
(`tier below pay floor`), listed with its blocker — not relabeled up.

## Business-impact framing (not a CVSS restatement)
State the **real-world damage to this asset's users/business** — what an attacker actually achieves —
tailored to the asset's `asset_tier` (B1). The same leaked credential is lower impact if it only reaches
internal hosts, higher if it reaches public assets (Bugcrowd's context rule). This is prose the
synthesizer writes, **distinct from** the CVSS line — never a reworded vector.

## Honest dedup note (per finding, from `priorart.json`)
Reconcile with the synthesizer's upstream `f.novelty` (read `priorart.json` first — consistency, no
re-fetch). Matched by **root cause** (CWE + component + sink + authz-context, the "same-fix" test), not
host+endpoint. Three states, verbatim — **never** auto-promote to novel:
- **`novel`** — submit. (`payout_ready` requires a *positive* `novelty:novel`, the economic analogue of
  the flag provenance gate.)
- **`likely-duplicate`** + `novelty_ref` (`h1#…`/`CVE-…`/`GHSA-…`/`submitted:f-XXXX`) — the operator
  decides; don't burn a report. Submit **as a regression** only if the current build contradicts the
  disclosed fix.
- **`could-not-verify`** (a private program with no archive, `dedup_coverage:unverifiable`) — report it
  **verbatim**: "could not verify novelty; operator confirms before submit." **Never** auto-"novel".
  **Novelty never touches `severity`.**

## Eligibility appendix (B4 — honest record, never deletion)
`eligibility:"excluded"` findings are **dropped from the submission body** and listed in a
**"Noted, not submitted (out-of-taxonomy / accepted-risk)"** appendix with their `eligibility_reason` —
an honest record, never silently deleted. An excluded class that **chains** into a payable impact is
reported through the chain (the chain's proven impact pays), never on its own.

## Kill-chain narrative (unchanged)
Tie findings into the chain from `killchain.md`: entry → escalation → lateral → objective. A proven chain
of mediums is usually the critical and the real payout ("the chain is the value").

## Pre-submission checklist (the `report-ready` rung — machine-checkable, not a vibe)
HackerOne's four quality questions, made the deterministic `report-ready` sub-gate (B2 sub-gate 6,
ISO-29147). Reuse `python tools/payout-gate.py --finding <f> --scope <scope> --explain` so `/report`
cannot ship an incomplete report — the checklist **pass IS the rung**:
1. **Reproducible?** `repro` steps + a runnable `poc_path` a triager replays verbatim.
2. **Impact clear?** the business-impact sentence + the CVSS vector + its per-metric justification.
3. **Supporting materials?** the `raw/` evidence + the PoC artifact (attach videos as files).
4. **Proper format?** code blocks + markdown; the program template's sections all present.

And the four pay-or-not axes (the HackerOne invalid-reason taxonomy) — each already a `payout_ready`
sub-gate, so a passing checklist means none of the three dead-ends can fire:

| H1 dead-end | upstream gate | the report shows |
|---|---|---|
| Not-Applicable (not reproducible) | the impact oracle | the one-shot PoC + `execution_evidence` |
| Informative (out of scope/eligibility) | B4 eligibility | `eligibility:payable` (excluded ⇒ appendix) |
| Duplicate | B3 novelty | `novelty:novel` (+ `novelty_ref` if not) |
| (sub-floor, pays nothing) | B5 tier vs `min_payable_tier` | `tier` at/above the pay floor |

## Red line (non-negotiable)
- **Scope fidelity is sacred.** `/report` only ever submits in-scope `payout_ready` findings. A high
  projected payout is **never** a reason to touch anything outside `scope.yaml`; an out-of-scope asset is
  a noted lead, never a submission.
- **Honest dedup — never fabricate novelty.** `could-not-verify` ≠ novel and is never auto-promoted;
  `likely-duplicate` is reported with its ref; **novelty never touches `severity`.**
- **Evidence-bound severity.** The CVSS vector is the recalibration of **proven** impact with a
  per-metric justification tied to the evidence — **never inflated to clear a pay floor or reach a higher
  tier**. The impact oracle still gates "proven"; economics never upgrade an unproven finding and never
  suppress a proven one.
- **Spider records; the operator submits.** `submitted`/`paid` come only from operator attestation (the
  B6 `submitted/<id>.json` stub + `/outcome`). Spider **never auto-submits** and never claims a payout it
  cannot prove.
- **No safeguard evasion for money.** Everything blocked/handed-off in impact/flag mode stays blocked in
  bounty mode. A payable finding is reached only by a legitimate, oracle-provable path; the ORACLE gate,
  the 4 skeptic lenses, the single-writer synthesizer, and the leash/scope authority are untouched.
