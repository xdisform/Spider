---
description: Turn a target's proven findings and kill chain into a human, submission-ready report with full PoC.
argument-hint: <target>
---

Write the human report for: **$ARGUMENTS**

1. Read `targets/<target>/findings.jsonl`, `state.json`, `killchain.md`, `docs/99-infra-final.md`,
   `priorart.json` (fix3 B3, if present), and the evidence under `raw/`.
2. Keep only **real, verified** findings — `verified:true`, `refuted:false`, with
   `execution_evidence` (or, for misconfig classes, a runnable PoC artifact). Drop `not_reproduced`
   and anything without a file under `raw/`. Dedup internally.
3. **Duplicate check before submission.** Spawn a `duplicate-scout` agent over the surviving findings
   (operator's submission archive → target context pack → public disclosure, best-effort). In bounty
   mode it **reads `priorart.json` first** (consistency + no re-fetch) and reconciles with the
   synthesizer's upstream `novelty`. Flag `likely_duplicate` items; the operator decides whether to
   still submit. Don't burn a report on a known duplicate; report `could-not-verify` verbatim (private
   program) — **never** auto-promote it to "novel".
4. For each finding: title, severity (justified by proven impact), affected hosts/URLs, vulnerable
   parameters, **full reproduction steps / PoC** (copy-paste, backed by the concrete proof in
   `raw/`), security impact, CWE, and remediation. Every request shows the mandatory header; only
   synthetic accounts; no real logins.
5. Tie findings into the kill-chain narrative: entry → escalation → lateral → objective. Include the
   chains from `killchain.md` — a proven chain of mediums is often the critical.
6. Write it human and submission-ready to `targets/<target>/report.md`. No filler, no unproven
   claims. If a program report template is referenced in scope, follow it.

## Bounty mode — triager-grade, payout-optimized (fix3; applies only when `objective.mode==='bounty'`)
In `impact`/`flag` mode (no `objective`/`program`, or the fields absent) `/report` behaves **exactly as
steps 1–6 above** — field-presence-gated, byte-identical to today. When `mode:bounty` + the economic
fields are present, add (methodology: `.claude/skills/report/payout-report/SKILL.md`):
- **Build the submission body ONLY from `payout_ready:true` findings** (B2). For a `payout_ready:false`
  finding, do **not** silently drop it — show its `payout_blockers` so the operator sees the one thing each
  still needs.
- **Order the body by `expected_value`** (B5), highest first — submission "signal" is a limited resource;
  spend it best-first.
- **Emit the full severity grade:** the CVSS 3.1 **`cvss_vector` string** (not just a word) + `cvss_score`
  + `tier`, and the `vrt`/`cwe` id — pick the template vocabulary by `program.platform_taxonomy`
  (Bugcrowd `Overview · Business Impact · Steps to Reproduce · Proof of Concept` with the VRT id; H1/
  cwe-cvss `Asset · Weakness (CWE) · Severity (CVSS vector) · PoC`). If `program.report_template` names an
  operator-transcribed template, follow it verbatim. A **missing CVSS vector is a report blocker** (B2
  sub-gate 4), never an assumed tier.
- **Title** = vuln type + endpoint + parameter ("IDOR in `GET /export/{id}` — cross-tenant document read",
  never "IDOR found").
- **Business-impact framing** (not a CVSS restatement): what an attacker achieves against *this* asset,
  tailored to its `asset_tier`.
- **One-shot reproducible PoC** (the hard bar — a triager accepts without a round-trip): copy-paste
  `curl`/HTTP steps backed by `raw/` + `execution_evidence`, the mandatory header on every request,
  synthetic accounts only; embed the runnable PoC artifact (`poc_path`) for XSS/CORS/redirect; demonstrate
  **actual impact** (data row / `id` output / OOB callback), not an `alert(1)`. Attach any PoC video as a
  file, never a link.
- **Severity defensible to a hostile triager:** state the CVSS vector + a one-line per-metric justification
  tied to the evidence (`PR:N` because pre-auth; `S:C` because the SSRF reaches the metadata service).
  **Never inflate to clear a pay floor** (B2/B4/B5 red line).
- **Dedup note (honest):** per finding cite `novelty` + `novelty_ref` from `priorart.json` — `novel`
  (submit) / `likely-duplicate` (operator decides) / `could-not-verify` (operator confirms before submit,
  never auto-novel).
- **Eligibility appendix (B4):** `eligibility:"excluded"` findings are **dropped from the submission body
  and listed in a "Noted, not submitted (out-of-taxonomy / accepted-risk)" appendix** — an honest record,
  never silently deleted.
- **Pre-submission stub (B6 schema):** on an operator-attested submit, write the pre-submission stub
  `targets/<target>/submitted/<finding-id>.json` via `python tools/outcome-record.py --write` (so the
  `outcome.schema.json` validator enforces the shape) — `state:"submitted"`, `outcome:"pending"`, with the
  economics/fingerprint fields already in hand. Use the OUTCOME-record field names (NOT the canonical
  finding names): **`finding_id`** (`^f-NNNN$`, the required key), **`est_tier`** (the tier snapshot —
  deliberately distinct from the canonical `finding.tier`), plus `cvss_vector, novelty, class, cwe,
  component, root_cause, host, platform, submitted_ts`. The terminal outcome is filled later by `/outcome`.
  This is the record `duplicate-scout` reads (keyed on `finding_id`) as its most-reliable dedup source.
  **Spider records; the operator submits — Spider never auto-submits.**
