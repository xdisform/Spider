# Changelog

All notable changes to Spider. Format loosely follows [Keep a Changelog](https://keepachangelog.com);
Spider is a living orchestrator, so entries are grouped by theme rather than strict semver releases.

## [Unreleased] — senior-uplift + release hardening (2026-11)

### Triage — 3-stage pre-submission veto funnel
- **`/triage` rebuilt as a staged funnel** (`workflows/triage.mjs`): Reproduce (`validator`, class-oracle
  veto) → Impact (`verifier-skeptic`, business + attacker-impact veto) → Severity (new `triage-scorer`,
  real CVSS + eligibility/dedup/payout-gate veto). Survivors of each stage are the only input to the next;
  a finding is ruled SUBMIT only if it clears all three. Replaces the single-skeptic-per-finding pass. The
  decisive gates (class oracle, FIRST CVSS, payout-gate) are deterministic — **zero false positives by
  construction**, not by promise.
- **New `triage-scorer` agent** — derives the CVSS 3.1 vector from the PROVEN impact, scores it with the
  FIRST calculator (`tools/ev-score.py`), corrects any inflation **down**, and runs the deterministic
  `tools/payout-gate.py` (a `payout_ready:false` finding can never be ruled SUBMIT).
- **`tools/ev-score.py`** now emits the official `first.org/cvss/calculator` link (`first_url`) with every
  grade, so a reviewer can re-verify the score on the FIRST calculator.
- **`smoke-workflows`** now executes `triage.mjs` end-to-end over random funnel branches — previously the
  one workflow with no smoke coverage.

### Attack phase — the hypothesis lifecycle
- **Reflect stage + `advisor` agent** — the missing Execute→Reflect→re-Execute loop. An attempted-but-
  unproven lead now gets an Advisor pass (derives the failure reason from the attempt artifacts) and one
  **sharpened retry** through the unchanged oracle gate before it is written off. Reflection ~doubles
  success in the literature (RefPentester, Red-MIRROR). In `attack.mjs` and `chain.mjs`
  (`reflect_rounds`, default 1; `reflect_max`).
- **Iterative reflect rounds** — a retry that still fails gets a fresh Advisor read next round, up to
  `reflect_rounds`; an `exhausted` verdict retires a lead.
- **In-turn self-reflection checkpoint** — after ~3 failed variants on one sub-approach the operator
  pauses, names why, and pivots or declares it dead instead of grinding.
- **Per-hop validation** (`hops[]`/`hops_reached`) — a multi-step hypothesis proves each hop's own
  mini-oracle before the next; a later hop can't be claimed on an unproven earlier one. Stops hallucinated
  end-to-end chains.
- **Evidence→Hypothesis→Verification discipline** + **anti-deception** (reject echoed payloads /
  honeypot 200s / fabricated success) in the operator and the impact skeptic.

### Find-rate levers
- **`deep-source-trace`** (recon-2 lens + `tools/source-trace.py`) — Vulnhuntr-style whole-tree
  source→sink taint tracing over the recovered JS, emitting verified chains as attack seams.
- **`cred-reuse` + `escalation-ladder`** — a proven credential is reused across the in-scope estate;
  a foothold climbs to the highest eligible impact (post-foothold planner, policy-gated).
- **`recall.py`** — in-run memory: agents query the target's own prior attempts (worked / dead-end /
  findings) so the fleet stops re-treading. Wired into recon-1/2, attack, chain.
- **`dynamic-validate`** (proof) — client-side bugs proven by real execution in the leashed Playwright MCP.
- **`cve-intel`** (recon-2 lens) — stack+version → prioritized exploitable-CVE list (KEV/EPSS/template)
  seeding variant analysis.
- **`waf-mutation`** (proof) — a WAF block triggers wafrift's evolutionary bypass, then re-proves the
  class oracle (a bypass without impact is not a finding).

### Recon
- **OSINT arsenal made runnable** — the installed-but-depless python tools (theHarvester, maigret,
  spiderfoot, cloud_enum, LinkFinder, SecretFinder) got their deps + `bin/` wrappers; `cloud_enum`,
  `LinkFinder`/`SecretFinder`, `hakrawler`/`gospider` wired into their recon skills.
- **THOROUGHNESS** directives in recon-1/recon-2 — run every tool per modality + merge-dedup, exhaust
  params/source-maps/CVEs, cross-pollinate; all within the leash rate-cap.

### New skill packs
`prototype-pollution`, `cache-poisoning` (wiring fixed), `artifact-analysis`, `escalation-ladder`,
`deep-source-trace`, `cve-intel`, `dynamic-validate`, `waf-mutation`. Index at 92 packs.

### Guards & fixes
- **New smoke guards:** `smoke-resolver` (attack↔chain resolver kept in sync + every pack reachable),
  `smoke-arsenal` (every `bin/<tool>` a skill references exists), `smoke-workflows` (every workflow
  executes end-to-end with mocked agents — catches runtime bugs `node --check` cannot).
- **Fixed:** the `attack.mjs`↔`chain.mjs` resolver had drifted 22 packs apart (now synced + guarded); a
  `CLIENT_SIDE is not defined` ReferenceError that would have crashed the validator every run; four
  orphaned/dangling skill wirings (`cache-poisoning`, `artifact-analysis`, `rate-limit-audit`,
  `target-classify`).

### Release hardening
- **CI** (`.github/workflows/smoke.yml`) runs the offline guards on push/PR.
- **`CONTRIBUTING.md`**, publish-safety pre-commit hook documented in `README`/`SECURITY`.
- **Genericity** — program-specific oracle markers (`standoff365` / Domain Admins group / backup marker
  file) moved to a configurable `objective.oracle_markers` in `scope.yaml` (defaults kept as the worked
  example); the AD / backup-pivot packs are now program-agnostic.

### Design doctrine
- `brain/attack-evolution.md` — the hypothesis lifecycle, the agent roster, and the research basis.
- `docs/mcp-integration.md` — which MCP servers Spider adopts (and deliberately refuses) and how they
  route through the leash.
