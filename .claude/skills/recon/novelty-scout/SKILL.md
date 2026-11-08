---
name: novelty-scout
description: Build the prior-art / dedup pack targets/<t>/priorart.json EARLY (bounty mode) from PASSIVE public disclosure indices + local files — the program's disclosure history (HackerOne Hacktivity GraphQL), the stack's CVEs (NVD 2.0), component advisories (GHSA), the changelog, and the operator's own submitted/ archive — indexed by ROOT CAUSE so the fleet spends waves on the NOVEL surface first and never on $0 duplicates. Emits a per-(class,component) novelty_index (novel|likely-duplicate|could-not-verify). PASSIVE OSINT: touches no target, needs no leash.
category: recon
tags: [novelty, dedup, prior-art, osint, hacktivity, cve, ghsa, bounty, passive]
chains_with: [tech-specific, takeover]
tools: [novelty-index, h1grep, curl, jq]
version: "1.1"
---

# Novelty / prior-art mapping

## Gate
This lens is in the recon-2 set **only** when `args.novelty.sources_present` is true — i.e. the engagement
is `objective.mode:bounty` (or otherwise has disclosure sources configured in `objective.novelty`). A plain
web/impact/flag run never adds it (recon-2 guards the `LENSES.push`, the shipped P5 `interactive-surface`
precedent — zero roster change, no round-robin shift, when inactive). This lens **reuses the
`duplicate-scout` agent** (prior-art mode), not a generic recon-operator: the per-lens `agentType` override
in recon-2 routes it. If you are reading this, the operator opted into bounty-mode novelty work.

## Why this is the biggest bounty lever
Bug bounty is a **race-to-report-first tournament**: only the FIRST distinct submission is paid; a valid
duplicate earns **nothing**. `duplicate-scout` historically ran only at `/report` — by then the fleet had
already burned whole attack waves proving bugs that are **$0 duplicates** (already disclosed, already
patched, or already in the operator's own `submitted/` archive). This lens pulls novelty **UPSTREAM of the
oracle**: learn what is already known **before** attacking, so the fleet spends on the **novel** surface
first. It builds **one** shared artifact — `targets/<t>/priorart.json` — read upstream (to orient the
fleet) and again at the existing `/report` + `/triage` gates. **It is not a parallel engine and not a
verifier.**

## Objective
Build (or refresh) `targets/<t>/priorart.json` and emit a per-`(class, component)` `novelty_index`. Input:
`scope.yaml` + `state.json` (the recon surface / stack / `fingerprints[]`) + `objective.novelty` (operator
URLs). Output: the pack (schema in `brain/schema.md`) + the `novelty_index` for the synthesizer to tag
per-hypothesis. **This lens does NOT write the per-finding `novelty` field** — the single-writer synthesizer
does, reconciling this index against the ranked hypotheses (the single-writer invariant is untouched).

## Methodology (PASSIVE — no target traffic)
Prefer the deterministic builder; it enforces the coverage honesty switch in code:
```
python tools/novelty-index.py --target-dir targets/<t> --from-state \
    --hacktivity-handle <handle> --ghsa <ecosystem>:<package> --nvd-cpe <cpe> \
    --changelog-url <url> --match raw/novelty-scout/hypotheses.json
```
`--from-state` derives NVD keywords from `state.json.fingerprints[]` (`stack:<fw>@<ver>` → `<fw>`);
`--offline` forces local-only (and honestly records unreachable network sources as failed). You may also
build the pack by hand. Pull sources **in order of reliability**:

1. **Operator submission archive** `targets/<t>/submitted/*.json` — the MOST reliable source on THIS
   program, and now outcome-bearing: a `duplicate` record carries a `dup_ref`; a `paid`/`resolved` record
   means "this exact root cause already pays here — **re-test for REGRESSION, do not re-report**". Also read
   the context pack's disclosure-history section (`.claude/skills/context/<program>/SKILL.md`). **Local,
   offline, no network.**
2. **Program disclosure history** — for a public HackerOne program, the unauthenticated
   `hackerone.com/graphql` Hacktivity query filtered to the team handle (title / severity / CWE /
   `disclosed_at` / substate). The robust shortcut instead of hand-rolling that GraphQL:
   `bin/h1grep --program <handle> --query "<class/component>" --severity critical high medium --json --pages 5 > raw/novelty-scout/h1grep-<handle>.json`
   (keyword/CWE/bounty filters, no API key) — feed its rows into `tools/novelty-index.py --match` exactly
   like the raw GraphQL pull; it is the same public feed, just parsed for you. For non-H1 platforms the
   operator supplies the index URL(s) in `objective.novelty.disclosure_urls`. PASSIVE — public feed, no
   leash.
3. **Stack / component prior art** — **NVD CVE API 2.0** (`keywordSearch` / `cpeName` for each detected
   stack+version from `state.json`) and **GitHub Security Advisories** (`GET /advisories?ecosystem=&affects=`
   per dependency): known CVE/advisory + **patched version ranges**. A dependency on a vulnerable range the
   program has NOT been told about is **novel-for-this-program**; a patched version is dead.
4. **Changelog / release notes** (`objective.novelty.changelog_urls`) — what is **already fixed** (don't
   re-report) and where a fix is **narrow/incomplete** (a same-root-cause **variant** at an adjacent sink is
   a high-value hypothesis — pairs with the `tech-specific` lens).

Optional env (operator's OWN keys, read-only, never stored): `NVD_API_KEY`, `GITHUB_TOKEN` lift the public
rate ceilings. NVD/GHSA/Hacktivity are **not the target**, so requests go **direct — never through the
leash** (same class as subfinder/gau). On a `429`/timeout/unreachable a source is recorded as failed, which
lowers `coverage` — it is never faked.

## The root-cause "same-fix" test (Intigriti)
Index each disclosed item as a **root-cause fingerprint** — `class` + `cwe` + `component` + `root_cause` +
`fixed` — and match with the operational standard: *"would the fix for the disclosed item fix this
hypothesis too?"* Match on **CWE + component (+ sink + authz-context)**, **never** an endpoint string.
Require **both** a class/cwe match **and** a component match before calling `likely-duplicate` — a weak
class-only overlap (same class, different component) is conservatively **novel**, so a false "duplicate"
never buries a real finding (the duplicate-scout's stated failure mode). VRT's machine-readable class JSON
is the canonical class vocabulary for the class axis.

## Honest coverage (the honesty switch — never fabricate novelty)
`coverage` gates every downstream verdict:
- **`verified`** — a real disclosure source resolved and was indexed.
- **`partial`** — some sources resolved, some were unreachable.
- **`unverifiable`** — **NO** source resolved (private program, no archive, no public page) ⇒ **every
  verdict defaults to `could-not-verify`**, surfaced as *"could not verify novelty; operator must confirm
  before submit"* — **NEVER** reported as `novel`.

Verdict vocabulary is EXACTLY `novel | likely-duplicate | could-not-verify` (the canonical field contract —
no new value):
- **`likely-duplicate`** — requires a **real root-cause match with a `ref`** to an **open** disclosed item.
  A high-confidence duplicate LEAF is the one the attack sort deprioritizes (and `drop_duplicates` may hold
  as a lead); a duplicate that is a **prerequisite** for a novel dependent is dependency-safe (not buried).
- **`could-not-verify`** — the honest default without a confident match, **and** the verdict for a
  disclosed-but-**FIXED** match (a **VARIANT/REGRESSION seed** — re-test on the current build; if current
  behavior contradicts the disclosed fix, the operator/gate may treat it as a fresh payable finding). It
  **runs normally** (fail-open to attacking — a missed novel bug costs more than a wasted wave) and is
  flagged for the gate/operator, never auto-promoted to `novel`.
- **`novel`** — only when `coverage` is `verified`/`partial` **and** the index positively does not cover the
  root cause.

## What to return
The built/refreshed `targets/<t>/priorart.json` (`coverage`, `sources_checked[]`, `disclosed[]` with the
root-cause fingerprint, `checked_ts`) and a `novelty_index` — an array of
`{class, component, host, verdict, ref, reason, source}` per `(class, component)` — aggregated into the
recon-2 return (like `proposed_modes`/`proposed_ideas`). A surface no source covers under `unverifiable`
coverage is an honest **"could not verify"**, not a gap and not a "novel". Save the pack + the raw
pulls under `raw/novelty-scout/`.

## Graph edges / tokens
**None.** Novelty is **metadata on a hypothesis/finding**, not a capability and not an impact class. This
lens adds **no capability token** (the closed `session`/`creds`/`token`/`foothold`/`admin`/`shell` grammar
is untouched), sets **no** `requires`/`provides`, and — unlike the fix2 recon lenses — needs **no oracle
row** (the oracle/skeptics/synthesizer/leash are all untouched). It feeds the **`dedup-cleared`** rung of
B2's bounty ladder and the EV-aware secondary attack sort; it never enters the F4 dependency graph.

## Evidence
The `priorart.json` + each raw source pull (the Hacktivity GraphQL response, the NVD/GHSA JSON, the fetched
changelog) under `raw/novelty-scout/`, so the dedup decision is **re-derivable by someone who distrusts you**
(`tools/novelty-index.py` recomputes the pack deterministically). A verdict with no indexed source behind it
is `could-not-verify`, never a claim.

## Red line
- **Scope fidelity is sacred.** Every source is **passive OSINT** against public disclosure indices + local
  files — it **touches no target**, needs **no leash**, and **never widens scope**. A host that appears in a
  disclosed report but is **not** in `scope.yaml` stays a **lead**, never a target. Novelty selection never
  relaxes a policy or grants a capability.
- **Honest dedup — never fabricate novelty.** `unverifiable` ⇒ `could-not-verify`, never `novel`;
  `likely-duplicate` needs a real `ref`; a fixed match is a regression seed that runs normally; we never
  invent a disclosed-match to kill (or to justify) a submission.
- **Evidence-bound severity is untouched.** Novelty is **orthogonal to severity** — it orders work and gates
  submittability; it **never** inflates a tier or deflates a grade. The oracle + the CVSS recalibration
  remain the only severity authority. A novel finding is not "more severe"; a duplicate is not "less
  severe" — it is just not *payable*.
- **Spider records, the operator submits.** This lens produces the dedup intelligence; it never submits and
  never claims a payout. Exploit nothing here — this is read-only OSINT upstream of the attack phase.
