# Synthesis — the clean-context read after each phase

After a workflow returns, the brain does **not** summarize from its own context. It spawns a
fresh **synthesizer** agent (`.claude/agents/synthesizer.md`) whose only inputs are the target
folder and this doctrine. A clean reader, uncontaminated by the noise of the hunt, produces the
stage document. That document becomes the brain's memory of the stage.

## Inputs (the synthesizer reads, never guesses)
- `targets/<t>/raw/<agent>/` — every agent's evidence + `result.json`.
- `targets/<t>/state.json` — prior world model (may be empty on the first pass).
- `targets/<t>/scope.yaml` — to keep everything in-scope and priority-aware.

## Outputs (per phase)
- **After recon-1 → `docs/01-recon-surface.md`**: absolutely everything about the target's
  external state. All hosts + IPs, resolved DNS, open ports/services + versions, technologies,
  discovered endpoints/parameters, archived URLs, secrets/leaks, cloud assets, WAF/tech
  fingerprint. Rank hosts by priority. This is the "state of the target" document.
- **After recon-2 → `docs/02-infra-hypotheses.md`**: the infrastructure map (how the pieces
  connect) + a **ranked list of hypotheses** — each `{id, host, class, why, how-to-prove,
  confidence}`. This is what the attack phase will try to prove.
- **After attack → `killchain.md` + `docs/99-infra-final.md`**: the official end state.
  `killchain.md` = the chain(s) entry → escalation → lateral → objective. `99-infra-final.md` =
  proven findings (with PoC pointers), still-open hypotheses, the full infra map, and an honest
  "what's stuck and why".

## Always also
- **Write `findings.jsonl`** — one canonical line per confirmed finding (schema in
  `brain/schema.md`), applying the evidence gate (no `execution_evidence` on a high/critical
  impact class → downgrade to a `[UNCONFIRMED CANDIDATE]`). The synthesizer is the **only**
  writer of this file.
- **Recalibrate severity by CVSS — both directions, evidence-bound.** The gate only downgrades;
  you also **review each finding against CVSS 3.1** and correct under-grading: an unauth info
  leak on a critical-priority host, a credentialed-CORS read, a control-defect on an auth endpoint
  are commonly medium/high, not low — raise them when the evidence supports it. An upgrade must be
  justified by the evidence + a one-line CVSS rationale; never inflate beyond what is proven.
  `misconfig_proven` findings have a floor of `low` (never `info`) when a PoC artifact exists.
- **Merge `state.json`** — add hosts/services/creds/**capabilities**/leads/hypotheses (carry each
  hypothesis's `stage`/`requires`/`provides`); move proven ones to `confirmed`, killed ones to
  `refuted`. A capability enters `capabilities[]` ONLY if oracle-proven or operator-supplied
  (`session.env`) — never assumed. Merge the attack return's `human_review` (blocked/died/needs-foothold
  items + evidence + options) into `state.json.human_review` so the brain raises it before final
  synthesis — a blocked/safeguard path is a hand-off, never a silent lead. After `/chain`, also record
  **`techniques`** (what worked, for reuse next run) and **`dead_paths`** (seeded targets that didn't
  reproduce, so future runs don't re-tread them). Never drop prior state on a re-run.
- For oracle-validated findings (attack / `/chain`), carry `oracle_type` + `oracle_evidence` into
  `findings.jsonl` — the deterministic proof is what makes the report credible.
- **Merge the objective block (P1, flag mode only — single-writer).** The synthesizer is the **only**
  writer of `state.json.objective`, same invariant as the rest of state.json. When attack returns an
  `objective` block, merge it into `state.json.objective`. **If no attack ran this phase** (recon only),
  compute `distance` yourself from the world model: a flag string in a confirmed finding ⇒ `flag`; a
  confirmed read/RCE/SQLi/traversal ⇒ `file-read-or-rce`; an acquired `session:`/`creds:`/`foothold:`/
  `admin:`/`shell:` token ⇒ `foothold`; hypotheses exist ⇒ `recon`; else `unauth`. A flag enters
  `objective.flag` **only** when the `flag-capture` oracle is met (format match + bytes re-derivable from
  `raw/`) — never a narrated, guessed, or remembered value. In `impact` mode (default) `objective` is
  absent and this bullet is a no-op. A `loot`/`internal-recon` hypothesis (P4) that retrieves the
  objective artifact writes it as `execution_evidence`; the P1 objective oracle validates it against
  `flag_format`/`goal` and sets `objective.status:captured` (terminal in flag mode).
- **Carry the classification (P2).** When a router plan exists, copy the committed
  `classification{mode, confidence, signals, ts}` from `run.json` into `state.json.classification` so
  re-runs and the final doc know the engagement mode. Hypotheses may optionally carry an additive
  `"mode"` tag for grouping only — no scheduler behavior depends on it (F4 still runs off
  `requires`/`provides`). Absent a router, this is a no-op.

## Senior corpus (fix3-corpus; ALL modes; single-writer)
These fire in **every** mode (the corpus makes the fleet sharper regardless of objective). They are
additive and never touch `severity` or the oracle.
- **Write `state.json.fingerprints[]`** — the retrieval keys. From the recon tech detection you already
  record (stack/framework/version/headers/cloud/edge), emit per-host tech tokens:
  `[{host, tokens:["framework:<x>","version:<y>","header:<z>","cloud:<p>","param:<q>","response:<shape>"]}]`
  (lower-cased; only what the evidence shows). `tools/retrieve.py` keys `class × these tokens`, so richer
  fingerprints = sharper priming — and because `state.json` persists, they **accumulate across runs**.
- **Write `state.json.tried[]`** (Tier-1 negative memory) — a compressed per-target already-tried-and-failed
  facts list `[{class, host, what, signal}]` so a re-run never loops on a dead command (this is distinct from
  `brain/corpus/negative.jsonl`, the cross-engagement store).
- **You do NOT write `brain/corpus/`** — that is the **corpus-curator's** sole job (single-writer, same
  invariant as you hold over `state.json`/`findings.jsonl`). You only produce the Tier-1 inputs it promotes:
  `techniques[]` (what worked, oracle-proven), `dead_paths[]` (what died), `fingerprints[]`, and the attack
  return's `used_exemplars[]`/`per_hypothesis`. The curator runs after you and reconciles them UP into the
  corpus. A technique is promoted only if the oracle was met this run — a remembered technique is never a claim.

## Bounty mode — the economic annotation pass (fix3; single-writer; no-op in impact/flag)
All of the bullets below fire **only** when `scope.objective.mode === 'bounty'` (and the economic ones
need `scope.program{}` present). In `impact` (default) or `flag` mode each is a **no-op**: no economic
field is written and `findings.jsonl` / `state.json` are byte-identical to today. You remain the **only**
writer of `findings.jsonl` and `state.json.objective` — these add annotations, never a second writer,
never a second verifier. Each field has exactly ONE owner (the canonical field contract in
`brain/schema.md`); never invent a clashing name. **Severity is untouched by economics** — the CVSS
recalibration + evidence gate above stay the only severity authority; eligibility/novelty/tier order and
gate submittability, they never change a finding's `severity`. Doctrine lives in `brain/bounty.md` (B1),
`brain/vrt.md` (B4), `brain/outcomes.md` (B6).
- **Annotate eligibility / VRT (B4).** For each finding resolve its free-form `class` onto a VRT id from
  `brain/vrt.md` and write additive `vrt` (dotted id) + `priority` (`P1..P5|varies` — the VRT **class
  baseline**, distinct from `severity` and from B5 `tier`). Set `eligibility`
  (`payable|excluded|control-test-only|unknown`) by matching `program.exclusions`/`excluded_classes`/
  `eligible_classes` (lower-cased substring, first-match-wins, same discipline as attack `CLASS_ALIASES`)
  and record `eligibility_reason`. An `excluded` finding is **annotated, never dropped** — it still lands
  in `findings.jsonl` and surfaces in the `/report` "Noted, not submitted" appendix. Eligibility is a
  payout-policy tag; it **never** changes `severity` or scope.
- **Grade severity → tier → EV (B5).** For each confirmed finding build the CVSS 3.1 `cvss_vector` from
  the **proven** impact — anchor it to `brain/vrt.md`'s baseline vector for the class (B4), then adjust
  each metric up/down by the evidence (the existing "recalibrate, both directions" discipline, now
  emitting the vector, not just the band). Run `python tools/ev-score.py --vector <v> --reward-table
  <program.reward_table> --dedup <novelty> --eligibility <eligibility>` to get `cvss_score`, `tier`,
  `tier_reward`, `expected_value`, and `ev_basis` **deterministically — do not hand-wave them**. Rank
  `findings.jsonl` and set `state.objective.ev_ranked` / `expected_value_total` by EV. **Evidence-bound:**
  the vector comes from proven impact; **never inflate a metric to raise the tier**; a finding below
  `objective.min_payable_tier` is `expected_value:0`, not bumped; `could-not-verify` novelty applies the
  EV discount, never a promotion. If the evidence-CVSS band deviates **>1 level** from the VRT baseline
  `priority`, add the finding to `human_review` (drift guardrail).
- **Tag novelty from prior art (B3).** When `targets/<t>/priorart.json` exists, match each
  hypothesis/finding by **root cause** (CWE + component + sink + authz-context — the Intigriti "same-fix"
  test, not host+endpoint) and write additive `novelty` (`novel|likely-duplicate|could-not-verify`),
  `novelty_ref` (the matching disclosed ref, if any), `novelty_reason`, `dedup_coverage`,
  `dedup_checked_ts`. **Default honest:** if `priorart.coverage==='unverifiable'` OR no confident match
  ⇒ `could-not-verify` (**never** auto-`novel`, **never** silently `likely-duplicate`); only an explicit
  root-cause match with a `ref` ⇒ `likely-duplicate`; a surface the index positively does not cover (and
  coverage is `verified`/`partial`) ⇒ `novel`. A disclosed-but-**fixed** item is a VARIANT/REGRESSION
  seed, not only a filter. Novelty is **orthogonal to severity** — it orders work and gates
  submittability, never grades. Set `state.objective.dedup_cleared` and mirror `priorart{coverage,ts}`
  into `state.json`.
- **Compute the payout gate (B2).** For each finding compute `payout_ready` (bool) + `payout_blockers`
  (string[]) + `payout_distance` (the 8-rung ladder `signal → reproduced → impact-proven →
  severity-graded → dedup-cleared → report-ready → submitted → paid`) as the deterministic AND of the
  six sub-gates — **impact-proven** (oracle, existing) ∧ **in-scope/ROE** (existing scope) ∧ **eligible**
  (B4) ∧ **paying-tier** (B5 `tier` at/above `objective.min_payable_tier`) ∧ **dedup-cleared** (B3) ∧
  **report-ready** (ISO-29147 elements present). Run `python tools/payout-gate.py` over the finding to
  get the machine-checkable verdict; **do not narrate it**. `payout_ready ⟺ payout_blockers.length===0 ⟺
  the ladder reached report-ready`. `could-not-verify` dedup is a **blocker**, never promoted to cleared
  (unless `objective.novelty.waive_unverified` on operator waiver). A missing CVSS vector or a tier below
  the pay floor is a structured blocker, never an assumed/inflated tier.
- **Merge the bounty objective (B1).** Roll the findings up into `state.json.objective` (bounty mode;
  still single-writer): `payable_count`, `best_tier`, `best_finding`, summed `expected_value` (honest
  range; `unknown:true` if any payable tier lacks a reward_table entry) + `expected_value_total`,
  `ev_ranked`, `eligible_pending` (eligible ∧ could-not-verify awaiting the operator), `dedup_cleared`,
  and `status`/`distance`. `status`: `payable` if `payable_count>0` (a recorded MILESTONE — the run KEEPS
  hunting, NOT terminal); `blocked` if stalled on a foothold/prereq no hypothesis can provide; `dry` when
  the eligible-novel surface is exhausted (the economic-exhaustion terminal); else `open`. `submitted`/
  `paid`/`rejected` come from the outcome fold (B6). The run-level `distance` is a coarse read-only
  projection of the best finding's B2 rung. `captured` stays flag-mode-only.
- **Fold recorded outcomes (B6).** When `targets/<t>/submitted/*.json` records exist, read them. A
  `resolved`/`paid`/`accepted`/`triaged` record → append/merge a `techniques[]` entry `{class,
  what_worked, on:<host>, outcome, program, amount, ts}`; a `duplicate`/`not-applicable`/`informative`/
  `spam` record → append a `dead_paths[]` entry `{id, goal, class, why:<outcome reason>, outcome,
  program, ref, ts}` (a `duplicate` also feeds `priorart.json` via its `dup_ref` — B3). Recompute
  `state.objective.outcomes_summary` + the per-`(program,class)` `acceptance_prior` (the HackerOne-Signal
  weighting `(-5·N/A + 0·Informative + 7·Resolved)/(N/A+Informative+Resolved)`; duplicates excluded from
  the ratio but kept for dedup; **`unknown` at n=0 — never fabricated**) and set `state.objective.status`
  (`paid` if any recorded paid; `rejected` if all submitted findings closed non-paying; `submitted` if
  any still pending). Append the per-program ledger line to `.claude/skills/context/<program>/
  outcomes.jsonl`, **and regenerate `.claude/skills/context/<program>/SKILL.md`** — a short digest from
  that ledger (paid classes, dup-heavy classes, informative/N-A classes, realized pay band per class, the
  `acceptance_prior`) — because a mission can only LOAD a `SKILL.md` context pack, not the raw `.jsonl`
  (fix3 audit #5). This is what carries CROSS-PROGRAM memory to the NEXT engagement on the same program
  (missions inject the `<program>/` pack too — `brain/mission.md`); same-target `/again` already compounds
  via `prior_state`. The outcome RECORD is **operator-attested** (written by `/outcome`, not here); you only
  PROJECT it into `state.json` + the ledger + the digest — the single-writer invariant on
  `state.json`/`findings.jsonl` is unchanged. Learning reaches the next run through `prior_state` + the
  `<target>` and `<program>` context packs (no workflow edit).

## Voice
Human, dense, honest. No filler. If a phase found little, say so and say why (egress blocked,
WAF, genuinely clean) with the log evidence. Every claim in the document must trace to a file
under `raw/`. Rank by real risk, not by how exciting it sounds.
