# The /spider cycle

Spider is the **brain**; each phase is delegated to a **fleet** running a workflow script. After
every phase a fresh **synthesizer** reads the target folder and writes a document. The operator
gates each transition with a GO.

```
/spider <target>
        │
        ▼
┌─ 1. SCOPE & WORKSPACE ─────────────────────────────┐
│  create targets/<t>/, write scope.yaml + leash.env │  brain (no fleet)
│  probe reachability (in-scope, through the leash)   │
│  CHECK EGRESS: probe.py --egress <t> (route/VPN/OOB)│  conflict => no GO
└────────────────────────────────────────────────────┘
        │
        ▼
┌─ 1.5 CLASSIFY & PROPOSE PLAN ──────────────────────┐
│  workflows/classify.mjs (NO packets: scope + the    │  brain (one agent)
│  one liveness fact + local artifact file-types)     │
│  → classification + chosen_modes + proposed_phases  │
│  + PROPOSE objective mode: bounty (default for a     │
│    reachable web/api bug-bounty) | flag | impact    │
└────────────────────────────────────────────────────┘
        │
        ▼   ◄── GO #1: operator picks FLEET (5/10/15) + MODEL TIER (fast/strong),
        │           approves the PROPOSED PLAN + the egress verdict → run.json
┌─ 2. RECON-1 (broad) ──────────┐        ┌─ 3. SYNTHESIS #1 ──────────────┐
│  workflows/recon-1.mjs        │  ────► │  synthesizer (clean context)   │
│  fleet fans out across OSINT  │        │  → docs/01-recon-surface.md    │
│  modalities → raw/<agent>/    │        │  → merge state.json            │
└───────────────────────────────┘        └────────────────────────────────┘
        │
        ▼   ◄── GO #2
┌─ 4. RECON-2 (deep) ───────────┐        ┌─ SYNTHESIS #2 ─────────────────┐
│  workflows/recon-2.mjs        │  ────► │  → docs/02-infra-hypotheses.md │
│  seeded w/ state.json;        │        │    (infra map + ranked         │
│  params, anomalies, probes    │        │     hypotheses to prove)       │
│  → HYPOTHESES                 │        └────────────────────────────────┘
└───────────────────────────────┘
        │
        ▼   ◄── GO #3
┌─ 5. ATTACK (proven impact) ───────────────────────┐   ┌─ 6. SYNTHESIS (final) ──────┐
│  workflows/attack.mjs (repeatable)                │──►│  → killchain.md             │
│  pipeline per hypothesis:                         │   │  → docs/99-infra-final.md   │
│    exploit → PoC (+interactsh OOB)                │   │  → findings.jsonl (gated)   │
│    → adversarial verify (3 lenses, refuted=true)  │   └─────────────────────────────┘
│  only PROVEN impact survives                      │        │
└───────────────────────────────────────────────────┘        │  "again" → relaunch attack
        │                                                     │  seeded with updated state
        ▼
┌─ 7. STOP ─ operator chooses ──────────────────────────────────────────┐
│  /report <t>   → submission-ready human report (verified findings only)│
│  /triage <t>   → hostile skeptic fleet: SUBMIT / FIX / DROP per finding │
│  /outcome <t>  → (bounty) record the operator-attested submission      │
│                  outcome; Spider learns what pays. NEVER auto-submits.  │
│  /again <t>    → full re-run seeded with all prior context             │
└────────────────────────────────────────────────────────────────────────┘
```

**Novelty pulled UPSTREAM (bounty mode — fix3 B3).** In `mode:bounty`, after Synthesis #1 (the stack is
known) and **before GO #3**, the brain builds the prior-art index ONCE: `duplicate-scout` in prior-art
mode → `targets/<t>/priorart.json`, from the program disclosure history (Hacktivity / the operator's
`submitted/` archive / the context pack) + the stack's CVEs (NVD) + component advisories (GHSA) + the
changelog, each indexed by **root cause** (the Intigriti "same-fix" test). This is **passive OSINT** — it
touches no target, needs no leash. The index seeds BOTH recon-2 (the fleet hunts the NOVEL surface first,
not $0 duplicates) and the gates. Honest: `coverage:unverifiable` (private, no archive) ⇒ every verdict
`could-not-verify`, **never** `novel`; a disclosed-but-**fixed** item is a REGRESSION seed, not only a
filter. Absent bounty mode / disclosure sources, nothing builds it and recon-2 is byte-identical to today.

**Attack is STAGED — foothold-first (F4).** recon-2 emits a dependency graph, not a flat list: each
hypothesis carries `requires`/`provides` capability tokens (`session:<host>`, `creds:<p>@<host>`, …;
grammar in `brain/schema.md`). `attack.mjs` runs a **wave scheduler**: foothold producers (login /
auth-bypass / otp-logic / SSH-or-service default-cred control-test) prove FIRST, and a dependent (e.g. a
BOLA that `requires:["session:<host>"]`) fires only once that token is **oracle-proven** — never as a
dead PoC. Un-footholded dependents are reported `blocked_on_prereq`, and the unmet tokens as `stalled_on`;
a red-line-blocked attempt returns `blocked` (never a silent "lead") and routes to `human_review`.
Once a foothold grants `shell:<host>`, the **post-foothold stage** (internal-recon → privesc → loot →
bounded in-scope lateral) fires in a later wave (zero scheduler change — the same `requires`/`provides`
graph). Enumeration is read-only and its output is analysed **locally**; only command delivery/exec rides
the leashed foothold channel (`tools/leash-foothold.sh`, host-pinned, non-destructive). Privesc is **ONE
oracle-proven step**, never a sweep or an implant; **persistence is never performed**; lateral pivots only
to in-scope hosts.

**When the only blocker is foothold:** `/spider resume-with-session <t>` — the operator supplies an
authorized session (`targets/<t>/session.env`, injected by the leash, never cracked by the fleet); the
scheduler seeds its acquired set from it and the waiting PoCs fire. Non-HTTP foothold (SSH/FTP/…) runs as
a bounded, policy-gated default-cred CONTROL-TEST through `tools/leash-cred.sh` (spray-not-brute, capped,
lockout-aware) — enabled only via `policies.default_cred_control_test`. A stateful or pwn service (nc /
custom line-or-binary protocol / WebSocket) is exploited over a **HELD, audited socket** via
`tools/leash-sock.py` (gated by `policies.interactive_protocol`, frame/byte/session-time-capped,
host-pinned); a proven conversation yields `session:`/`foothold:` into the graph, and the full transcript
under `raw/` is the oracle evidence.

**Invariants:** one GO before the first live packet (`resume-with-session` is itself that GO); fleet +
tier fixed at GO #1; every HTTP request through the leash (header + off-scope 403 + rate cap + audit, and
the operator session injected only AFTER the scope-lock); non-HTTP tools host-pinned by the guard; a claim
without a file under `raw/` is a lead; high/critical without `execution_evidence` is a candidate, not a
finding; a capability enters the graph only when oracle-proven or operator-supplied; a `[cyber]` safeguard
block is a hand-off, never worked around. **Target reachable before GO is a HARD preflight gate** —
`arsenal/probe.py --egress <target>` emits `egress_ok | warn | conflict` (default route + full-tunnel-VPN
ownership + OOB-proxy port + one in-scope liveness connect); a `conflict` (e.g. a WireGuard `/0`
kill-switch owning the route) blocks GO. That connect **is** the step-1 liveness probe, not new traffic.
**The classifier sends no packets** (scope + the one liveness fact only); a web target defaults to the
full standard flow; new modes are opt-in and operator-approved at GO. **In `flag` mode a captured flag**
(format match + re-derivable from `raw/`) is a **TERMINAL** state — the run ends cleanly and routes to
`/report`; the default `impact` mode is unchanged and iterates to dry.

**Senior priming (fix3-corpus, all modes).** Between Synthesis #2 and attack the brain retrieves distilled
senior exemplars from `brain/corpus/` (`tools/retrieve.py`, keyed `class × state.json.fingerprints`,
localhost/zero-traffic) and injects them as `args.exemplars`/`args.negatives` — a HINT upstream of the
oracle, **never cited as proof** (the oracle always re-derives; `patched-instance` records never prime).
After the final synthesis the **corpus-curator** promotes this run's oracle-proven techniques + reusable
dead-ends back into `brain/corpus/` (single-writer), so each engagement leaves the next one stronger and a
fresh clone inherits the grown corpus. Distillation of external reports is **offline, outside the GO-gated
cycle** (`workflows/distill.mjs`). Absent the corpus/args, every mission is byte-identical to today.

**In `mode:bounty` (fix3) the win is a PAYABLE finding** — impact-proven ∧ in-scope ∧ eligible (B4) ∧
paying-tier via a CVSS vector (B5) ∧ dedup-cleared (B3) ∧ report-ready — the six-term `payout_ready` gate
(B2), the economic analogue of the flag oracle, enforced at `/triage` (a `payout_ready:false` finding
cannot be ruled SUBMIT). A payable finding is a recorded **MILESTONE, not terminal**; the run is **dry**
(terminal) when the eligible-novel surface is exhausted. The per-finding 8-rung ladder (`signal → reproduced
→ impact-proven → severity-graded → dedup-cleared → report-ready → submitted → paid`) is the brain's
steering signal: dup-heavy ⇒ pivot to the novel surface; low-tier-only ⇒ chain up (proven impact, never
inflation); stalled ⇒ the F1/F2 hand-off; payable ⇒ milestone, keep hunting to dry. **Eligibility is a
payout policy, never a scope change** (an excluded class is a noted lead, never dropped, never attacked out
of scope). **Honest dedup** (`could-not-verify` ≠ novel; novelty never touches severity). **Severity is
evidence-bound** (tier from proven impact, never inflated to clear a pay floor). The loop closes with
`/outcome`: the operator submits externally and attests the result; **Spider records, never auto-submits**,
folds it into `techniques`/`dead_paths` + the per-program ledger, reaches `submitted`/`paid`/`rejected`,
and seeds the next run through `prior_state` + the context pack. Absent `objective`/`program`, every bounty
path is empty and the run is byte-identical to today's `impact` default.
