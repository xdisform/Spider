# Attack-phase evolution — the hypothesis lifecycle, the agent roster, and the roadmap

This is the design material for making Spider's **attack phase** (and the `/chain` re-attack) hunt like a
senior team, not a scanner. It is grounded in a 2025–2026 scan of autonomous-pentest research and
open-source frameworks (see **Research basis**), mapped onto what Spider already has, with the gaps it is
closing and the backlog ranked by impact.

The organising idea the whole field converged on: **the LLM explores creatively; deterministic code
verifies and maintains state** (XBOW), and **an explicit reflect-on-failure step roughly doubles success**
(Red-MIRROR 33%→66%; RefPentester vuln-ID 87.5% vs 35.7% baseline). Architecture beats model choice (CAI:
same base model, up to 2.6× from design alone). Spider was already strong on verification and state; its
missing piece was the reflect loop. That is now in.

## 1. The hypothesis lifecycle (the state machine)

A hypothesis is a unit of belief that travels a fixed set of states. The transitions are **code-forced**
(in `workflows/attack.mjs`), not left to a model to remember — the lesson of arXiv 2509.07939 (LLM-kept
task trees need constant regen; keep the tree in code).

```
recon lead ──► scheduled ──► attempted ──► [oracle + 3 skeptics] ──► confirmed
   (recon-2)     (F4 wave        (operator,          │                   (survives)
   emits a       scheduler:      up to trajN          ├─► refuted  (oracle/skeptic veto)
   ranked        requires/       diverse              ├─► blocked  (safeguard / policy / needs-session — a HAND-OFF)
   hypothesis    provides        trajectories)        └─► not_reproduced ─► REFLECT ─► sharpened retry ─► [oracle] ─► confirmed
   w/ seam)      graph)                                                     (Advisor)                                  │
                                                                                                                       └─► lead (exhausted)
```

- **scheduled → attempted**: the **foothold-first wave scheduler** fires a hypothesis only when every token
  in its `requires` is already in `acquired` (operator session + capabilities proven earlier). A confirmed
  finding's `provides` (plus `derivedCaps`: a proven RCE mints `shell:`, ATO mints `session:`, a leak mints
  `creds:`) unlocks the next wave — the web→infra bridge.
- **attempted**: the operator runs up to `trajN` **heterogeneous trajectories** in parallel (baseline +
  tool-first / manual-first / cve-seeded / chain-first / auth-depth); the strongest candidate feeds the gate.
- **the gate** (unchanged, load-bearing): a deterministic **oracle** re-executes the PoC, alongside 4
  adversarial **skeptic** lenses (reproduce / impact / scope-policy / origin-check hard-veto). No oracle,
  no finding. The impact lens now also rejects **deceptive evidence** (ATOBench: echoed payloads, honeypot
  200s, fabricated success).
- **not_reproduced → REFLECT** (new): instead of dropping to a lead, the **Advisor** derives the failure
  reason from the attempt artifacts and either sharpens one retry (through the same gate) or calls it
  exhausted. This is the Execute→Reflect→re-Execute loop the field shows doubles success.
- **confirmed → CHAIN**: the **chain-builder** combines confirmed+candidate+lead into kill chains and
  proposes composite hypotheses; a bounded **rechain** loop proves `medium+medium → critical` in-script.

Orthogonal carriers that ride a hypothesis: **`seam`** (recon already proved the structural primitive —
desync variant, unkeyed cache input, source→sink chain, stack-CVE — so attack weaponizes instead of
re-detecting), **`exemplars`/`negatives`** (senior priming from the corpus), **`requires`/`provides`**
(the dependency grammar), and the bounty economics (`eligibility`/`projected_ev`).

## 2. The agent roster (what each does, and how)

The orchestrator (`/spider`) spawns a **fleet of focused, clean-context agents**; each owns one slice and
returns structured data. Separation of concerns is deliberate — a creative attacker and a hostile verifier
must not be the same context.

| Agent (`.claude/agents/`) | Role | What it does | How |
|---|---|---|---|
| **attack-operator** | Exploiter | Drives ONE hypothesis to a reproducible PoC of real impact | Iterates Evidence→Hypothesis→Verification; runs the arsenal through the leash + the class/proof skills; honest `proven_state` |
| **advisor** *(new)* | Reflector | Reads a FAILED attempt, derives the failure reason, decides sharpen-or-exhausted | Clean context; reads `raw/attack-<id>/` + `recall.py`; never attacks; returns a sharpened angle or an honest "dead" |
| **validator** | Oracle | Deterministically RE-EXECUTES the PoC and emits class-oracle evidence | Veto power — no oracle, no finding; for client-side classes re-runs in the leashed Playwright MCP |
| **verifier-skeptic** | Adversary | Tries to REFUTE the claim from one axis (reproduce/impact/scope/origin) | Defaults to refuted; a claim survives only on evidence it can't break |
| **triage-scorer** *(new)* | Severity-truth triager | STAGE 3 of `/triage`: builds the CVSS vector from proven impact, scores it with the FIRST calculator (`tools/ev-score.py`), checks eligibility/dedup, runs the payout-gate | Veto power — inflated/ineligible/duplicate/below-floor never ships; the deterministic tools beat narration |
| **chain-builder** | Exploitation lead | Combines findings into kill chains + proposes composite hypotheses for the next round | Reads the world model; pushes cred-reuse/escalation composites when a foothold is held |
| **synthesizer** | Scribe | Merges the fleet's returns into `state.json` + the stage doc; populates `seam` from tool output | Clean reader; honest, evidence-traced; the single state writer per stage |
| **corpus-curator** | Librarian | Promotes oracle-proven techniques + reusable dead-ends into `brain/corpus/` | The single corpus writer; re-ranks exemplar hit-rate; never claims a finding |
| **duplicate-scout** | Economist | Flags likely-duplicate findings before a wasted report (bounty) | Root-cause match vs prior-art; a payout-policy annotation, never a scope change |

Supporting deterministic tools (code, not agents): the **leash** (scope/rate/header/fail-closed choke
point), the **wave scheduler** + **capability-token graph**, `recall.py` (in-run memory), `source-trace.py`
(source→sink skeleton), `retrieve.py`/`prime.py` (corpus priming), the **oracle** gate.

## 3. What was implemented this round

- **Reflect stage + the Advisor agent** — the missing Execute→Reflect→re-Execute loop. Every
  attempted-but-unproven lead gets one failure-reason→sharpened-retry pass through the unchanged oracle
  gate; bounded by `a.reflect_rounds` (default 1; 0 = off = byte-identical) and `a.reflect_max` (fan-out
  cap). It can only upgrade a lead to confirmed. Upgrades land before the chain stage, so the chain-builder
  sees the richer finding set. [`workflows/attack.mjs`, `.claude/agents/advisor.md`]
- **Evidence→Hypothesis→Verification discipline** baked into the attack-operator (read every response,
  sharpen from what it showed, mutate on a WAF block — don't blind-guess).
- **Anti-deception** in the impact skeptic lens (ATOBench): reject echoed payloads / honeypot 200s /
  fabricated success; demand an effect the target cannot fake.
- **Reflect in `chain.mjs`** (/chain + /again) and **`proof/waf-mutation`** (wafrift evolutionary bypass →
  re-prove the class oracle), injected into proofSkills for WAF-prone classes. (backlog #1 + #2, done.)
- **Per-hop validation** (`hops[]`/`hops_reached`, multi-step hypotheses — stops hallucinated end-to-end
  chains) + **iterative reflect rounds** + an **in-turn self-reflection checkpoint**. (backlog #3 + #4, done.)

## 4. Backlog (ranked by impact × effort)

1. ~~**Reflect in `chain.mjs` too**~~ — ✅ **DONE** (2026-11-02): the Advisor reflect loop is now in the
   standalone `/chain`/`/again` engine too (dead/unconfirmed targets get a failure-reason→sharpened-retry
   pass through the same oracle+scope gate; same `reflect_rounds`/`reflect_max` flags).
2. ~~**Payload-mutation feedback loop as a proof skill**~~ — ✅ **DONE** (2026-11-02): `proof/waf-mutation`
   wraps `bin/wafrift`'s evolutionary bypass (encoding/grammar/content-type mutation, detonation-guided,
   gene-bank) with the oracle discipline (the bypassing variant must still meet the CLASS oracle). Injected
   into `proofSkills` for WAF-prone classes (sqli/xss/ssti/rce/ssrf/xxe/ognl/waf-body-bypass) in attack+chain,
   and the Advisor points failures at it.
3. ~~**Per-hypothesis attack sub-tree**~~ — ✅ **DONE** (2026-11-02): a multi-step hypothesis (auto-detected
   by chain markers in how_to_prove, or `multi_step:true`) renders a **per-hop validation** block — prove
   each hop's own mini-oracle with its own evidence before the next; a later hop can't be claimed on an
   unproven earlier one (stops a hallucinated end-to-end chain). `hops[]`/`hops_reached` carry the structured
   tree as honest distance-to-impact. In attack + chain (seeded targets are always chains).
4. ~~**Advisor "after-N-consecutive-failures" trigger**~~ — ✅ **DONE** (2026-11-02): two parts — (a) the
   reflect stage now ITERATES up to `reflect_rounds` (a sharpened retry that still fails gets a fresh
   Advisor read next round; 'exhausted' retires a lead), and (b) an in-turn **self-reflection checkpoint**
   in the operator mission (after ~3 failed variants on the same sub-approach, stop, name why, pivot or
   declare dead — don't grind one wall). In attack + chain.
5. **Semantic recall (Mem0/embeddings)** to replace keyword `recall.py` — ranks prior attempts by meaning,
   not keyword overlap. *(larger; dependency)*
6. **CodeQL/Semgrep** behind `deep-source-trace` to replace the regex/proximity tracer with real AST taint.
   *(larger; cross-OS build)*

## Research basis (2025–2026)

HuggingFace was evaluated and **deliberately not adopted**: the 2026 HF landscape for offensive ML is a
supply-chain liability (31 malicious repos in the Oct-2026 campaign; `trust_remote_code` RCE CVEs
2026-4372 / 2026-80047), there is no strong public payload/PoC dataset worth the risk, and a hosted model
would break Spider's model-agnostic, local-first, leash-gated design. Keep the corpus local.

- Red-MIRROR — reflective verification + knowledge-augmented interaction (arXiv 2603.27127).
- RefPentester — knowledge-informed self-reflective PT, 7-state machine + Reflector reward (arXiv 2505.07089).
- "Staying on the Attack Path" — structured state for long-horizon PT (arXiv 2609.07344).
- "Guided Reasoning … Structured Attack Trees" — keep the tree in code, grounded in ATT&CK (arXiv 2509.07939).
- ATOBench — how agents verify when target evidence lies (arXiv 2608.12996).
- A Survey of LLM-Driven Penetration Testing (arXiv 2607.02605); LLM4Pentest curated list
  (github.com/simon-p-j-r/LLM4Pentest) — VulnBot (task-graph + Planner/Executor/Summarizer modules),
  CHYing (Advisor/Lead-Attacker split), AgentNote (structured working memory), XBOW (LLM explores / code
  verifies).
- WAF-A-MoLE (guided mutation fuzzer, confidence-priority queue) + `wafrift` (evolutionary bypass, gene-bank).
