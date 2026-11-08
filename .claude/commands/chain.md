---
description: Seeded exploitation — take ALL findings and actually exploit them into proven, oracle-validated critical chains. Working PoCs, not hypotheses.
argument-hint: <target>
---

Build and prove exploitation chains for: **$ARGUMENTS**

This is the "really get results" pass, modelled on how the strongest autonomous pentesters work
(validator-gated PoCs, seeded/variant hunting, heterogeneous trajectories, chaining via shared state).
Read `brain/spider.md`, `brain/schema.md`, and `.claude/skills/proof/oracles/SKILL.md`, then:

1. **Gather everything.** Read `targets/<target>/findings.jsonl`, `state.json` (world model + prior
   techniques + dead paths), `killchain.md`, and any `.claude/skills/context/<target>/SKILL.md`. Collect
   confirmed findings, candidates, and open leads — the solver builds exploitation ON TOP of all of them.
2. **Run the engine.** `Workflow({scriptPath:"workflows/chain.mjs", args})` with: target, target_dir,
   scope, authorization, fleet, model_tier, bin_dir, leash, skills_dir, the full `findings`
   {confirmed, candidates, leads}, `composite_hypotheses` (from the attack chain-builder), `context_pack`
   path if present, and `trajectories` (default 3). The engine:
   - a **planner** turns all findings into **seeded exploitation targets** (variant/seeded: each gets a
     starting point — a confirmed finding, a lead, or the known CVE/pattern for the detected stack);
   - **heterogeneous independent trajectories** (tool-first / manual-first / CVE-seeded / chain-first /
     auth-depth) actually exploit each — diverse solvers beat one loop;
   - a deterministic **validator** re-runs the best PoC and applies the **class oracle** (OOB callback /
     DB banner / command output / cross-account record / …). **No oracle, no finding.**
3. **Synthesize (clean context).** Spawn the `synthesizer`: fold oracle-confirmed findings into
   `findings.jsonl` (with `oracle_type`/`oracle_evidence`), update `killchain.md` with the proven chains,
   and **merge `state.json`** — record **successful techniques** (for reuse next run) and **dead paths**
   (so future runs don't re-tread them). Apply CVSS recalibration.
4. **Repeat or stop.** Newly confirmed links open new chains — relaunch `/chain` seeded with the updated
   state to push further, until the chains are proven or genuinely dry. Then present the proven chains
   and offer `/report` (submission) and `/triage`.

Only oracle-validated findings count. A dead path is recorded honestly, never reported. Everything stays
in scope, through the leash.
