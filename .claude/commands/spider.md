---
description: Run the Spider cycle on a target — scope, GO, recon, deep recon, attack-to-proven-impact, synthesize. You orchestrate; the fleet hunts.
argument-hint: <target or scope>
---

Run Spider for: **$ARGUMENTS**

Read `brain/spider.md`, `brain/scope.md`, `brain/schema.md`, `brain/mission.md`, and
`brain/synthesis.md`, and follow them exactly. **You are the tech-lead: you orchestrate, you do
not hunt, and you never pick a tool for an agent.** Each phase is delegated to a fleet of workflow
agents; you build the mission, launch the workflow, and synthesize with a clean context.

1. **Scope & workspace.** Create/confirm `targets/<target>/` per `brain/schema.md`. Write
   `scope.yaml` (authorization + exact in-scope list + rules); generate `leash.env` from it.
   One in-scope liveness probe through the leash — is the target reachable?
2. **Preflight.** `python arsenal/probe.py --json`; provision if needed. Bring the leash up and
   confirm header-inject + off-scope-403. Report ready / missing honestly. (Localhost only.)
   Run the egress gate `python arsenal/probe.py --egress <target>:<port>` — a `conflict` blocks GO.
2.5. **Classify & propose plan.** Launch `workflows/classify.mjs` (no target traffic — it reasons over
   `scope.yaml` + the one liveness/egress fact + local `artifacts/` file-types) and read
   `brain/modes.md`. Get `{classification, chosen_modes, proposed_phases}`. A web-reachable target ⇒ the
   full standard web flow; low confidence / error ⇒ fail-open to `['web','network']`. This is the
   self-distributing router: it *proposes* how to spend the fleet; the operator approves at GO.
3. **Scope GO.** Show target, scope, ready arsenal, the **egress verdict**, and the **proposed plan**.
   Ask the operator to pick **fleet (5/10/15)** and **model tier (fast/strong)**, then GO. Approving GO
   also approves the plan (`go.plan`); the operator may override `chosen_modes` or pin
   `engagement.type`. Write fleet/tier/plan/egress to `run.json`. Nothing hits the target before GO.
4. **Recon-1.** Build the `args` (per `brain/mission.md`) and launch
   `Workflow({scriptPath:"workflows/recon-1.mjs", args})`. When it returns, spawn the
   **synthesizer** → `docs/01-recon-surface.md` + merge `state.json`. Present tight. Ask GO.
5. **Recon-2.** Launch `workflows/recon-2.mjs` seeded with `state.json`. Synthesize →
   `docs/02-infra-hypotheses.md`. Present the infra map + ranked hypotheses. Ask GO.
6. **Attack.** First **retrieve senior exemplars** — for each hypothesis run `python tools/retrieve.py
   --class <class> --fingerprint <state.json.fingerprints for host> --k 5` and assemble the non-secret
   `args.exemplars`/`args.negatives` (+ `args.reflex_cards` for a recon-2 re-run); see **Senior priming**
   in `brain/spider.md` (localhost, zero target traffic; absent corpus ⇒ pass nothing). Launch
   `workflows/attack.mjs` seeded with the hypotheses **and** `args.exemplars`. It exploits and
   **adversarially verifies** every claim (proven impact only; the exemplar is a hint, never cited as
   proof). Synthesize → `killchain.md` + `docs/99-infra-final.md`, then spawn the **corpus-curator**
   (`.claude/agents/corpus-curator.md`) to promote this run's oracle-proven techniques + dead-ends into
   `brain/corpus/` (the cross-session growth loop). If leads remain and the operator says "again",
   relaunch attack seeded with the updated state; repeat until proven or dry.
7. **Stop.** Present proven findings, open hypotheses, the chain, where it's stuck. Offer
   `/report <target>`, `/triage <target>`, or `/again <target>`.

The fleet size and model tier chosen at the scope GO are passed into every workflow and fixed for
the run. Between phases you pause for the operator's GO. Report per-agent status honestly — a dead
agent is never "nothing found". Never touch anything outside `scope.yaml`.
