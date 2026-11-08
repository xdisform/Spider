---
description: Classify an engagement and print the proposed mode + cycle/lens plan — read-only, no target traffic. A dry-run of the router before you commit to a run.
argument-hint: <target or scope>
---

Dry-run the Spider **mode router** for: **$ARGUMENTS**

Run ONLY the classifier and show its proposed plan. **This touches only localhost — plus, when a target
is given, the single in-scope liveness connect `/spider` step 1 already performs.** It never launches
recon, never asks for GO, and widens nothing. Mirrors `/doctor`: a preflight-only sanity check so an
operator can see how the router reads a new scope **before** committing the fleet.

1. **Locate the engagement.** Resolve `targets/<target>/` (or the scope file passed). If no `scope.yaml`
   exists yet, say so and stop — the router reasons over scope, and there is nothing to classify.
2. **Preflight facts (no new traffic).** Use the facts already on hand: `scope.yaml`, the one
   liveness/egress fact (`python arsenal/probe.py --egress <host>:<port>` if a target is reachable — the
   same sanctioned step-1 connect, no extra packets), and the `file`-type of any local artifact under
   `targets/<target>/artifacts/` (`file <artifact>` — LOCAL only, never against a URL).
3. **Classify.** Read `brain/modes.md` (the registry) and launch
   `Workflow({scriptPath:"workflows/classify.mjs", args})` with `args.scope` (the parsed `scope.yaml`),
   `args.preflight` (the liveness/egress `reach_detail`), `args.target`/`args.target_dir`,
   `args.skills_dir`, and `args.model_tier`. The classifier sends **no packets**.
4. **Print the plan.** Show the returned `{classification{mode,confidence,signals}, chosen_modes,
   proposed_phases, proposed_ideas}` plainly: the committed mode + why (the signals), the fine
   `chosen_modes` that would drive `args.modes`, and the ordered cycle plan. Note explicitly when a
   web-reachable target defaults to the full standard flow, or when a low-confidence/empty result
   fail-opens to `['web','network']`. Also print the proposed **objective mode** (`impact | flag |
   bounty`) with its reason (the additive `proposed_objective{mode,why}`, fix3 B7) — so the operator sees
   the recommended `bounty` default for a reachable web/api bug-bounty target before GO. It is a
   recommendation only (orthogonal to `chosen_modes`); it sets no mode, relaxes no policy, grants no
   capability.
5. **Stop — do NOT run.** This is a dry-run: do not write `run.json`, do not GO, do not launch any recon
   or attack cycle. If the plan looks right, point the operator at `/spider <target>` to run it for real
   (where the same classification is shown at GO #1 and approved with `go.plan`).

Nothing here hits a target beyond the one sanctioned liveness connect, and nothing is committed. A mode
is a lens/cycle selection, never a capability — this command only *reads and proposes*.
