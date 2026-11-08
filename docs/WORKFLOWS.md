# Workflows — the per-stage fleets, and how to extend them

Each phase of the cycle is a **workflow script** in `workflows/`. The brain (running `/spider`)
launches one with the Workflow tool; the script fans a fleet of agents out over the phase's work,
collects their structured results, and returns a summary. The brain then runs a clean **synthesizer**
over the target folder to write the phase document.

```
workflows/
  recon-1.mjs   broad OSINT sweep         → assets
  recon-2.mjs   deep recon, seeded        → hypotheses
  attack.mjs    exploit → PoC → verify    → confirmed findings   (repeatable)
  triage.mjs    hostile skeptics vs report → SUBMIT/FIX/DROP
```

## How the brain runs one

The brain builds an `args` object (see `brain/mission.md`) and calls:

```js
Workflow({ scriptPath: "workflows/recon-1.mjs", args: { target, target_dir, scope,
           authorization, fleet, model_tier, bin_dir, leash, skills_dir, /* … */ } })
```

`fleet` (5/10/15) and `model_tier` (fast/strong) are chosen by the operator at the scope GO and
passed into every phase. The workflow returns a compact summary (counts, per-agent status); the real
output is the evidence the agents wrote to `raw/<label>/`.

## The load-bearing constraint

A **workflow script is pure JavaScript with no filesystem and no network.** Data moves only through:
- **`args`** — everything the brain read from disk and passed in (scope, authorization, skill paths).
- **agent return values** — validated against a JSON `schema`.

Everything that touches disk or the network happens **inside an agent** (they have Bash/Read/Write):
agents read the scope, run `bin/` tools through the leash, and write evidence to `raw/<label>/`.
The script is a pure coordinator.

## The script API (what you can call)

- `agent(prompt, opts)` — spawn one subagent. `opts`: `label`, `phase`, `agentType`
  (`recon-operator` / `attack-operator` / `verifier-skeptic` / `synthesizer`), `schema` (forces
  structured JSON return), `model` (`'sonnet'`/`'opus'`). Returns the validated object, or `null` if it died.
- `parallel([() => agent(...), …])` — run tasks concurrently (a barrier: awaits all). Failed tasks → `null`.
- `pipeline(items, stage1, stage2, …)` — each item flows through all stages independently (no barrier
  between stages). Used in `attack.mjs`: exploit → verify per hypothesis.
- `phase(title)` / `log(msg)` — progress display.
- `args` — the object the brain passed. No `Date.now()`/`Math.random()` (they break resume).

The script **must** start with `export const meta = { name, description, phases }` (a pure literal).

## How agents get tools & skills inside a workflow

- **Tools** — the mission names `bin/` (agents call tools via Bash) and tells target-facing tools to
  go through `tools/leashed.sh <target_dir> bin/<tool>`. Any connected MCP tool-server is reachable
  via `ToolSearch`.
- **Skills** — the mission passes the skill path(s) for the agent's surface; the agent Reads them.
- **Role** — `agentType` selects the system prompt (`.claude/agents/<role>.md`) with the cross-cutting
  rules (scope, proof standard).

## Proven-impact enforcement (attack.mjs)

The attack workflow is where "not a hypothesis, a PoC" is enforced, in code:
1. **Exploit** (`attack-operator`) → a candidate with `proven` + `execution_evidence` + `poc_path`.
2. **Verify** — three `verifier-skeptic` agents from distinct lenses (reproduce / impact / scope-policy),
   each defaulting to `refuted=true`. A candidate survives only if ≥2 do not refute it; severity is
   re-graded to the lowest a surviving verifier justified.
Only survivors become confirmed findings; the synthesizer applies the schema evidence gate on top.

## Add or change a workflow

- **New phase** — copy an existing script, keep the `export const meta` literal, define your fan-out
  with `parallel`/`pipeline`, and return a compact summary. Wire the brain to call it (add a step in
  `.claude/commands/spider.md` / `brain/spider.md`), and add a synthesizer output in `brain/synthesis.md`.
- **Change breadth** — recon breadth is bounded by the modality/lens lists (`MODALITIES` in
  `recon-1.mjs`, `LENSES` in `recon-2.mjs`); add an entry (and its skill) to widen coverage. Attack
  breadth follows the hypotheses from recon-2.
- **Change verification rigor** — edit the `LENSES` / survivor threshold in `attack.mjs`.
- **Iterate fast** — every `Workflow` run saves its script under the session dir and prints the path;
  edit that file and re-invoke `Workflow({scriptPath, resumeFromRunId})` to replay unchanged agents
  from cache. For the shipped scripts, edit `workflows/*.mjs` directly.

## Validate a workflow script

They use top-level `await`/`return` (the runtime wraps the body in an async function), so plain
`node --check` rejects them. Validate by emulating the wrapper:

```bash
tmp=$(mktemp -d); f=workflows/attack.mjs
{ echo "async function __wf(args){"; sed 's/^export const meta/const meta/' "$f"; echo "}"; } > "$tmp/c.mjs"
node --check "$tmp/c.mjs" && echo OK; rm -rf "$tmp"
```
