# Spider docs — start here

Spider turns Claude Code into a pentest **tech-lead** that delegates each phase of an authorized
bug-bounty engagement to fleets of workflow agents, synthesizes a clean report after every phase,
gates on your GO, and drives findings to **proven impact — not hypotheses**.

> **Authorized testing only.** A `scope.yaml` transcribes the program — its in-scope list and rules —
> and the `researcher` attests authorization; that is the authorization grant (public **or private /
> invite-only** programs alike). Spider does not second-guess it or block on what the target is, will not
> run without a scope and an explicit GO, and never tests what the scope excludes. Bug-bounty programs,
> contracted engagements, CTFs, and labs you own.

## For a human cloning this repo

```bash
# 1. Install the arsenal (downloads tools into bin/ — nothing is committed)
export GITHUB_TOKEN=ghp_xxx          # avoids the GitHub API rate limit
python arsenal/provision.py          # ~28 tools; python arsenal/probe.py to check

# 2. Define an authorized scope
cp docs/scope.example.yaml targets/<target>/scope.yaml   # edit for your program

# 3. From Claude Code, in this repo:
#    /doctor            preflight (arsenal + leash)
#    /spider <target>   run the cycle (it pauses for your GO at each gate)
```

Requirements: Python 3.8+, Node, Git, curl. No WSL/Kali required (an optional heavy tool-server can
be attached — see `ARSENAL.md`). Everything is cross-platform (Windows/Linux/macOS).

## For a future Claude Code picking up this repo

Read these first, in order:
1. **`brain/spider.md`** — your role: tech-lead, delegate, never hunt, never pick a tool for an agent.
2. **`brain/schema.md`** — the one data contract (scope.yaml, state.json, findings.jsonl, docs/).
3. **`brain/scope.md`**, **`brain/mission.md`**, **`brain/synthesis.md`** — the GO gate, how to build
   a phase's `args`, how the clean synthesizer writes each doc.

Then this docs set:
| Doc | What it covers |
|---|---|
| [ARCHITECTURE.md](ARCHITECTURE.md) | how the pieces fit + the pure-JS data-flow constraint |
| [CYCLE.md](CYCLE.md) | the `/spider` phase diagram (GO gates, synthesis, repeatable attack) |
| [ARSENAL.md](ARSENAL.md) | where tools live (`bin/`), install channels, **how to add a tool** |
| [SKILLS.md](SKILLS.md) | what skills are, how they reach agents, **how to add a skill** |
| [WORKFLOWS.md](WORKFLOWS.md) | the per-stage fleets, the script API, **how to add/change a workflow** |
| [TOOL-MAP.md](TOOL-MAP.md) | which tool + skill serves which workflow |
| [mcp-integration.md](mcp-integration.md) | which MCP servers Spider adopts (and refuses), and how they route through the leash |

## The layers (where everything is)

```
.claude/commands/   /spider /chain /again /triage /report /doctor          (entry points)
.claude/agents/     recon-operator, attack-operator, verifier-skeptic, synthesizer  (roles)
.claude/skills/     methodology packs, routed by index.json           (how-to for agents)
brain/              the tech-lead doctrine + data contract            (the engine = prompts)
workflows/*.mjs     per-stage multi-agent fan-out scripts             (pure JS coordinators)
arsenal/            manifest.json + provision.py + probe.py           (self-provisioning tools)
tools/              leash.py, leashed.sh, guard.py, finding schema    (scope safety)
bin/                the downloaded arsenal (git-ignored)              (created by provision)
targets/<t>/        per-engagement workspace                          (scope, evidence, findings, docs)
```

## Extending Spider (the three knobs)

- **Add a tool** → one entry in `arsenal/manifest.json`, then `python arsenal/provision.py`. See `ARSENAL.md`.
- **Add a skill** → a `SKILL.md` under `.claude/skills/`, then `python tools/skill_index.py`. See `SKILLS.md`.
- **Add/adjust a phase** → a `workflows/*.mjs` script + a brain step + a synthesizer output. See `WORKFLOWS.md`.

## Safety model (non-negotiable)

One GO before the first live packet. Every target-facing HTTP request goes through the **leash**
(mandatory header, off-scope 403, rate cap, fail-closed, JSONL audit) via `tools/leashed.sh`;
non-HTTP tools are host/CIDR-pinned by `tools/guard.py`. A claim without a file under `raw/` is a
lead; high/critical without `execution_evidence` is a candidate, not a finding.
