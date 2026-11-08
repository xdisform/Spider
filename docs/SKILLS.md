# Skills — methodology, and how to add it

## What a skill is (and isn't)

A skill is a **methodology playbook** in Markdown — knowledge, not code. It tells an agent *how* to
approach a job (which techniques, in what order, what counts as proof) and *which arsenal tools* to
use. The agent still runs the tools itself from `bin/`. Skills live in `.claude/skills/`:

```
.claude/skills/
  index.json              # router: name/category/class/tags/cwe → path (generated)
  recon/<name>/SKILL.md    # OSINT/recon playbooks (one per modality/lens)
  attack/<class>/SKILL.md  # per-vuln-class exploitation playbooks
  proof/<name>/SKILL.md    # what counts as proven impact (poc-standard, oob-interactsh)
  triage/<name>/SKILL.md   # (optional) skeptic axes for triage
```

There are 30 skills today: 16 recon, 12 attack, 2 proof. See `docs/TOOL-MAP.md` for which skill
serves which workflow.

## How a skill reaches a workflow agent

Workflow scripts are pure JS and **cannot read files** — so skills reach agents by path:

1. The workflow builds each agent's mission with the skill path(s) for that agent's surface, e.g.
   `.claude/skills/recon/subdomain-enum/SKILL.md` (recon-1 by modality) or
   `.claude/skills/attack/<class>/SKILL.md` (attack, by the hypothesis's class).
2. The agent (which *can* Read) opens the skill and follows it.

Missing skills **degrade gracefully**: the workflow also embeds the modality/class jobs inline in
the mission, so an agent still works without a matching `SKILL.md` — the skill just makes it sharper.

The **agent role files** (`.claude/agents/*.md`) carry the cross-cutting rules (scope routing via
the leash, proof standard); the **skill** carries the technique for one surface. Both are read by
the subagent.

## SKILL.md format

YAML frontmatter, then a tight playbook (~40–60 lines). Copy an existing one as a template
(`.claude/skills/attack/ssrf/SKILL.md`, `.claude/skills/recon/subdomain-enum/SKILL.md`).

```markdown
---
name: attack-xxe                 # attack skills: attack-<class>; recon: the modality key
description: one line
category: web-application         # web-application | recon | proof
tags: [xxe, injection, xml]
cwe_ids: [CWE-611]                # attack skills
chains_with: [attack-ssrf]        # optional: other skills this pairs with
tools: [curl, nuclei, interactsh-client]   # a subset of the real bin/ arsenal
version: "1.0"
---

# Title
## Objective            # 1–2 sentences: what to prove/gather
## Methodology          # numbered phases with REAL commands using bin/ tools by name
## What counts as a finding   # attack: severity tied to PROVEN impact (see proof/poc-standard)
## Evidence             # what to save under raw/<label>/
```

Rules that keep skills honest:
- Reference **only tools that exist in the arsenal** (`arsenal/manifest.json`).
- Target-facing commands go through the leash: `tools/leashed.sh <target_dir> bin/<tool> …`;
  passive OSINT runs direct; non-HTTP tools use `tools/guard.py` (see `docs/ARCHITECTURE.md`).
- Severity is set by **proven** impact only — an impact/injection class claimed high/critical without
  `execution_evidence` is a `[UNCONFIRMED CANDIDATE]` (see `.claude/skills/proof/poc-standard`).

## Add a skill

1. Create `.claude/skills/<category>/<name>/SKILL.md` with the frontmatter above.
2. Regenerate the router:
   ```bash
   python tools/skill_index.py     # rebuilds .claude/skills/index.json from all frontmatter
   ```
3. If it's a new **attack class**, name the folder exactly the `class` string the `recon-2`
   hypotheses will emit (lowercased), so `attack.mjs` finds it at `attack/<class>/SKILL.md`.
   If it's a new **recon modality/lens**, add the modality to the relevant workflow's list
   (`workflows/recon-1.mjs` `MODALITIES` or `workflows/recon-2.mjs` `LENSES`) so an agent is assigned to it.

## Skills vs. the optional MCP tool-server

Skills are *ours* — authored methodology, kept license-clean. They are separate from any external
MCP tool-server, which provides *executable tools* (reached via `ToolSearch`), not methodology. A
skill can tell an agent to use an MCP tool if one is connected, but it should always work with the
`bin/` arsenal alone.
