# skills/

Methodology packs the workflow agents read for their surface. Each is a `SKILL.md` with YAML
frontmatter + a tight playbook. They are **knowledge, not executables** — they tell an agent *how*;
the agent runs the `bin/` arsenal itself.

Layout: `recon/`, `attack/`, `proof/`, `triage/`. `index.json` routes skills by class/tags so the
brain can pick the right ones per phase and pass their paths to the agents.

## Add a skill
1. Create `<category>/<name>/SKILL.md` with frontmatter:
   ```yaml
   ---
   name: attack-xxe
   description: one line
   category: web-application
   tags: [xxe, injection]
   cwe_ids: [CWE-611]
   chains_with: [attack-ssrf]
   tools: [curl, nuclei]
   ---
   ```
   Body: `## Objective` → `## Methodology` (numbered phases with real commands) →
   `## What counts as a finding` (severity tied to proof) → `## Evidence`.
2. Regenerate the router: `python tools/skill_index.py` (rebuilds `index.json` from all frontmatter).

Full guide (what skills are, how they reach agents, the frontmatter contract): **`docs/SKILLS.md`**.

Missing skills degrade gracefully: the workflow embeds the modality/class jobs inline, so an agent
still works without a matching SKILL.md — the skill just makes it sharper. Keep methodology honest:
severity always tied to **proven** impact (see `proof/poc-standard`).
