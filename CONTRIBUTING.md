# Contributing to Spider

Spider is an authorized-security-testing orchestrator for Claude Code. Contributions are welcome —
new skill packs, arsenal tools, workflow phases, and fixes. Read [SECURITY.md](SECURITY.md) first:
Spider is for **authorized** testing only, and engagement data must never be committed.

## First-time setup (once per clone)

```bash
git config core.hooksPath .githooks     # publish-safety guard: blocks staging bin/ + targets/ + *.env
python arsenal/provision.py              # fetch the arsenal into bin/ (nothing is vendored)
```

`targets/` (real scope/evidence/findings) and `bin/` (the arsenal) are git-ignored and must never be
published — the pre-commit guard enforces this even against `git add -f`.

## Run the checks before a PR

All offline, no target traffic, no arsenal needed — the same checks CI runs
([.github/workflows/smoke.yml](.github/workflows/smoke.yml)):

```bash
bash tools/smoke-resolver.sh      # the attack class->skill resolver stays in sync (attack.mjs == chain.mjs) + every pack is reachable
node tools/smoke-workflows.mjs    # every workflow executes end-to-end with mocked agents (catches runtime bugs node --check cannot)
bash tools/smoke-arsenal.sh       # every bin/<tool> a skill references exists (needs the provisioned arsenal)
bash tools/smoke-corpus.sh        # the corpus / retrieve tools hold their contracts
python -I tools/source-trace.py --self-test && python tools/recall.py --self-test
```

## How to extend

| You want to add… | Read | In short |
|---|---|---|
| a **skill** (methodology pack) | [docs/SKILLS.md](docs/SKILLS.md) | drop `.claude/skills/<recon\|attack\|proof>/<key>/SKILL.md`; a workflow lens/class with that key picks it up. Re-run `python tools/skill_index.py` + `tools/smoke-resolver.sh`. |
| a **tool** to the arsenal | [docs/ARSENAL.md](docs/ARSENAL.md) | add an entry to `arsenal/manifest.json`; reference it as `bin/<tool>` from a skill; `tools/smoke-arsenal.sh` verifies it resolves. |
| a **workflow phase / lens** | [docs/WORKFLOWS.md](docs/WORKFLOWS.md) | edit the `.mjs` in `workflows/`; keep the `attack.mjs` ↔ `chain.mjs` resolver in sync (the smoke enforces it); `node tools/smoke-workflows.mjs` must stay green. |

## Ground rules

- **No destructive, DoS, brute-force-of-others, social-engineering, or physical actions** in any skill or
  tool — ever, regardless of scope. Findings must be **oracle-proven**, not asserted.
- Keep workflow changes **additive** — a new feature gated off (an absent arg / flag) must leave the run
  byte-identical to before it.
- Program-specific details (oracle markers, platform conventions) belong in `scope.yaml`
  (`objective.oracle_markers`), not hardcoded — see the AD / backup-pivot packs for the pattern.
