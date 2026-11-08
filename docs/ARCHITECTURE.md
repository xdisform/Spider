# Architecture

Spider turns Claude Code into a pentest **tech-lead** that delegates to fleets of workflow agents.
The brain never hunts; it scopes, delegates, synthesizes, and gates.

## The pieces

- **`brain/`** — the doctrine (prompts are the engine). `spider.md` (the tech-lead loop),
  `scope.md` (the GO gate), `schema.md` (the one data contract), `mission.md` (how a phase's `args`
  is built), `synthesis.md` (how the clean-context synthesizer writes each doc).
- **`.claude/commands/`** — the entry points: `/spider`, `/again`, `/triage`, `/report`, `/doctor`.
- **`.claude/agents/`** — the roles a workflow spawns: `recon-operator`, `attack-operator`, `advisor`
  (reflective strategist), `validator` (deterministic oracle), `verifier-skeptic`, `triage-scorer`
  (severity-truth triager), `chain-builder`, `synthesizer`, `corpus-curator`, `duplicate-scout`. Each is a
  system prompt; the workflow picks it via
  `agentType`.
- **`.claude/skills/`** — methodology packs (Markdown). Agents `Read` the ones relevant to their
  surface. `index.json` routes by class/tags.
- **`workflows/*.mjs`** — the per-stage fan-out scripts. The brain runs them with
  `Workflow({scriptPath, args})`. They are pure coordinators: agents do all file I/O and tool exec.
- **`arsenal/`** — self-provisioning tools. `manifest.json` (the vetted tool set — recon, attack, AD,
  CTF, control), `provision.py` (downloads per-OS into `bin/`), `probe.py` (capability report).
- **`tools/`** — the scope controls: `leash.py` (mitmproxy addon), `guard.py` (host/CIDR pin for
  non-HTTP tools), `schema/finding.schema.json` (the finding shape + evidence gate).
- **`targets/<t>/`** — per-engagement workspace (the data contract in `brain/schema.md`).

## Data flow (the load-bearing constraint)

A **workflow script is pure JS with no filesystem or network** — data moves only through `args`
(in) and agent return values (out). So:

1. The brain reads `scope.yaml`/`state.json`/skill paths and passes them in `args`.
2. Agents (Bash/Read/Write) read scope, run `bin/` tools **through the leash**, and write evidence
   to `raw/<agent>/` — then return a compact schema.
3. The script aggregates the returns and hands them back to the brain.
4. A fresh **synthesizer** reads the whole target folder and writes the stage doc, `findings.jsonl`
   (the only writer), and the merged `state.json`.

## How agents get capability

- **CLI arsenal** — `bin/` tools via Bash (provisioned by `arsenal/`).
- **MCP tools** — any connected MCP server, discovered per-agent via `ToolSearch` (optional heavy
  tool-servers plug in here).
- **Methodology** — skill files, passed as paths in `args`; the agent `Read`s them.

## Safety

Every live HTTP request is forced through the **leash** (mandatory header, off-scope 403, global
rate cap, fail-closed, JSONL audit). Non-HTTP tools are host/CIDR pinned by the **guard**.
Intrusive tools are gated behind explicit scope. One human GO before any live traffic. Proven
impact only — the evidence gate and the adversarial verifier kill unproven claims.

## Isolation model — the leash, not a container

Tools like Strix sandbox the **agent** in a Docker container. Spider isolates the **traffic** instead,
with the scope leash — a deliberate choice:

- **The constraint that matters in bug bounty is scope, not the host.** An engagement is defined by
  *which hosts you may touch and how* — exactly what the leash enforces on every request (mandatory
  header, off-scope 403, rate cap, fail-closed, audited), regardless of which tool makes it. A container
  isolates the agent from the host but does nothing to stop it hitting an out-of-scope asset; the leash
  does precisely the thing that matters.
- **Spider runs inside Claude Code**, where the agent is already a bounded process with a tool
  allow-list and per-command approval — much of a container's host-isolation is already present.
- **Cross-platform, no daemon.** The arsenal is native `bin/` binaries; there is no image to build or
  Docker daemon to run on Windows / macOS / Linux.

The honest trade-off (also in `SECURITY.md`): the leash is enforced by routing every target-facing
command through `tools/leashed.sh` — orchestrator + operator discipline, **not** a kernel-level egress
lock. Verify the audit log (`raw/leash.jsonl`) proves in-scope traffic before trusting a run. A future
hardening is a transparent-proxy egress lock so the leash holds even for a tool that ignores proxy
environment variables.
