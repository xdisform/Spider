<p align="center">
  <img src="docs/Spider.PNG" alt="Spider — Multi-agent Intelligent Spider System" width="100%">
</p>

<div align="center">

# Spider

### Claude, weaponized. A fleet of senior AI pentest agents that ships proven exploits — zero false positives, zero fluff.

<br/>

![Runs on Claude Code](docs/badge-runson.svg)
[![Bug bounty paid](docs/badge-bounty.svg)](https://ibb.co/qL87ZM8V)
![License MIT](https://img.shields.io/badge/license-MIT-111111?style=for-the-badge)

![Skills](docs/badge-skills.svg)
![Agents](docs/badge-agents.svg)
![False positives](https://img.shields.io/badge/false%20positives-0%20by%20design-111111?style=flat-square)

[![disform.ru](docs/btn-site.svg)](https://disform.ru)
[![Telegram](docs/btn-telegram.svg)](https://t.me/xdisform)
[![Private chat](docs/btn-chat.svg)](https://t.me/tribute/app?startapp=s1bsn)

</div>

Spider turns **Claude Code** into an autonomous red-team lead. No scanner, no Docker, no glue code — **the whole engine is prompts and skills**. A fleet of senior agents runs reconnaissance, exploitation and OSINT under frontier control, and **only oracle-proven impact survives**. The payoff: exploits that clear real program triage — already **1 000 000 ₽** in paid bug bounties.

> [!NOTE]
> **Proven, not promised.** Every "critical" is backed by a working PoC that a deterministic oracle re-derives. If the machine cannot reproduce it, it never ships — that is how Spider reaches **zero false positives**.

---

## Proven impact

Autonomous offensive AI is only getting sharper — and Spider is already landing real impact. Every result below was reached **fully autonomously** on **authorized bug-bounty and engagement scope**, and every one **paid out**. The operator ran them with **no formal security background** — not one infosec book, no networking theory — the fleet did the hunting.

> **Make no mistake: autonomous systems will hack more, and better, very soon.** Spider is that curve — shipping today.

1. **Unauthorized fund withdrawal from a bank** — found a missing authorization-token check and confirmed money moving out through the banking terminals.
2. **Administrator account takeover in the public sector.**
3. **RCE across every repository of a platform.**
4. **Full kill-chain — SQLi - credential read - RCE - webshell - host filesystem.** The defenders had to **irreversibly wipe the backend** to stop the advance through their infrastructure.
5. **600 customers' personal data (PII) exfiltrated in a single request.**
6. **MITM credential theft inside the CI/CD of a top security vendor.**
7. **Platform-wide RCE via the `app_dev.php` controller.**

…and more — every one fully autonomous, oracle-proven, and submitted.

---

## Why Spider

- **The future of pentesting, now.** Manual testing cannot keep pace with modern attack surface; a coordinated fleet of autonomous agents can. Spider is that bet — and it is already proven on real targets (above).
- **A fleet, not a bot.** Up to **~30 clean-context agents per task**, each armed with the real arsenal (`bin/` — nuclei, sqlmap, the OSINT stack, interactsh, …) and curated by a **tech-lead brain** that assigns surfaces, synthesizes every return, and drives the fleet to the objective.
- **Autonomous, in cycles.** scope → recon → deep recon → attack → chain → triage → report — each phase a fleet plus a clean-context synthesis, looping until the target is proven or dry. You approve each **GO**; the fleet does the rest.
- **Hypotheses from reconnaissance.** Recon doesn't just map the surface — it emits **ranked, VRT-tagged attack hypotheses** the attack fleet then tries to prove. Reasoning, not just scanning.
- **Learns from its own failures.** A dedicated **reflector agent** reads a failed attempt, derives *why* it failed from the evidence, and fires one **sharpened retry** through the same oracle gate before a lead is written off.
- **Memory between sessions.** A single-writer **corpus** promotes proven techniques and dead-ends from one engagement into the next — every run makes the following one sharper.
- **Deterministic proof, zero false positives.** Class oracles + FIRST CVSS 3.1 (`tools/ev-score.py`) + a payout-gate decide what ships. The model cannot narrate a false positive past the machine, and severity is never inflated to clear a pay floor.
- **Leashed and safe.** A scope / rate / egress fail-closed proxy; the fleet *physically* cannot reach an off-scope host, and a pre-commit guard keeps engagement data out of the repo.
- **Nothing to install but the arsenal.** Native to Claude Code — the intelligence is the prompt layer, not a heavyweight runtime.

---

## Commands

Run these from Claude Code. You orchestrate; the fleet hunts — and you approve every GO.

| Command | What it does |
|---|---|
| `/spider <target>` | **The full cycle** — scope, recon, deep recon, attack-to-proven-impact, synthesize. |
| `/doctor` | Preflight — detect and bootstrap the arsenal, bring up the scope leash, report readiness. No target traffic. |
| `/classify` | Dry-run the router — print the proposed mode and cycle/lens plan. Read-only, no traffic. |
| `/chain <target>` | Seeded exploitation — drive **all** findings into proven, oracle-validated kill-chains. Working PoCs, not hypotheses. |
| `/triage <target>` | Adversarial **3-stage** triage — hostile skeptics kill anything not truly proven before you submit. |
| `/report <target>` | Turn proven findings and the kill-chain into a submission-ready report with full PoC. |
| `/again <target>` | Re-run recon and attack from scratch **with full prior context** — unwind what the last run left open. |
| `/resume <target>` | Resume the attack with an operator-supplied session (foothold) the fleet could not obtain itself. |
| `/outcome` | Record a submission outcome (accepted / paid / duplicate / …) into the learning loop. |

---

## The cycle

Each phase is an operator **GO** gate, a fleet of clean-context agents, and a clean-context synthesis.

| Phase | What happens | Fleet | Output |
|---|---|---|---|
| **Scope + GO** | Transcribe `scope.yaml`, liveness + egress check, pick fleet (5 / 10 / 15) and model tier | — | `run.json`, leash up |
| **Recon-1** | Broad OSINT across every modality in parallel | recon operators | `01-recon-surface.md`, `state.json` |
| **Recon-2** | Deeper recon → ranked, VRT-tagged hypotheses | recon operators | `02-infra-hypotheses.md` |
| **Attack** | Exploit each hypothesis from diverse angles; adversarially verify every claim | operators · validator · 3 skeptics | reproducible PoCs, confirmed findings |
| **Chain** | Combine findings into composite kill-chains | chain-builder · operators | `killchain.md` |
| **Triage** | Three hostile vetoes — oracle ▸ impact ▸ real CVSS / payout | validator · verifier-skeptic · triage-scorer | `SUBMIT` / `FIX` / `DROP` |
| **Report** | Assemble the submission-ready report with PoC | — | `report.md` |

---

## Quick start

```bash
# 1. Clone
git clone <your-repo-url> spider && cd spider

# 2. Provision the arsenal (downloaded at install, never committed)
export GITHUB_TOKEN=ghp_xxx          # optional: avoids the GitHub API rate limit
python arsenal/provision.py --check  # dry-run: what would be installed
python arsenal/provision.py          # install into bin/

# 3. Activate the publish-safety hook (blocks engagement data / secrets from commits)
git config core.hooksPath .githooks
```

Then, in Claude Code: `/doctor` to preflight, `/spider <target>` to run.

> [!WARNING]
> **Authorized use only.** Spider actively tests the targets you point it at. Run it only against systems you own or have **explicit written permission** to test — bug-bounty scope, a contracted engagement, or your own lab — and stay within scope. It will not run without a `scope.yaml` and your GO. You alone are responsible for authorization and compliance; unauthorized testing is illegal in most jurisdictions.

---

## Recommendations

- **Run it on Claude Code Max (5× or 20×).** A fleet of up to ~30 agents per task moves fast and burns tokens — **20×** gives comfortable headroom for large targets and deep runs; **5×** is enough for smaller scopes and recon-heavy work.
- **Pick the model tier per phase.** Use the **strong** tier (Opus) for attack / chain / triage — the reasoning that actually lands exploits — and the **fast** tier (Sonnet) for broad recon, where breadth beats depth.
- **Size the fleet to the target.** 5 for a quick pass, 10–15 for broad coverage; scale up on a bigger plan for large estates.
- **Provision with a token.** Set `GITHUB_TOKEN` before `arsenal/provision.py` to dodge the GitHub API rate limit.
- **Let long phases run in the background.** Deep recon and attack take minutes to hours — run them detached and review at each GO.
- **Keep scope tight.** One precise `scope.yaml` per target; the leash enforces it, and a narrow scope makes the fleet faster and sharper.

---

## Layout

```
.claude/
  skills/      attack · recon · proof — 92 methodology packs
  agents/      10 roles (operator · validator · verifier-skeptic · triage-scorer · …)
  commands/    the slash commands above
brain/         the tech-lead doctrine the agents read (spider · schema · mission · vrt)
workflows/     per-phase multi-agent scripts (recon-1/2 · attack · chain · triage)
tools/         deterministic Python / shell (leash · ev-score · payout-gate · oracles)
arsenal/       self-provisioning installer (bin/ is downloaded, never committed)
docs/          architecture · cycle · skills · tool-map
```

`targets/` (engagement data) and `bin/` (arsenal) are git-ignored and never ship.

---

## Docs

Full docs in **[docs/](docs/README.md)** — [Architecture](docs/ARCHITECTURE.md) · [Cycle](docs/CYCLE.md) · [Skills](docs/SKILLS.md) · [Workflows](docs/WORKFLOWS.md) · [Tool map](docs/TOOL-MAP.md). Changes in [CHANGELOG.md](CHANGELOG.md); contributing in [CONTRIBUTING.md](CONTRIBUTING.md).

<div align="center">
<sub><b>MIT</b> · built for authorized offensive security · fetched tools keep their own licenses (<a href="THIRD-PARTY-LICENSES.md">THIRD-PARTY-LICENSES</a>)</sub>
</div>
