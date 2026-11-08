---
name: target-classify
description: Read-only, traffic-free classification of an engagement — read scope.yaml + the one liveness fact + local artifact file-types, commit a mode set, and propose a foothold-first cycle/lens plan. No packets, no login.
category: recon
tags: [classify, router, mode, planning, scope]
chains_with: [port-service, http-probe, nonhttp-cred-surface]
tools: [file]
version: "1.0"
---

# Target classification & mode routing (preflight, read-only)

## Objective
Give the brain a **macro plan** before the first packet: classify the engagement into the closed mode
set and propose which cycles/lenses run, in what order. You are the *router* — you **classify and
sequence only**, you never hunt. This runs in **preflight**, so it must send **zero target traffic**: it
reasons over `scope.yaml`, the single already-authorized liveness/egress probe step 1 took, and the
`file`-type of any local artifact the operator dropped under `targets/<t>/artifacts/`. The brain shows
your plan at GO #1; the operator approves it. The authoritative registry is **`brain/modes.md`**.

## Methodology (read-only, no packets)
1. **Read the authority.** Parse `scope.yaml`: `hosts`/`services`/`netblocks`, any pinned
   `engagement.type`/`modes`/`artifacts`/`challenges`, and the `objective.goal`/`flag_format`/`where_hint`
   (a classification + ordering bias — a lead, never authority or proof).
2. **Read the one liveness fact** (already taken — do not re-probe): an HTTP status/title/server ⇒ `web`;
   a raw service banner or a non-HTTP in-scope port ⇒ `network`/`service`; an OpenAPI/Swagger/GraphQL
   path with little/no HTML ⇒ `api`.
3. **Read local artifact magic** with `file` (LOCAL only — never against a URL): ELF/PE ⇒ `binary`
   (expands to `ctf-pwn`+`ctf-rev`); document/image/pcap/ciphertext ⇒ `file` (expands to
   `ctf-forensics`/`ctf-stego`/`ctf-crypto`). `engagement.challenges[].category` pins the exact `ctf-*`.
4. **Commit the mode set** from the decision table in `brain/modes.md`. Emit `chosen_modes` as the
   **fine** lens-mode set (`web|network|service|api|ctf-pwn|ctf-rev|ctf-crypto|ctf-forensics|ctf-stego`)
   — that is what the recon mode gate intersects — and a single coarse `mode` label for the banner.
5. **Order foothold-first** (ATT&CK: Credential/Initial Access before Discovery/Collection).

## Decision rules (the backward-compat contract — follow exactly)
- **Default to the full web set.** If ANY host is reachable, `chosen_modes` MUST include every
  `web`/`network`/`service`/`api` mode any signal supports. Do **not** narrow below the full web set for
  a web-reachable target — `web∪network∪service∪api` equals the entire current lens list, so this is what
  keeps a normal run byte-for-byte unchanged.
- **Narrow only for a pure artifact.** Choose a `ctf-*`/binary/file-only set **only** when there is NO
  reachable host at all (a provided puzzle); then propose `[classify, attack, objective-check]` and skip
  the web recon cycles.
- **Fail-open.** Not confident, or genuinely ambiguous with no operator pin ⇒ return
  `chosen_modes:['web','network']`, `confidence:'low'`. The default is always the thing that works today.
- **Coarse → fine:** `binary`→`[ctf-pwn,ctf-rev]`, `file`→`[ctf-forensics,ctf-stego,ctf-crypto]`,
  `ctf`→ the categories in `challenges[]`, `mixed`→ the union. (Full table in `brain/modes.md`.)

## What to return
The `PLAN` schema (see `workflows/classify.mjs`): `mode` (coarse label), `chosen_modes` (the fine set
driving `args.modes`), `confidence`, `signals` (the concrete evidence per mode — `host:port` + status,
a swagger path, a `file` magic string), `proposed_phases` (the ordered, foothold-first cycle plan), and
optional `proposed_ideas`. The return value **is** the plan the operator approves at GO #1.

## Evidence
Your reasoning traces to the facts you were handed — the liveness fact and the `file`-magic lines on
local artifacts. There is no `raw/` write and no finding here: classification produces a **plan**, not an
asset or a capability. The capability graph is populated later, only by oracle-proven or operator-supplied
producers.

## Red line
**Classify only — no packets, no scan, no login, no new connection before GO.** A mode is a lens/cycle
selection, **never** a capability or a policy relaxation: choosing a mode never enables a control-test,
never relaxes a safeguard, and only turns on lenses/classes that themselves obey the red line. The
operator GO is preserved and enriched (it now shows your plan), never replaced. The mid-run re-route
runs only via the brain's one `AskUserQuestion` + a logged `run.json.plan_revisions` entry — the fleet
proposes, the human approves, nothing widens scope or mode silently; out-of-scope discoveries stay leads.
