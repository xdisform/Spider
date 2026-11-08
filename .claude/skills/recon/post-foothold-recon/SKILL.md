---
name: post-foothold-recon
description: Read-only planner that, for every host with a credible foothold surface, emits the LATENT post-foothold chain (internal-recon → privesc → loot → lateral) as stage:"post-foothold" hypotheses the scheduler fires only once the shell:/foothold: token is proven. No surface ⇒ emits nothing. Plans only; runs nothing.
category: recon
tags: [post-foothold, planner, shell, privesc, loot, lateral, dependency-graph]
chains_with: [nonhttp-cred-surface, auth-flow, access-control]
tools: []
version: "1.0"
---

# Post-foothold operations planner (read-only)

## Objective
Model the *inside-the-box* kill chain **up front**, before any foothold exists. For every host in
`state.json` that has a **credible foothold surface**, emit the four latent `stage:"post-foothold"`
hypotheses the attack scheduler will hold `blocked_on_prereq` until a producer proves the host's
`shell:<host>`/`foothold:<host>` token — then they fire automatically in a later wave (zero scheduler
change). This is what lets Spider plan `foothold → privesc → loot the flag → bounded lateral` without
ever building a step that fires before its prerequisite. **This lens PLANS; it does not run anything,
touch the target, or open a channel.**

## What is a "credible foothold surface" (the emit condition)
Emit the chain for a host when `state.json` shows at least one of:
1. a **non-HTTP service that can yield a shell** — ssh / telnet / rdp (these provide `shell:<host>`;
   mysql/redis/vnc are app/db-only and do **NOT** yield `shell:`);
2. an open **RCE / SSTI / command-injection / file-upload** hypothesis on the host (a proven one will
   provide `shell:<host>`);
3. a **proven or operator-supplied session/foothold** already in `capabilities[]` (`session.env`, a
   confirmed auth-bypass/otp-logic/cred control-test).

If **no** host has a foothold surface, **emit NOTHING** — a plain web target is byte-for-byte unaffected
(this lens is the shipped `nonhttp-cred-surface` precedent: always-on, self-gating, silent when N/A).

## Methodology (read-only planning)
Read `state.json` + `docs/01-recon-surface.md`. For each host with a foothold surface, emit, with the
correct `stage`/`requires`/`provides` from the `brain/schema.md` token grammar:

1. **`class:internal-recon`** — `stage:"post-foothold"`, `requires:["shell:<host>"]`, `provides:[]`
   (knowledge; may yield `creds:<p>@<in-scope-host>` if a cred for another in-scope host is found).
   Read-only enumeration (linPEAS stealth / manual SUID-sudo-caps-cron-writable-interesting-files).
2. **`class:privesc`** — `stage:"post-foothold"`, `requires:["shell:<host>"]`, `provides:["admin:<host>"]`.
   ONE oracle-proven single-step escalation from a concrete GTFOBins/LOLBAS/known-CVE misconfig.
3. **`class:loot`** — `stage:"post-foothold"`, `requires:["shell:<host>"]` (OS files) **or**
   `["foothold:<host>"]` (app-level read), `provides:[]` (+ `creds:<p>@<host>` if a cred is read).
   Read the **objective-relevant** files first — the flag usually lives behind the foothold.
4. **`class:lateral`** — `stage:"post-foothold"`, `requires:["shell:<host>"]`,
   `provides:["creds:<p>@<host2>"]` for an **in-scope** neighbour only.

Each hypothesis carries a concrete `how_to_prove` (the enumeration/lookup/read it will run under
`tools/leash-foothold.sh`) and an `evidence` path under `raw/`. Rank them so the chain that reaches the
objective (loot of the flag, via privesc if the flag is root-only) is highest.

## What to return
The four latent hypotheses per footholdable host with their `stage`/`requires`/`provides` wired to the
graph, plus the surface signal that justified each. If a host has only an app-level session (web login,
BOLA) and no shell path, emit **only** the `foothold:`-gated `loot` hypothesis and mark that `privesc`/
`internal-recon`/`lateral` are N/A for that host (they need `shell:`, which a web session does not grant)
— an honest result, not a gap.

## Evidence
This lens reads the world model only; its "evidence" is the `state.json` host/service/hypothesis entries
it cites to justify each latent hypothesis, recorded under `raw/post-foothold-recon/`. No probe, no
banner grab, no channel — a plan, not a packet.

## Red line
Planning is **observation only**. Nothing here runs on any host, opens any socket, or leaves scope. The
actual inside-the-box work runs in the attack phase (classes `internal-recon`/`privesc`/`loot`/`lateral`)
**only** once a foothold producer proves the token, and **only** through `tools/leash-foothold.sh`
(host-pinned, non-destructive, bounded). Spider models **no persistence** — no implants, backdoors, or
persistence hypotheses are ever emitted.
