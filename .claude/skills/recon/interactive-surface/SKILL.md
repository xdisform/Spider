---
name: interactive-surface
description: Read-only recon of STATEFUL non-HTTP services (pwn nc listeners, custom line/binary protocols, telnet/console, redis-RESP/mqtt/amqp, game servers) and WebSocket endpoints — grab the opening banner/frames one-shot, judge whether the protocol is conversational, and emit class:interactive-<proto> foothold hypotheses with a concrete conversation sketch. No held socket here.
category: recon
tags: [interactive, stateful-protocol, websocket, pwn, non-http, foothold]
chains_with: [nonhttp-cred-surface, port-service, interactive-exploit]
tools: [leash-tcp, websocat]
version: "1.0"
---

# Interactive / stateful-protocol surface

## Gate
This lens is in the recon set **only** when `scope policies.interactive_protocol.enabled` is true — a plain
web/network run never adds it (recon-2 guards the `LENSES.push`). If you are reading this, the operator
opted into interactive work. Recon is still **read-only** regardless; the held-socket exploit lives in the
`interactive-exploit` attack class.

## Objective
Turn the stateful non-HTTP services `port-service`/`nonhttp-cred-surface` found — and every WebSocket
endpoint recon saw — into **foothold hypotheses** for a conversation-driven exploit. Spider's one-shot
non-HTTP path (`tools/leash-tcp.sh`) can banner-grab a single request/response but **cannot hold a
conversation**; a pwn `nc` logic bug, a custom admin/console protocol, or a WebSocket command bug is
exploited over many frames on one held connection. This lens finds those surfaces and hands the attack
phase a concrete plan. A reachable stateful service is a first-class **foothold producer** in the attack
dependency graph. **No held socket, no exploitation in recon — this lens is strictly read-only, like
`nonhttp-cred-surface`.**

## Methodology (read-only)
1. **Pin scope first.** Non-HTTP tools don't honor the HTTP leash — gate every probe with
   `python tools/guard.py --scope "$LEASH_SCOPE" --check "<cmd>"` and route the banner grab through
   `tools/leash-tcp.sh <target_dir> <host> <cmd>`. One host, never a range, never `-iL`. **One-shot only** —
   do NOT open `tools/leash-sock.py` here (that is the attack phase).
2. **Opening banner / frames.** Read the first bytes the service sends: a prompt (`> `, `$ `, `name? `), a
   menu, a login handshake, a version string, a RESP/MQTT/AMQP greeting. For a WebSocket, note the
   `Upgrade: websocket` endpoint recon-1 saw (a `new WebSocket(...)` in JS, an `Upgrade` response) — a WS
   endpoint is in-scope for this lens even though the HTTP leash saw only the upgrade.
3. **Is it conversational?** Judge from the opening bytes whether the protocol is **stateful** — a
   prompt/menu to answer, a verb set to call, a handshake that gates later commands, a session that carries
   state frame-to-frame. A pure one-shot request/response (a simple banner, a `QUIT`-only service) is NOT an
   interactive surface — say so and move on.
4. **Name the suspected logic flaw.** From the verb set / prompts, hypothesize the *conversation-level* bug:
   a **protocol state-machine auth-bypass** (a privileged verb accepted out of order / before auth), a
   **missing-authz command** (an admin verb any peer may call), a **format-string / overflow** in a field
   the prompt reads, or a **race** over the socket. This is a *lead*, proven only in attack.
5. **Emit the hypothesis with a conversation sketch.** For each conversational service emit
   `class: interactive-<proto>` (e.g. `interactive-tcp`, `interactive-ws`, `interactive-line`,
   `interactive-binary`) with a concrete **conversation sketch** in `how_to_prove`: the opening prompt, the
   verbs to try, the field to attack, and the expected proof (command output over the socket, a leaked
   record, or a protocol state crossed).

## Graph edges (set these exactly)
- A conversation that **grants access** (a pwn shell, a protocol auth-bypass that logs you in) →
  `stage: "foothold"`, `provides: ["session:<host>", "foothold:<host>"]`. It is a FOOTHOLD PRODUCER the
  attack scheduler proves first; a pwn `nc` that drops a shell also satisfies P1's `objective-capture`
  (`requires: ["foothold:<host>"]`).
- A logic bug inside a service you must **already hold** → `stage: "post-foothold"`,
  `requires: ["session:<host>"]`.
- P5 adds **no new capability token** — the closed grammar (`session`/`creds`/`token`/`foothold`/`admin`)
  is unchanged; an interactive foothold reuses `session:`/`foothold:` (grammar in `brain/schema.md`).

## What to return
Per service: the opening banner, the conversational verdict (interactive / one-shot and why), the suspected
logic flaw, and the hypothesis with its `stage`/`requires`/`provides` and conversation sketch. A service that
is not conversational is an honest N/A, not a gap.

## Evidence
The one-shot banner grabs + the `guard.py` check that authorized each probe, all under
`raw/interactive-surface/`. A claim with no evidence file is a lead, not an asset.

## Red line
Observation only. Never hold a socket, never send a second frame to drive state, never flood, never a range.
The actual conversation runs in the attack phase via the `interactive-exploit` class, and **only** if
`scope policies.interactive_protocol.enabled`. Logic exploitation of an authorized stateful service is in
scope there; cracking/brute-forcing auth as evasion is not — a door reachable only by defeating an auth
control as an attack is a hand-off (`blocked:safeguard`), never a workaround.
