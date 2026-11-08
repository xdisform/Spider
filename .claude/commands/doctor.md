---
description: Preflight — detect and bootstrap the arsenal, bring up the scope leash, report what's ready. No target traffic.
argument-hint: "[--install] [<host:port>]"
---

Diagnose Spider's readiness. **This touches only localhost — plus, when a target is given, the single
in-scope liveness connect `/spider` step 1 already performs.**

1. **Arsenal.** Run `python arsenal/probe.py` and show the table (what's present per phase). If
   the manifest is missing, say the arsenal research hasn't run yet.
2. **Install (if asked).** If the operator passed `--install` (or tools are missing and they
   confirm), run `python arsenal/provision.py` — it downloads the arsenal into `bin/` from
   upstream releases. Report each tool installed / skipped / failed with the reason. State sizes
   before large downloads.
3. **Leash.** Confirm `mitmdump` is available (part of the arsenal). Explain that on a live run
   `tools/start-leash.sh targets/<t>/leash.env` brings the scope leash up on 127.0.0.1:8080.
4. **Egress / VPN-conflict preflight (CODE, not prose).** Run `python arsenal/probe.py --egress`
   (localhost-only: default route, full-tunnel-VPN ownership of that route, and whether a local proxy is
   listening on an OOB-callback port 9090/7890 — the h-41 mihomo/Clash case). Show the verdict:
   - `warn:oob-proxy-listening` → a local proxy (mihomo/Clash) can bounce OOB callbacks back to this box
     (origin-check false-positive). Tell the operator to stop it or move it off the standard port.
   - `egress_ok` (localhost) → route is sane; reachability is confirmed at `/spider` step 1.
   **HARD reachability gate (when a target is known — `/spider` step 1 or `/doctor <host:port>`):** run
   `python arsenal/probe.py --egress <host:port>`. A `conflict` verdict (exit 2) is a **GO blocker** —
   e.g. `vpn-fulltunnel-killswitch` (a WireGuard `/0` kill-switch or mihomo TUN `auto-route` owns the
   default route and the target is unreachable — the exact POSTMORTEM F9 case). Do NOT present GO until
   the target is reachable; print `advice` and the fix. This is the sanctioned step-1 liveness connect
   upgraded to a verdict — it adds no new target traffic.
5. **Optional heavy arsenal.** If a tool-server MCP is connected this session (ToolSearch),
   note it as available; if configured but down, say so — do NOT assume it.
6. **Verdict.** Ready / what's missing / exact command to fix it. Nothing here hits a target.
