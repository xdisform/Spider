---
name: poc-standard
description: What counts as PROVEN impact vs a hypothesis. The bar every finding must clear before it is a finding.
category: proof
tags: [poc, evidence, impact, verification]
version: "1.0"
---

# Proof standard — proven impact, not hypotheses

A finding is only a finding when a **PoC reproduces real harm**. "An attacker could…", a reflected
value, a 200 on an admin path, a stack trace — these are **leads**, not findings. This skill is the
bar. If you cannot clear it, downgrade to a lead and say so.

## The bar per class (execution_evidence you must capture)
- **RCE** — command output proving code ran: `whoami` / `id` / `hostname` (only these, per policy).
  Save the exact request and the response containing the output.
- **SQLi** — data proving the query ran: `database()` / `@@version` / `current_user` (only these).
  Not "the parameter is injectable" — the returned DB string.
- **IDOR / BOLA** — the OTHER user's data actually returned to you, with proof it isn't yours
  (a second account's id/email/record). Two accounts, side-by-side responses.
- **SSRF** — an **out-of-band callback** you received (see `oob-interactsh`) or the internal
  resource's real response body (e.g. cloud metadata). A blind hit needs the interactsh log line.
- **Auth bypass / ATO** — you reached a protected action/identity you should not have, with the
  before/after showing the boundary crossed.
- **XSS** — execution proof (a callback, an `alert`-equivalent DOM effect captured), not just a
  reflected `<script>` string in the body.
- **Info disclosure** — the actual sensitive data returned, and why it's sensitive + unauthorized.

## Evidence you save under `raw/<label>/` for every finding
1. The exact **request(s)** (curl or the raw HTTP), carrying the mandatory header.
2. The **response(s)** proving impact (the command output / leaked record / callback).
3. A **runnable PoC** (a `.sh`/`.hurl`/`.py`) a triager can execute to reproduce it.
4. One-line **repro steps** in plain words.

## Severity rule
Severity is set by **proven** impact only. An impact/injection class claimed high/critical with an
empty `execution_evidence` is auto-downgraded to `medium` and titled `[UNCONFIRMED CANDIDATE]`.
When unsure, under-claim — the verifier and triager are hostile and will catch inflation.

## Policy
Stay inside the program's safe-PoC limits (from `scope.yaml`): the proof commands above and nothing
destructive. A PoC that violates policy is invalid no matter how big the impact.
