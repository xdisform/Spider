---
name: dynamic-validate
description: Prove a client-side bug by REAL execution in a leashed headless browser (Playwright MCP) — DOM-XSS, prototype-pollution gadget, origin-less postMessage, open-redirect, clickjacking, credentialed CORS — so the oracle is "the JS fired / the boundary crossed", never a reflected string.
category: proof
tags: [dynamic, browser, playwright, dom-xss, oracle, execution]
chains_with: [oracles, poc-standard, deep-source-trace, js-sink-mining]
tools: [playwright-mcp]
version: "1.0"
---

# Dynamic validation (live browser execution oracle)

## Objective
Client-side classes do not reach `impact_proven` on a reflected string — the oracle table
(`proof/oracles`) demands the payload **execute**. This skill turns a static source→sink lead (from
`deep-source-trace`/`js-sink-mining`) into a proven finding by running it in a **real headless browser**,
so the evidence is a captured execution signal a re-run reproduces. Static analysis finds the path;
dynamic validation is what makes it a high, not a "possible XSS" lead. This is the half the fleet most
often skips — wiring it in is a direct find-rate lever (Strix/Shannon prove every client-side bug live).

## Prerequisite — the leashed browser
The **Playwright MCP** is pinned to the scope leash in `.mcp.json`
(`--proxy-server http://127.0.0.1:8080 --ignore-https-errors --headless`), so the browser hits only
in-scope hosts, carries the mandatory header, and is rate-capped like every other target-facing tool.
Start the leash first (`tools/start-leash.sh ${target_dir}/leash.env`). Load the MCP tools with
ToolSearch (`mcp__playwright__*`). Drive **in-scope hosts only** — a discovered host is a lead. If the
browser MCP is not connected, say so and fall back to the blind-XSS OOB path below; do NOT claim a DOM
finding you could not execute.

## The execution oracle per class
Navigate to the crafted URL/flow, then capture the signal with a page hook (never a human-read screenshot
as the sole proof):
- **DOM-XSS / eval sink:** install a sentinel before navigation (override `alert`/`print`, or set
  `window.__xss=0` and have the payload do `window.__xss=1` / `document.title='PWNED-<nonce>'`). Oracle =
  the sentinel fired (`__xss===1`, the title/nonce changed, a dialog was raised) — read it back via the
  MCP's evaluate/console API. A payload that only appears in the DOM as text did NOT execute → lead.
- **prototype-pollution gadget:** after the polluting input, evaluate `({}).<polluted-key>` in the page —
  the fresh object carries the injected property (pollution oracle); then show the gadget firing (a
  sentinel as above for a script gadget, or the privileged client state). 
- **postMessage:** from a second page/frame `postMessage` the payload to the target `window`; oracle = the
  handler acted on it with no origin check (sentinel fired / state changed).
- **open-redirect:** navigate the crafted link; oracle = the browser actually lands on the
  attacker-controlled host (final URL / a request to it in the network log), not just a 3xx header.
- **clickjacking:** load the target inside an attacker `<iframe>`; oracle = it renders framed (no
  `X-Frame-Options`/frame-ancestors broke it) AND a sensitive action is clickable — capture the framed
  render + the action.
- **credentialed CORS:** with the operator session active (leash-injected), do the cross-origin `fetch`
  from an attacker origin and read the victim body back (pairs with `proof/cors-poc-html`).

## What to save (re-runnable evidence)
Under `raw/<label>/`: the exact crafted URL/flow, the sentinel/hook used, the captured execution signal
(console line, `__xss` value, final URL, framed render), and a runnable repro — either the MCP action
sequence written down, or a Playwright script, so the validator re-derives the same signal. A remembered
"it popped" is not evidence.

## Oracle (load-bearing)
Per `proof/oracles`: the finding is `confirmed` only when the browser re-run reproduces the execution
signal. The blind-XSS OOB callback (interactsh) remains a valid alternative oracle when the sink is a
stored/blind context. Narration, a reflected value, or a screenshot with no captured signal is NOT proof.

## Red line
In-scope hosts only, through the leash, headless, non-destructive. Use the operator's own
session/synthetic accounts; never act on a real victim. No auth-crack, no flood. The safeguard red line,
the oracle gate, and the skeptic lenses are unchanged.
