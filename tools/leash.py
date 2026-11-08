"""
Spider scope leash — a mitmproxy addon.

Run:  mitmdump -s tools/leash.py --listen-host 127.0.0.1 --listen-port 8080 --ssl-insecure -q
Force an agent through it: set HTTP_PROXY/HTTPS_PROXY to the leash and trust its mitm CA.

On EVERY request it:
  - injects the program's mandatory header (traffic ID)                  -> findings stay valid
  - 403s any off-scope host locally, so it never egresses                -> scope-lock
  - holds a single global req/s cap across all concurrent flows          -> polite rate
  - passes the agent's own API/LLM endpoints through untouched           -> brain keeps working
  - fails CLOSED: no token or no scope => every request is blocked        -> no accidental leaks
  - appends a JSONL audit line per allowed request                       -> proof of in-scope traffic

Config comes from env (Spider writes these from scope.yaml into leash.env):
  X_BUGBOUNTY_TOKEN   secret value of the mandatory header (required)
  LEASH_HEADER        header name (default: X-Bug-Bounty)
  LEASH_SCOPE         comma-separated in-scope hosts/domains (required)
  LEASH_EXACT         1 = exact host only; 0 = also allow subdomains (default 1)
  LEASH_PASSTHROUGH   comma-separated hosts forwarded untouched (agent's own APIs)
  LEASH_RPS           aggregate requests/sec cap (default 5)
  LEASH_LOG           audit JSONL path (default: leash.jsonl)
"""
import asyncio
import json
import os
import re
import time

from mitmproxy import http

HEADER = os.environ.get("LEASH_HEADER", "X-Bug-Bounty")
TOKEN = os.environ.get("X_BUGBOUNTY_TOKEN", "")
SCOPE = [h.strip().lower() for h in os.environ.get("LEASH_SCOPE", "").split(",") if h.strip()]
EXACT = os.environ.get("LEASH_EXACT", "1") == "1"
# Per-host EXACT override (used when LEASH_EXACT=0 globally, but SOME hosts in the program's own
# in-scope list are listed WITHOUT wildcard — e.g. "https://example.market" vs "*.example.com"). Comma-
# separated hostnames that must match EXACTLY (host==s), ignoring any subdomain. These entries
# must ALSO appear in LEASH_SCOPE (this is a tightener, not an expander).
SCOPE_EXACT_HOSTS = set(h.strip().lower() for h in os.environ.get("LEASH_SCOPE_EXACT", "").split(",") if h.strip())
PASSTHROUGH = [h.strip().lower() for h in os.environ.get("LEASH_PASSTHROUGH", "").split(",") if h.strip()]
RPS = float(os.environ.get("LEASH_RPS", "5"))
LOG = os.environ.get("LEASH_LOG", "leash.jsonl")

# F1 — operator-supplied session (from targets/<t>/session.env, sourced by start-leash.sh). SECRET.
# Injected ONLY after the scope-lock below, so it is carried on in-scope requests and can never egress.
SESSION_COOKIE = os.environ.get("SESSION_COOKIE", "")
SESSION_HEADERS = [h for h in re.split(r"[|\n]", os.environ.get("SESSION_HEADERS", "")) if h.strip()]

_min_interval = 1.0 / RPS if RPS > 0 else 0.0
_lock = asyncio.Lock()
_last = 0.0


def _host(flow: http.HTTPFlow) -> str:
    return (flow.request.pretty_host or "").lower().rsplit(":", 1)[0]


def _passthrough(host: str) -> bool:
    return any(host == p or host.endswith("." + p) for p in PASSTHROUGH)


def _in_scope(host: str) -> bool:
    if EXACT:
        return host in SCOPE
    # per-host exact override: SCOPE_EXACT_HOSTS entries never match a subdomain
    return any(
        (host == s) if s in SCOPE_EXACT_HOSTS else (host == s or host.endswith("." + s))
        for s in SCOPE
    )


def _audit(method: str, url: str) -> None:
    try:
        with open(LOG, "a", encoding="utf-8") as f:
            f.write(json.dumps({"ts": time.time(), "method": method, "url": url}) + "\n")
    except Exception:
        pass


async def request(flow: http.HTTPFlow) -> None:
    host = _host(flow)

    # agent's own API/LLM endpoints — never touched
    if _passthrough(host):
        return

    # fail closed
    if not TOKEN or not SCOPE:
        flow.response = http.Response.make(403, b"LEASH: fail-closed (no token or no scope)\n")
        return

    # scope-lock — answered locally, never egresses
    if not _in_scope(host):
        flow.response = http.Response.make(403, b"LEASH: out of scope\n")
        return

    # mandatory header
    flow.request.headers[HEADER] = TOKEN

    # operator-supplied session (F1): injected only here — AFTER passthrough + fail-closed + scope-lock —
    # so it rides every in-scope request automatically and physically cannot leak to an off-scope host.
    if SESSION_COOKIE:
        have = flow.request.headers.get("Cookie", "")
        flow.request.headers["Cookie"] = (f"{have}; {SESSION_COOKIE}".strip("; ")) if have else SESSION_COOKIE
    for _h in SESSION_HEADERS:
        _name, _, _val = _h.partition(":")
        if _name.strip():
            flow.request.headers[_name.strip()] = _val.strip()

    # global rate cap across all concurrent flows
    global _last
    async with _lock:
        now = time.monotonic()
        wait = _min_interval - (now - _last)
        if wait > 0:
            await asyncio.sleep(wait)
        _last = time.monotonic()

    _audit(flow.request.method, flow.request.pretty_url)
