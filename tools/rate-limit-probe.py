#!/usr/bin/env python3
"""
Rate-limit / lockout control-test — through the leash, in scope, honest.

This proves the ABSENCE of a rate-limit or account-lockout control (a paid defect class on many
programs) WITHOUT brute-forcing anyone: it sends N identical requests to ONE in-scope endpoint and
records the status curve. If the server never returns 429/419 (or a lockout) after N requests,
that's the control defect. It is NOT for guessing other users' credentials.

Routes through the scope leash (proxy 127.0.0.1:8080 + mitm CA), so every request is header-tagged,
rate-capped, off-scope-blocked and audited into raw/leash.jsonl, exactly like the rest of the fleet.

    python tools/rate-limit-probe.py --target-dir targets/acme \
        --url https://app.acme.com/api/login --method POST \
        --data '{"user":"OWN_TEST_ACCOUNT","pass":"wrong"}' --count 50

Guardrails: point it at YOUR OWN test account / a benign endpoint only. Respect the program's policy
(scope.yaml policies.rate_limit_test). stdlib only.
"""
from __future__ import annotations

import argparse
import json
import os
import ssl
import sys
import time
import urllib.request
import urllib.error
from pathlib import Path

LEASH = "http://127.0.0.1:8080"


def load_env(target_dir: str) -> dict:
    env = {}
    p = Path(target_dir) / "leash.env"
    if p.exists():
        for line in p.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                env[k.strip()] = v.strip().strip('"')
    return env


def opener_through_leash(ca: str | None):
    handlers = [urllib.request.ProxyHandler({"http": LEASH, "https": LEASH})]
    if ca and Path(ca).exists():
        ctx = ssl.create_default_context(cafile=ca)
        handlers.append(urllib.request.HTTPSHandler(context=ctx))
    return urllib.request.build_opener(*handlers)


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="Rate-limit / lockout control-test through the leash")
    ap.add_argument("--target-dir", required=True, help="targets/<t> (reads leash.env)")
    ap.add_argument("--url", required=True, help="ONE in-scope endpoint")
    ap.add_argument("--method", default="GET")
    ap.add_argument("--data", default=None, help="request body (triggers the method's body)")
    ap.add_argument("--count", type=int, default=50)
    ap.add_argument("--content-type", default="application/json")
    ap.add_argument("--out", default=None, help="write JSON result here (default: raw/rate-limit/<host>.json)")
    args = ap.parse_args(argv)

    env = load_env(args.target_dir)
    ca = os.environ.get("MITM_CA", str(Path.home() / ".mitmproxy" / "mitmproxy-ca-cert.pem"))
    header_name = env.get("LEASH_HEADER", "X-Bug-Bounty")
    token = env.get("X_BUGBOUNTY_TOKEN", "")
    opener = opener_through_leash(ca)

    body = args.data.encode() if args.data else None
    codes = []
    limited_at = None
    t0 = time.monotonic()
    for i in range(args.count):
        req = urllib.request.Request(args.url, data=body, method=args.method)
        if token:
            req.add_header(header_name, token)  # the leash also injects it; belt-and-suspenders
        if body:
            req.add_header("Content-Type", args.content_type)
        try:
            with opener.open(req, timeout=20) as r:
                code = r.status
        except urllib.error.HTTPError as e:
            code = e.code
        except Exception as e:  # noqa: BLE001
            code = f"ERR:{type(e).__name__}"
        codes.append(code)
        if code in (429, 419) and limited_at is None:
            limited_at = i + 1
            break
    elapsed = round(time.monotonic() - t0, 2)

    sent = len(codes)
    verdict = ("RATE-LIMITED at request %d — control present" % limited_at) if limited_at \
        else ("NO rate-limit / lockout observed after %d requests — CONTROL DEFECT (verify it's a login/sensitive endpoint and your own account)" % sent)
    result = {
        "url": args.url, "method": args.method, "requested": args.count, "sent": sent,
        "elapsed_s": elapsed, "status_codes": codes, "limited_at": limited_at, "verdict": verdict,
        "note": "through the leash (in-scope, header-tagged, audited). Own test account only.",
    }

    host = args.url.split("//", 1)[-1].split("/", 1)[0].replace(":", "_")
    out = Path(args.out) if args.out else Path(args.target_dir) / "raw" / "rate-limit" / f"{host}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps({k: result[k] for k in ("sent", "limited_at", "verdict")}, indent=2))
    print(f"[rate-limit-probe] full result -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
