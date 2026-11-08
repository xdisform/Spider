#!/usr/bin/env bash
# Leash mechanics proof against httpbin.org ONLY (never a real target). Starts the leash, checks
# header injection (in-scope) + off-scope 403 + audit, then tears down. Plain HTTP, no CA needed.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MITM="$ROOT/bin/.pyenv/Scripts/mitmdump.exe"
[ -f "$MITM" ] || MITM="$(command -v mitmdump || true)"
[ -n "$MITM" ] && [ -f "$MITM" ] || { echo "smoke: mitmdump missing (run: python arsenal/provision.py --only mitmproxy)"; exit 3; }

export X_BUGBOUNTY_TOKEN="smoke-token" LEASH_HEADER="X-Bug-Bounty" LEASH_SCOPE="httpbin.org" \
       LEASH_EXACT="0" LEASH_RPS="5" LEASH_LOG="$ROOT/bin/.smoke-leash.jsonl"
rm -f "$LEASH_LOG"

"$MITM" -s "$ROOT/tools/leash.py" --listen-host 127.0.0.1 --listen-port 8080 -q >/dev/null 2>&1 &
PID=$!
trap 'kill $PID 2>/dev/null' EXIT

# wait for the proxy to accept connections (curl-internal retry, no shell sleep)
curl -s --retry 15 --retry-connrefused --retry-delay 1 -x http://127.0.0.1:8080 \
     -o /dev/null http://httpbin.org/get || { echo "smoke: proxy never came up"; exit 4; }

echo "1) in-scope (httpbin.org) -> mandatory header injected?"
curl -s -x http://127.0.0.1:8080 http://httpbin.org/headers | grep -i "bug-bounty" || echo "   NO HEADER (FAIL)"

echo "2) off-scope (example.com) -> should be 403 LEASH"
code=$(curl -s -x http://127.0.0.1:8080 -o /dev/null -w "%{http_code}" http://example.com/)
echo "   example.com HTTP $code $([ "$code" = "403" ] && echo '(blocked, OK)' || echo '(FAIL)')"

echo "3) audit log lines: $(wc -l < "$LEASH_LOG" 2>/dev/null || echo 0)"
