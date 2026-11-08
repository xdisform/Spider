#!/usr/bin/env bash
# Offline proof that the F9 egress / VPN-conflict gate (arsenal/probe.py --egress) holds — runs NO
# network and connects to NO target, so a refactor can't silently regress the "target reachable before
# GO" verdict (the sprayshed/smoke-leash discipline). Asserts (1) the verdict table self-test, and
# (2) that a bare, localhost-only --egress never touches a target and never emits a GO-blocking
# conflict. Cross-OS: picks a working python3/python/py. Run: tools/smoke-egress.sh
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PROBE="$ROOT/arsenal/probe.py"
FAIL=0

# Pick an interpreter that ACTUALLY runs (Windows ships a `python3` Store shim that prints a banner and
# exits without running code — validate via a stdout sentinel, not just exit status).
PY=""
for c in python3 python py; do
  command -v "$c" >/dev/null 2>&1 || continue
  if [ "$("$c" -c 'print("PYOK")' 2>/dev/null)" = "PYOK" ]; then PY="$c"; break; fi
done
[ -n "$PY" ] || { echo "SMOKE-EGRESS: FAIL (no working python3/python/py on PATH)"; exit 1; }
echo "python: $PY ($("$PY" --version 2>&1))"

echo "1) the egress verdict table self-test passes offline (expect rc=0)"
"$PY" "$PROBE" --self-test; RC=$?
echo "   rc=$RC"; [ "$RC" -eq 0 ] || { echo "   FAIL: verdict table regressed"; FAIL=1; }

echo "2) bare --egress is localhost-only: well-formed JSON, no target touched, never a conflict (expect rc=0)"
OUT="$("$PY" "$PROBE" --egress --json)"; RC=$?
echo "   rc=$RC (expect 0 — localhost-only never blocks GO)"
[ "$RC" -eq 0 ] || { echo "   FAIL: bare --egress returned nonzero"; FAIL=1; }
printf '%s' "$OUT" | "$PY" -c '
import sys, json
d = json.load(sys.stdin)
assert d["mode"] == "egress", d
assert d["checked_localhost_only"] is True, d
assert d["target"] is None, d                 # no target supplied
assert d["reach_detail"] is None, d           # => NO target connect happened (offline)
assert d["verdict"] in ("egress_ok", "warn"), d   # localhost-only can never be a GO-blocking conflict
print("   localhost-only JSON well-formed, no target connect: OK")
' || { echo "   FAIL: bare --egress JSON malformed or not localhost-only"; FAIL=1; }

echo "3) the bare --egress human output prints a verdict line and exits clean (expect rc=0)"
HUM="$("$PY" "$PROBE" --egress 2>&1)"; RC=$?
echo "   rc=$RC"
{ [ "$RC" -eq 0 ] && printf '%s' "$HUM" | grep -qiE '^egress:'; } \
  || { echo "   FAIL: human --egress line/exit wrong"; FAIL=1; }

[ "$FAIL" -eq 0 ] && echo "SMOKE-EGRESS: PASS" || { echo "SMOKE-EGRESS: FAIL"; exit 1; }
