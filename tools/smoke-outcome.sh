#!/usr/bin/env bash
# Offline proof that the outcome recorder (fix3 B6) holds its honesty + learning contract. No target
# traffic, no network: the recorder writes/reads operator-attested records on a temp dir and the roll-up
# is a pure projection (mirrors tools/smoke-payout.sh / smoke-cred.sh).
# Proves: (1) the comprehensive --self-test; (2) a record with no attested outcome stays `pending`, never
# paid; (3) a `resolved` record lands in techniques_delta and a `duplicate` in dead_paths_delta carrying
# its dup_ref; (4) the acceptance prior IS the HackerOne-Signal formula on a fixed fixture (dup+pending
# excluded) and `unknown` at n=0; (5) `--pull` without the operator's token FAILS CLOSED (exit 5) and
# never submits; (6) source honesty — an 'inferred' outcome is rejected on --write. Run: tools/smoke-outcome.sh
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PYTHON:-python}"
REC="$ROOT/tools/outcome-record.py"
TDIR="$(mktemp -d)"; trap 'rm -rf "$TDIR"' EXIT
mkdir -p "$TDIR/acme"
FAIL=0

# make sure no operator token leaks in from the environment (the fail-closed test depends on it).
unset HACKERONE_API_USERNAME HACKERONE_API_TOKEN 2>/dev/null || true

W() { "$PY" "$REC" --write --target-dir "$TDIR/acme" --record - "$@"; }   # record JSON on stdin

echo "1) outcome-record.py --self-test (expect exit 0 + self-test: OK)"
OUT1="$("$PY" "$REC" --self-test 2>&1)"; RC1=$?
echo "   $OUT1"
{ [ "$RC1" -eq 0 ] && printf '%s' "$OUT1" | grep -q "self-test: OK"; } \
  || { echo "   FAIL: self-test"; FAIL=1; }

echo "2) a record with no attested outcome stays 'pending' (never auto-promoted to paid)"
OUT2="$(printf '%s' '{"finding_id":"f-0001","target":"acme","program":"Acme BB","platform":"private","state":"submitted"}' | W 2>&1)"; RC2=$?
{ [ "$RC2" -eq 0 ] && printf '%s' "$OUT2" | grep -q '"outcome": "pending"'; } \
  || { echo "   FAIL: empty outcome not defaulted to pending"; echo "$OUT2"; FAIL=1; }

echo "3) a 'resolved' -> techniques_delta; a 'duplicate' -> dead_paths_delta carrying dup_ref"
printf '%s' '{"finding_id":"f-0007","target":"acme","program":"Acme BB","platform":"hackerone","class":"IDOR","host":"app.acme.com","root_cause":"missing object-level authz on GET /export/{id}","state":"closed","outcome":"resolved","report_ref":"h1#1234567"}' | W >/dev/null 2>&1
printf '%s' '{"finding_id":"f-0008","target":"acme","program":"Acme BB","platform":"hackerone","class":"XSS","host":"app.acme.com","state":"closed","outcome":"duplicate","report_ref":"h1#2222222","dup_ref":"h1#1111111"}' | W >/dev/null 2>&1
OUT3="$("$PY" "$REC" --roll-up --target-dir "$TDIR/acme" 2>&1)"; RC3=$?
{ [ "$RC3" -eq 0 ] \
  && printf '%s' "$OUT3" | grep -q '"techniques_delta"' \
  && printf '%s' "$OUT3" | grep -q '"outcome": "resolved"' \
  && printf '%s' "$OUT3" | grep -q '"dead_paths_delta"' \
  && printf '%s' "$OUT3" | grep -q '"ref": "h1#1111111"'; } \
  || { echo "   FAIL: resolved/duplicate not projected correctly"; echo "$OUT3"; FAIL=1; }

echo "4) the acceptance prior IS the Signal formula on a fixed fixture (dup+pending excluded)"
# fixture dir: 2 resolved (+7,+7), 1 informative (0), 1 not-applicable (-5), 1 duplicate (excluded),
#              1 pending (excluded) -> n=4, value=(7+7+0-5)/4 = 2.25
mkdir -p "$TDIR/fix"
A() { "$PY" "$REC" --write --target-dir "$TDIR/fix" --record - >/dev/null 2>&1; }
printf '%s' '{"finding_id":"f-0001","target":"t","program":"P","platform":"hackerone","state":"closed","outcome":"resolved","report_ref":"h1#1"}' | A
printf '%s' '{"finding_id":"f-0002","target":"t","program":"P","platform":"hackerone","state":"closed","outcome":"resolved","report_ref":"h1#2"}' | A
printf '%s' '{"finding_id":"f-0003","target":"t","program":"P","platform":"hackerone","state":"closed","outcome":"informative","report_ref":"h1#3"}' | A
printf '%s' '{"finding_id":"f-0004","target":"t","program":"P","platform":"hackerone","state":"closed","outcome":"not-applicable","report_ref":"h1#4"}' | A
printf '%s' '{"finding_id":"f-0005","target":"t","program":"P","platform":"hackerone","state":"closed","outcome":"duplicate","report_ref":"h1#5","dup_ref":"h1#0"}' | A
printf '%s' '{"finding_id":"f-0006","target":"t","program":"P","platform":"private","state":"submitted","outcome":"pending"}' | A
OUT4="$("$PY" "$REC" --roll-up --target-dir "$TDIR/fix" 2>&1)"
{ printf '%s' "$OUT4" | grep -q '"n": 4' \
  && printf '%s' "$OUT4" | grep -q '"value": 2.25' \
  && printf '%s' "$OUT4" | grep -q '"unknown": false'; } \
  || { echo "   FAIL: acceptance prior != Signal formula (expect n=4 value=2.25)"; echo "$OUT4"; FAIL=1; }
# n=0 -> unknown
OUT4b="$("$PY" "$REC" --roll-up --target-dir "$TDIR/empty" 2>&1)" || true
mkdir -p "$TDIR/empty"
OUT4b="$("$PY" "$REC" --roll-up --target-dir "$TDIR/empty" 2>&1)"
{ printf '%s' "$OUT4b" | grep -q '"unknown": true' \
  && printf '%s' "$OUT4b" | grep -q '"status": null'; } \
  || { echo "   FAIL: n=0 prior not unknown / empty status not null"; echo "$OUT4b"; FAIL=1; }

echo "5) --pull without the operator's token FAILS CLOSED (expect exit 5), submits nothing"
OUT5="$("$PY" "$REC" --pull --platform hackerone --target-dir "$TDIR/acme" 2>&1)"; RC5=$?
echo "   rc=$RC5"
{ [ "$RC5" -eq 5 ] && printf '%s' "$OUT5" | grep -q "fail-closed"; } \
  || { echo "   FAIL: --pull did not fail closed without a token"; echo "$OUT5"; FAIL=1; }

echo "6) source honesty — an 'inferred' outcome is rejected on --write (expect non-zero)"
OUT6="$(printf '%s' '{"finding_id":"f-0010","target":"acme","program":"Acme BB","platform":"hackerone","state":"closed","outcome":"resolved","report_ref":"h1#9"}' | "$PY" "$REC" --write --target-dir "$TDIR/acme" --record - --source inferred 2>&1)"; RC6=$?
echo "   rc=$RC6"
{ [ "$RC6" -ne 0 ] && printf '%s' "$OUT6" | grep -qi "source"; } \
  || { echo "   FAIL: 'inferred' source was not rejected"; echo "$OUT6"; FAIL=1; }

[ "$FAIL" -eq 0 ] && echo "SMOKE-OUTCOME: PASS" || { echo "SMOKE-OUTCOME: FAIL"; exit 1; }
