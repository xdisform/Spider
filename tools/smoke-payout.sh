#!/usr/bin/env bash
# Offline proof that the payout-readiness gate (fix3 B2) holds its contract — it FAILS CLOSED on every
# unmet sub-gate and only declares payout_ready when all six hold. No target traffic: the gate is a
# read-only projection over a crafted finding + scope (mirrors tools/smoke-cred.sh / smoke-corpus.sh).
# Proves: (1) the comprehensive --self-test; (2) full-pass => payout_ready:true, distance report-ready;
# (3) no CVSS vector => blocked; (4) out-of-scope host => NEVER payout_ready (scope is a hard AND term);
# (5) tier below the pay floor => blocked, never inflated; (6) could-not-verify => caps at severity-graded,
# never cleared/novel; (7) --fail-unless-ready exits 3 on a blocked finding. Run: tools/smoke-payout.sh
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PYTHON:-python}"
GATE="$ROOT/tools/payout-gate.py"
TDIR="$(mktemp -d)"; trap 'rm -rf "$TDIR"' EXIT
FAIL=0

# G() runs the gate on a finding file against our scope; prints JSON to stdout, rc in $?.
G() { "$PY" "$GATE" --finding "$1" --scope "$TDIR/scope.yaml"; }

cat > "$TDIR/scope.yaml" <<'EOF'
target: acme
scope_exact: true
hosts:
  - host: app.acme.com
    ip: 203.0.113.10
out_of_scope: [status.acme.com]
objective:
  mode: bounty
  min_payable_tier: P3
  novelty:
    waive_unverified: false
EOF

# a fully-payable finding (in scope, oracle-proven, eligible, P2 >= P3 floor, novel, report-complete)
cat > "$TDIR/full.json" <<'EOF'
{"id":"f-0001","target":"app.acme.com","type":"IDOR","verified":true,"refuted":false,
 "oracle_type":"idor-cross-account","eligibility":"payable",
 "cvss_vector":"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N","tier":"P2","novelty":"novel",
 "repro":"1. GET /export/2 as user A returns user B's record","poc_path":"raw/attack-h-01/poc.sh",
 "detail":"missing object-level authz on GET /export/{id}","cwe":["CWE-639"]}
EOF

echo "1) payout-gate.py --self-test (expect exit 0 + self-test: OK)"
OUT1="$("$PY" "$GATE" --self-test 2>&1)"; RC1=$?
echo "   $OUT1"
{ [ "$RC1" -eq 0 ] && printf '%s' "$OUT1" | grep -q "self-test: OK"; } \
  || { echo "   FAIL: self-test"; FAIL=1; }

echo "2) full pass => payout_ready:true, distance report-ready (expect rc=0)"
OUT2="$(G "$TDIR/full.json")"; RC2=$?
{ [ "$RC2" -eq 0 ] \
  && printf '%s' "$OUT2" | grep -q '"payout_ready": true' \
  && printf '%s' "$OUT2" | grep -q '"payout_distance": "report-ready"'; } \
  || { echo "   FAIL: full-pass finding was not payout_ready/report-ready"; echo "$OUT2"; FAIL=1; }

echo "3) no CVSS vector => blocked on tier (fail-closed, not an assumed tier)"
"$PY" - "$TDIR" <<'PY'
import json,sys,pathlib
t=pathlib.Path(sys.argv[1]); d=json.loads((t/"full.json").read_text()); d["cvss_vector"]=""
(t/"nocvss.json").write_text(json.dumps(d))
PY
OUT3="$(G "$TDIR/nocvss.json")"
{ printf '%s' "$OUT3" | grep -q '"payout_ready": false' \
  && printf '%s' "$OUT3" | grep -q 'tier: no CVSS vector'; } \
  || { echo "   FAIL: missing CVSS vector was not blocked"; echo "$OUT3"; FAIL=1; }

echo "4) out-of-scope host => NEVER payout_ready (scope is a hard AND term)"
"$PY" - "$TDIR" <<'PY'
import json,sys,pathlib
t=pathlib.Path(sys.argv[1]); d=json.loads((t/"full.json").read_text()); d["target"]="evil.example.com"
(t/"oos.json").write_text(json.dumps(d))
PY
OUT4="$(G "$TDIR/oos.json")"
{ printf '%s' "$OUT4" | grep -q '"payout_ready": false' \
  && printf '%s' "$OUT4" | grep -q '"blocker": "scope:'; } \
  || { echo "   FAIL: out-of-scope host was not blocked"; echo "$OUT4"; FAIL=1; }

echo "5) tier below the pay floor => blocked, tier NOT inflated (P4 < floor P3)"
"$PY" - "$TDIR" <<'PY'
import json,sys,pathlib
t=pathlib.Path(sys.argv[1]); d=json.loads((t/"full.json").read_text()); d["tier"]="P4"
(t/"lowtier.json").write_text(json.dumps(d))
PY
OUT5="$(G "$TDIR/lowtier.json")"
{ printf '%s' "$OUT5" | grep -q '"payout_ready": false' \
  && printf '%s' "$OUT5" | grep -q 'P4 below pay floor P3'; } \
  || { echo "   FAIL: below-floor tier was not blocked"; echo "$OUT5"; FAIL=1; }

echo "6) could-not-verify => caps at severity-graded, never cleared/novel"
"$PY" - "$TDIR" <<'PY'
import json,sys,pathlib
t=pathlib.Path(sys.argv[1]); d=json.loads((t/"full.json").read_text()); d["novelty"]="could-not-verify"
(t/"cnv.json").write_text(json.dumps(d))
PY
OUT6="$(G "$TDIR/cnv.json")"
{ printf '%s' "$OUT6" | grep -q '"payout_ready": false' \
  && printf '%s' "$OUT6" | grep -q '"payout_distance": "severity-graded"' \
  && printf '%s' "$OUT6" | grep -q 'could-not-verify'; } \
  || { echo "   FAIL: could-not-verify was not capped at severity-graded"; echo "$OUT6"; FAIL=1; }

echo "7) --fail-unless-ready exits 3 on a blocked finding, 0 on a ready one"
"$PY" "$GATE" --finding "$TDIR/lowtier.json" --scope "$TDIR/scope.yaml" --fail-unless-ready >/dev/null 2>&1; RC7a=$?
"$PY" "$GATE" --finding "$TDIR/full.json"    --scope "$TDIR/scope.yaml" --fail-unless-ready >/dev/null 2>&1; RC7b=$?
echo "   blocked rc=$RC7a (expect 3), ready rc=$RC7b (expect 0)"
{ [ "$RC7a" -eq 3 ] && [ "$RC7b" -eq 0 ]; } \
  || { echo "   FAIL: --fail-unless-ready exit codes wrong"; FAIL=1; }

[ "$FAIL" -eq 0 ] && echo "SMOKE-PAYOUT: PASS" || { echo "SMOKE-PAYOUT: FAIL"; exit 1; }
