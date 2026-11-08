#!/usr/bin/env bash
# Offline proof that the severity->tier->EV engine (fix3 B5) holds its contract: the CVSS score is the
# exact FIRST.org value, the tier is evidence-bound (never inflated to clear a pay floor), and the EV
# discounts are honest (could-not-verify never counts as novel, excluded is 0). No target traffic: the
# engine is a pure deterministic projection over a vector + metadata (mirrors tools/smoke-payout.sh /
# smoke-cred.sh). Proves: (1) the comprehensive --self-test (pins the CVSS reference vectors);
# (2) a known vector => the exact score; (3) monetary midpoint math; (4) a P4 under a P3 floor => EV 0,
# tier NOT inflated; (5) ordinal fallback (no reward_table) still gives a valid P1>P4 order;
# (6) could-not-verify dedup discounts EV x0.5 and is NEVER x1.0; (7) eligibility:excluded => EV 0;
# (8) a >1-band drift from the VRT priority flags needs_human_review (tier stays the evidence band);
# (9) an invalid vector fails closed (no assumed score). Run: tools/smoke-ev.sh
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PYTHON:-python}"
EV="$ROOT/tools/ev-score.py"
FAIL=0

# table used across the monetary checks (P1..P4 bands)
RT='{"currency":"USD","tiers":{"P1":[5000,20000],"P2":[2000,5000],"P3":[500,2000],"P4":[100,500]}}'
CRIT='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'   # 9.8 -> Critical -> P1
LOW='CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N'     # 1.8 -> Low      -> P4

# field <json> <python-index-expr> : print a single value from the tool's JSON, exactly (no grep ambiguity)
field() { printf '%s' "$1" | "$PY" -c "import json,sys;print(json.load(sys.stdin)$2)"; }

echo "1) ev-score.py --self-test (expect exit 0 + self-test: OK)"
OUT1="$("$PY" "$EV" --self-test 2>&1)"; RC1=$?
echo "   $OUT1"
{ [ "$RC1" -eq 0 ] && printf '%s' "$OUT1" | grep -q "self-test: OK"; } \
  || { echo "   FAIL: self-test"; FAIL=1; }

echo "2) known vector => exact CVSS score 9.8, band Critical, tier P1"
OUT2="$("$PY" "$EV" --vector "$CRIT" --reward-table "$RT" --dedup novel --eligibility payable)"
S2="$(field "$OUT2" "['cvss_score']")"; T2="$(field "$OUT2" "['tier']")"; B2="$(field "$OUT2" "['band']")"
echo "   score=$S2 band=$B2 tier=$T2"
{ [ "$S2" = "9.8" ] && [ "$B2" = "Critical" ] && [ "$T2" = "P1" ]; } \
  || { echo "   FAIL: wrong score/band/tier"; FAIL=1; }

echo "3) monetary mode => reward_value is the (min+max)/2 midpoint, EV = midpoint x 1.0 x 1.0"
RV3="$(field "$OUT2" "['ev_basis']['reward_value']")"; EV3="$(field "$OUT2" "['expected_value']")"
MODE3="$(field "$OUT2" "['ev_basis']['mode']")"; TR3="$(field "$OUT2" "['tier_reward']")"
echo "   mode=$MODE3 reward_value=$RV3 tier_reward=$TR3 EV=$EV3"
{ [ "$MODE3" = "monetary" ] && [ "$RV3" = "12500" ] && [ "$EV3" = "12500" ] && [ "$TR3" = "[5000, 20000]" ]; } \
  || { echo "   FAIL: monetary midpoint math wrong"; FAIL=1; }

echo "4) a P4 under a P3 pay floor => EV 0, tier NOT inflated (evidence-bound severity)"
OUT4="$("$PY" "$EV" --vector "$LOW" --reward-table "$RT" --dedup novel --eligibility payable --min-payable-tier P3)"
T4="$(field "$OUT4" "['tier']")"; EV4="$(field "$OUT4" "['expected_value']")"; BF4="$(field "$OUT4" "['below_pay_floor']")"
echo "   tier=$T4 below_pay_floor=$BF4 EV=$EV4"
{ [ "$T4" = "P4" ] && [ "$EV4" = "0" ] && [ "$BF4" = "True" ]; } \
  || { echo "   FAIL: below-floor tier was inflated or not zeroed"; FAIL=1; }

echo "5) ordinal fallback (no --reward-table) => a valid payout-maximizing order (P1 EV > P4 EV)"
O5A="$("$PY" "$EV" --vector "$CRIT" --dedup novel --eligibility payable)"
O5B="$("$PY" "$EV" --vector "$LOW"  --dedup novel --eligibility payable)"
M5="$(field "$O5A" "['ev_basis']['mode']")"; E5A="$(field "$O5A" "['expected_value']")"; E5B="$(field "$O5B" "['expected_value']")"
echo "   mode=$M5 P1_EV=$E5A P4_EV=$E5B"
{ [ "$M5" = "ordinal" ] && [ "$E5A" = "4" ] && [ "$E5B" = "1" ] \
  && "$PY" -c "import sys;sys.exit(0 if $E5A > $E5B else 1)"; } \
  || { echo "   FAIL: ordinal order wrong"; FAIL=1; }

echo "6) could-not-verify dedup => novelty_confidence 0.5 (NEVER 1.0); EV halved"
OUT6="$("$PY" "$EV" --vector "$CRIT" --reward-table "$RT" --dedup could-not-verify --eligibility payable)"
NC6="$(field "$OUT6" "['ev_basis']['novelty_confidence']")"; EV6="$(field "$OUT6" "['expected_value']")"
echo "   novelty_confidence=$NC6 EV=$EV6 (expect 0.5 / 6250, half of 12500)"
{ [ "$NC6" = "0.5" ] && [ "$EV6" = "6250" ]; } \
  || { echo "   FAIL: could-not-verify was not discounted honestly"; FAIL=1; }

echo "7) eligibility:excluded => eligibility_confidence 0.0, EV 0 (recorded, deprioritized, not deleted)"
OUT7="$("$PY" "$EV" --vector "$CRIT" --reward-table "$RT" --dedup novel --eligibility excluded)"
EC7="$(field "$OUT7" "['ev_basis']['eligibility_confidence']")"; EV7="$(field "$OUT7" "['expected_value']")"
echo "   eligibility_confidence=$EC7 EV=$EV7"
{ [ "$EC7" = "0.0" ] && [ "$EV7" = "0" ]; } \
  || { echo "   FAIL: excluded eligibility did not zero EV"; FAIL=1; }

echo "8) drift guardrail: a P1 evidence band vs a P4 VRT priority => needs_human_review, tier stays P1"
OUT8="$("$PY" "$EV" --vector "$CRIT" --reward-table "$RT" --dedup novel --eligibility payable --priority P4)"
HR8="$(field "$OUT8" "['needs_human_review']")"; T8="$(field "$OUT8" "['tier']")"; D8="$(field "$OUT8" "['cvss_vs_priority_drift']")"
echo "   tier=$T8 drift=$D8 needs_human_review=$HR8"
{ [ "$HR8" = "True" ] && [ "$T8" = "P1" ] && [ "$D8" = "3" ]; } \
  || { echo "   FAIL: drift guardrail wrong (tier must stay the evidence band)"; FAIL=1; }

echo "9) an invalid CVSS vector fails closed (exit 2, no assumed score)"
"$PY" "$EV" --vector 'not-a-vector' >/dev/null 2>&1; RC9=$?
echo "   invalid-vector rc=$RC9 (expect 2)"
{ [ "$RC9" -eq 2 ]; } \
  || { echo "   FAIL: invalid vector did not fail closed"; FAIL=1; }

[ "$FAIL" -eq 0 ] && echo "SMOKE-EV: PASS" || { echo "SMOKE-EV: FAIL"; exit 1; }
