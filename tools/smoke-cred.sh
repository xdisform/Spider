#!/usr/bin/env bash
# Offline proof that leash-cred.sh enforces its safety controls (F5): fail-closed when disabled,
# inter-attempt pacing, and the per-principal attempt cap. No target traffic — runs `true` through the
# wrapper in self-test mode, so pacing/cap can't silently regress. Run: tools/smoke-cred.sh
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TDIR="$(mktemp -d)"; OFFDIR="$(mktemp -d)"; trap 'rm -rf "$TDIR" "$OFFDIR"' EXIT
mkdir -p "$TDIR/raw" "$OFFDIR/raw"
export LEASH_CRED_SELFTEST=1
FAIL=0
LC() { bash "$ROOT/tools/leash-cred.sh" "$@" >/dev/null 2>&1; }

cat > "$OFFDIR/leash.env" <<'EOF'
LEASH_SCOPE=127.0.0.1
LEASH_CRED_ENABLED=0
EOF
echo "1) fail-closed when policy disabled (expect rc=4)"
LC "$OFFDIR" 127.0.0.1 root true; RC1=$?
echo "   rc=$RC1"; [ "$RC1" -eq 4 ] || { echo "   FAIL: not fail-closed"; FAIL=1; }

cat > "$TDIR/leash.env" <<'EOF'
LEASH_SCOPE=127.0.0.1
LEASH_CRED_ENABLED=1
LEASH_CRED_DELAY_S=2
LEASH_CRED_JITTER_S=0
LEASH_CRED_MAX_TRIES_PER_PRINCIPAL=2
EOF

echo "2) first attempt allowed; second is paced >= delay (gap BETWEEN ledger records)"
LC "$TDIR" 127.0.0.1 root true; echo "   attempt 1 rc=$?"
LC "$TDIR" 127.0.0.1 root true; RC2=$?
# the pacing contract = >= DELAY_S between consecutive attempt records to the host, read from the ledger
mapfile -t EP < <(grep '"principal":"root"' "$TDIR/raw/cred-ledger.jsonl" | sed -n 's/.*"epoch":\([0-9]*\).*/\1/p')
GAP=$(( ${EP[1]:-0} - ${EP[0]:-0} ))
echo "   attempt 2 rc=$RC2 ledger-gap=${GAP}s (expect rc=0, >= 2)"
{ [ "$RC2" -eq 0 ] && [ "$GAP" -ge 2 ]; } || { echo "   FAIL: pacing/allow wrong"; FAIL=1; }

echo "3) third attempt to same principal hits the cap (expect rc=6)"
LC "$TDIR" 127.0.0.1 root true; RC3=$?
echo "   attempt 3 rc=$RC3"; [ "$RC3" -eq 6 ] || { echo "   FAIL: per-principal cap not enforced"; FAIL=1; }

echo "4) a DIFFERENT principal is independent (expect rc=0)"
LC "$TDIR" 127.0.0.1 admin true; RC4=$?
echo "   admin attempt 1 rc=$RC4"; [ "$RC4" -eq 0 ] || { echo "   FAIL: cap leaked across principals"; FAIL=1; }

echo "5) ledger recorded root's attempts"
N=$(grep -c '"principal":"root"' "$TDIR/raw/cred-ledger.jsonl" 2>/dev/null || echo 0)
echo "   ledger attempt lines for root: $N (expect 2)"; [ "$N" -eq 2 ] || { echo "   FAIL: ledger count wrong"; FAIL=1; }

[ "$FAIL" -eq 0 ] && echo "SMOKE-CRED: PASS" || { echo "SMOKE-CRED: FAIL"; exit 1; }
