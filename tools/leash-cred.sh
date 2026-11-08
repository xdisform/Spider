#!/usr/bin/env bash
# Scope + SAFETY enforcer for the default-cred CONTROL-TEST (F5). Sibling of leash-tcp.sh, but adds the
# controls that make a credential spray a control-test instead of a brute-force:
#   - fail-closed unless policies.default_cred_control_test.enabled (LEASH_CRED_ENABLED=1)
#   - host-pin + cred-mode guard via guard.py (rejects brute flags, oversized sets, CIDR targets)
#   - a per-(host,principal) attempt ledger capped at max_tries_per_principal
#   - explicit inter-attempt delay + jitter, burst = 1 (NOT a token bucket)
#   - lockout/throttle detection on the tool's output -> stop + back off + exit non-zero
#   - every attempt logged to raw/cred-ledger.jsonl
#
# Usage: tools/leash-cred.sh <target_dir> <dst-host> <principal> <cmd> [args...]
#   e.g. tools/leash-cred.sh targets/acme 10.0.0.5 root bin/nuclei -t bin/.nuclei/default-logins -u ssh://10.0.0.5
# Self-test (offline, no target): LEASH_CRED_SELFTEST=1 tools/leash-cred.sh <target_dir> <host> <principal> true
set -uo pipefail

TDIR="${1:?usage: leash-cred.sh <target_dir> <dst-host> <principal> <cmd> [args...]}"
HOST="${2:?dst host required}"
PRINCIPAL="${3:?principal required (whose login is being control-tested)}"; shift 3
[ "$#" -ge 1 ] || { echo "leash-cred: no command given"; exit 2; }
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ENVFILE="$TDIR/leash.env"
[ -f "$ENVFILE" ] || { echo "leash-cred: no leash.env at $ENVFILE"; exit 2; }
set -a; . "$ENVFILE"; set +a
: "${LEASH_SCOPE:?leash-cred: LEASH_SCOPE missing (fail-closed)}"

# --- policy gate (fail-closed) ---------------------------------------------------------------------
[ "${LEASH_CRED_ENABLED:-0}" = "1" ] || {
  echo "leash-cred: policies.default_cred_control_test.enabled is OFF — refusing (fail-closed)"; exit 4; }
MAX_PAIRS="${LEASH_CRED_MAX_PAIRS:-20}"
DELAY_S="${LEASH_CRED_DELAY_S:-3}"
JITTER_S="${LEASH_CRED_JITTER_S:-2}"
MAX_TRIES="${LEASH_CRED_MAX_TRIES_PER_PRINCIPAL:-1}"
BACKOFF_S="${LEASH_CRED_LOCKOUT_BACKOFF_S:-300}"
LEDGER="$TDIR/raw/cred-ledger.jsonl"; mkdir -p "$(dirname "$LEDGER")"
NOW() { date -u +%s; }
STAMP() { date -u +%Y-%m-%dT%H:%M:%SZ; }

# --- host-pin + cred-mode guard (skip host-pin only in offline self-test) --------------------------
EXTRA=""; [ "${LEASH_EXACT:-1}" = "1" ] || EXTRA="--allow-subdomains"
if [ "${LEASH_CRED_SELFTEST:-0}" != "1" ]; then
  if ! python "$ROOT/tools/guard.py" --scope "$LEASH_SCOPE" $EXTRA --check "$HOST" >/dev/null 2>&1; then
    echo "leash-cred: $HOST is OUT OF SCOPE — refusing (fail-closed)"; exit 3
  fi
  if ! python "$ROOT/tools/guard.py" --scope "$LEASH_SCOPE" $EXTRA --cred-mode --max-pairs "$MAX_PAIRS" --check "$* $HOST" >/dev/null 2>&1; then
    echo "leash-cred: command rejected by cred-mode guard (brute flags / oversized set / range target)"; exit 5
  fi
fi

# --- per-(host,principal) attempt ledger cap -------------------------------------------------------
KEY="$HOST|$PRINCIPAL"
TRIES=0
if [ -f "$LEDGER" ]; then
  TRIES=$(grep -c "\"key\":\"$KEY\"" "$LEDGER" 2>/dev/null || echo 0)
fi
if [ "$TRIES" -ge "$MAX_TRIES" ]; then
  echo "leash-cred: $KEY already has $TRIES/$MAX_TRIES attempts — refusing (lockout-safe cap)"; exit 6
fi

# --- pace: explicit delay + jitter since the last attempt to this host (burst = 1) -----------------
LAST=0
if [ -f "$LEDGER" ]; then
  LAST=$(grep "\"host\":\"$HOST\"" "$LEDGER" 2>/dev/null | tail -1 | sed -n 's/.*"epoch":\([0-9]*\).*/\1/p')
  [ -n "$LAST" ] || LAST=0
fi
JITTER=$(( RANDOM % (JITTER_S + 1) ))
NEED=$(( DELAY_S + JITTER ))
ELAPSED=$(( $(NOW) - LAST ))
if [ "$LAST" -gt 0 ] && [ "$ELAPSED" -lt "$NEED" ]; then
  WAIT=$(( NEED - ELAPSED ))
  echo "leash-cred: pacing — waiting ${WAIT}s (delay=${DELAY_S}+jitter=${JITTER}, elapsed=${ELAPSED})"
  sleep "$WAIT"
fi

# --- record the attempt BEFORE running (so a crash can't hide it) ----------------------------------
printf '{"ts":"%s","epoch":%s,"key":"%s","host":"%s","principal":"%s","cmd":"%s"}\n' \
  "$(STAMP)" "$(NOW)" "$KEY" "$HOST" "$PRINCIPAL" "$*" >> "$LEDGER"

# --- run, capture output, scan for lockout/throttle ------------------------------------------------
OUT="$(mktemp)"; trap 'rm -f "$OUT"' EXIT
"$@" > "$OUT" 2>&1; RC=$?
cat "$OUT"
if grep -qiE 'lock(ed|out)|too many attempts|try again (later|in)|throttl|rate.?limit|429|account disabled|temporarily (locked|blocked)' "$OUT"; then
  printf '{"ts":"%s","epoch":%s,"host":"%s","event":"lockout","backoff_s":%s}\n' \
    "$(STAMP)" "$(NOW)" "$HOST" "$BACKOFF_S" >> "$LEDGER"
  echo "leash-cred: LOCKOUT/THROTTLE signal detected — stopping and backing off (${BACKOFF_S}s). This is a BLOCKED result, not 'no default cred'."
  exit 7
fi
exit "$RC"
