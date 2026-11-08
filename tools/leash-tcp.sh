#!/usr/bin/env bash
# Scope audit for NON-HTTP target tools (SMTP/IMAP/DB/etc.) that the HTTP leash (mitmproxy) can't see.
# It validates the destination host against the target's scope (via guard.py), logs the connection to
# raw/leash-tcp.jsonl, then execs the tool. This is the enforcement point that lets SMTP/non-HTTP
# lenses run WITHOUT leaving scope control. Fail-closed: off-scope host => refuse.
#
# Usage: tools/leash-tcp.sh <target_dir> <dst-host> <cmd> [args...]
#   e.g. tools/leash-tcp.sh targets/acme mail.acme.com bin/swaks --to test@acme.com --server mail.acme.com
set -euo pipefail

TDIR="${1:?usage: leash-tcp.sh <target_dir> <dst-host> <cmd> [args...]}"
HOST="${2:?dst host required}"; shift 2
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ENVFILE="$TDIR/leash.env"
[ -f "$ENVFILE" ] || { echo "leash-tcp: no leash.env at $ENVFILE"; exit 2; }
set -a; . "$ENVFILE"; set +a
: "${LEASH_SCOPE:?leash-tcp: LEASH_SCOPE missing (fail-closed)}"

EXTRA=""; [ "${LEASH_EXACT:-1}" = "1" ] || EXTRA="--allow-subdomains"
if ! python "$ROOT/tools/guard.py" --scope "$LEASH_SCOPE" $EXTRA --check "$HOST" >/dev/null 2>&1; then
  echo "leash-tcp: $HOST is OUT OF SCOPE — refusing (fail-closed)"; exit 3
fi

LOG="$TDIR/raw/leash-tcp.jsonl"; mkdir -p "$(dirname "$LOG")"
printf '{"ts":"%s","host":"%s","cmd":"%s"}\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$HOST" "$*" >> "$LOG"

exec "$@"
