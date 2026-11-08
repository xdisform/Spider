#!/usr/bin/env bash
# Supervised scope leash: keep mitmdump up across a long phase, restart it if it dies.
# Same addon/config as start-leash.sh (sources leash.env, appends to the same audit log),
# but survives a crash so a long fleet phase never silently loses the leash.
# Usage: tools/leash-supervise.sh targets/<t>/leash.env
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ENVFILE="${1:?usage: leash-supervise.sh <leash.env>}"
[ -f "$ENVFILE" ] || { echo "leash: no env file at $ENVFILE"; exit 2; }
set -a; . "$ENVFILE"; set +a
: "${X_BUGBOUNTY_TOKEN:?leash: X_BUGBOUNTY_TOKEN missing — refusing to start (fail-closed)}"
: "${LEASH_SCOPE:?leash: LEASH_SCOPE missing — refusing to start (fail-closed)}"
MITM="$ROOT/bin/.pyenv/Scripts/mitmdump.exe"
[ -f "$MITM" ] || MITM="$(command -v mitmdump || true)"
[ -n "$MITM" ] || { echo "leash: mitmdump not found"; exit 3; }

echo "leash-supervise: up on 127.0.0.1:8080 header=${LEASH_HEADER:-X-Bug-Bounty} rps=${LEASH_RPS:-5} exact=${LEASH_EXACT:-1}"
n=0
while true; do
  n=$((n+1))
  echo "[leash] start #$n $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  "$MITM" -s "$ROOT/tools/leash.py" --listen-host 127.0.0.1 --listen-port 8080 --ssl-insecure -q
  code=$?
  echo "[leash] mitmdump exited code=$code — restarting"
  python -c "import time; time.sleep(2)" 2>/dev/null || true
done
