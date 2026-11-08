#!/usr/bin/env bash
# Bring the scope leash up. Reads targets/<t>/leash.env, refuses to start without a
# token + scope (fail-closed), and runs mitmdump on 127.0.0.1:8080.
#
# Usage: tools/start-leash.sh targets/<target>/leash.env
set -euo pipefail

ENVFILE="${1:?usage: start-leash.sh <path/to/leash.env>}"
[ -f "$ENVFILE" ] || { echo "leash: no env file at $ENVFILE"; exit 2; }

set -a; . "$ENVFILE"; set +a
# F1 — pick up an operator-supplied session next to leash.env (cookie/bearer/headers). Optional; SECRET.
SDIR="$(dirname "$ENVFILE")"; [ -f "$SDIR/session.env" ] && { echo "leash: sourcing operator session.env"; set -a; . "$SDIR/session.env"; set +a; }
: "${X_BUGBOUNTY_TOKEN:?leash: X_BUGBOUNTY_TOKEN missing — refusing to start (fail-closed)}"
: "${LEASH_SCOPE:?leash: LEASH_SCOPE missing — refusing to start (fail-closed)}"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# Resolve mitmdump: PATH first, then the provisioned locations under bin/ (this box ships a
# .pyenv venv binary + a .cmd shim, not a bare `mitmdump`). Prefer the real .exe.
MITM="$(command -v mitmdump || true)"
for cand in "$ROOT/bin/.pyenv/Scripts/mitmdump.exe" "$ROOT/bin/mitmdump.cmd" "$ROOT/bin/mitmdump"; do
  [ -n "$MITM" ] && break
  [ -f "$cand" ] && MITM="$cand"
done
[ -n "$MITM" ] || {
  echo "leash: mitmdump not found — run: python arsenal/provision.py --only mitmproxy (or pip install mitmproxy)"; exit 3; }

echo "leash: up on 127.0.0.1:8080  header=${LEASH_HEADER:-X-Bug-Bounty}  rps=${LEASH_RPS:-5}  exact=${LEASH_EXACT:-1}"
exec "$MITM" -s "$ROOT/tools/leash.py" --listen-host 127.0.0.1 --listen-port 8080 --ssl-insecure -q
