#!/usr/bin/env bash
# Route a TARGET-FACING tool through the scope leash. Sources the target's leash.env, exports the
# proxy + mitm CA for every common runtime, then execs the command. Fail-closed if the CA is absent
# (leash not up). Use ONLY for tools that hit the TARGET (httpx, nuclei, katana, ffuf, dalfox,
# sqlmap, curl-to-target). Passive OSINT tools (subfinder, gau, tlsx, trufflehog on local files)
# talk to third-party APIs, NOT the target — run those WITHOUT this wrapper, or the leash 403s them
# as off-scope. Non-HTTP tools (nmap/naabu) don't honor a proxy — pin them with tools/guard.py.
#
# Usage: tools/leashed.sh <target_dir> <command> [args...]
#   e.g. tools/leashed.sh targets/acme bin/httpx -u https://app.acme.com -json
set -euo pipefail

TDIR="${1:?usage: leashed.sh <target_dir> <cmd> [args...]}"; shift
ENVFILE="$TDIR/leash.env"
[ -f "$ENVFILE" ] || { echo "leashed: no leash.env at $ENVFILE"; exit 2; }
set -a; . "$ENVFILE"; set +a

export HTTP_PROXY="http://127.0.0.1:8080" HTTPS_PROXY="http://127.0.0.1:8080"
export http_proxy="$HTTP_PROXY" https_proxy="$HTTPS_PROXY"

CA="${MITM_CA:-$HOME/.mitmproxy/mitmproxy-ca-cert.pem}"
[ -f "$CA" ] || { echo "leashed: mitm CA missing at $CA — start the leash first (fail-closed)"; exit 3; }
export NODE_EXTRA_CA_CERTS="$CA" REQUESTS_CA_BUNDLE="$CA" CURL_CA_BUNDLE="$CA" SSL_CERT_FILE="$CA"

exec "$@"
