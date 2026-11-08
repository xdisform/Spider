#!/usr/bin/env bash
# Offline proof that leash-sock.py enforces its safety controls (P5): fail-closed when disabled,
# off-scope refusal, proto/port allow-list, a full transcript, and the flood caps (frames + session-time).
# No target traffic — the only socket is a Python-stdlib loopback echo server this script starts itself,
# so the controls can't silently regress (the sprayshed/pacing lesson applied to the held socket).
# Run: tools/smoke-sock.sh
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TDIR="$(mktemp -d)"; OFFDIR="$(mktemp -d)"
ECHO_PID=""
cleanup() { [ -n "$ECHO_PID" ] && kill "$ECHO_PID" 2>/dev/null; rm -rf "$TDIR" "$OFFDIR"; }
trap cleanup EXIT
mkdir -p "$TDIR/raw" "$OFFDIR/raw"
FAIL=0
LS() { python "$ROOT/tools/leash-sock.py" "$@" >/dev/null 2>&1; }
dir_count() { local n; n=$(grep -c "\"dir\":\"$2\"" "$1" 2>/dev/null); echo "${n:-0}"; }
limit_count() { local n; n=$(grep -c "\"dir\":\"limit\",.*\"printable\":\"$2\"" "$1" 2>/dev/null); echo "${n:-0}"; }

# --- stdlib loopback echo server (ephemeral port -> $TDIR/echo.port) --------------------------------
cat > "$TDIR/echo.py" <<'PY'
import socket, sys, threading
srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", 0))
srv.listen(16)
with open(sys.argv[1], "w") as f:
    f.write(str(srv.getsockname()[1]))
def handle(c):
    f = c.makefile("rwb")
    for line in f:          # line-oriented echo
        f.write(line); f.flush()
    c.close()
while True:
    conn, _ = srv.accept()
    threading.Thread(target=handle, args=(conn,), daemon=True).start()
PY
python "$TDIR/echo.py" "$TDIR/echo.port" & ECHO_PID=$!
for _ in $(seq 1 50); do [ -s "$TDIR/echo.port" ] && break; sleep 0.1; done
PORT="$(cat "$TDIR/echo.port" 2>/dev/null)"
[ -n "$PORT" ] || { echo "SMOKE-SOCK: FAIL (echo server did not start)"; exit 1; }
echo "   loopback echo server on 127.0.0.1:$PORT"

# ===================================================================================================
echo "1) fail-closed when policy disabled (expect rc=4)"
cat > "$OFFDIR/leash.env" <<EOF
LEASH_SCOPE=127.0.0.1
LEASH_SOCK_ENABLED=0
EOF
LS "$OFFDIR" 127.0.0.1 "$PORT" --proto tcp; RC=$?
echo "   rc=$RC"; [ "$RC" -eq 4 ] || { echo "   FAIL: not fail-closed"; FAIL=1; }

# a green leash.env for the enabled cases (short idle so a stall fails fast instead of hanging) --------
GREEN=$(cat <<EOF
LEASH_SCOPE=127.0.0.1
LEASH_EXACT=1
LEASH_SOCK_ENABLED=1
LEASH_SOCK_PROTOS=tcp,tls,ws,wss,pty
LEASH_SOCK_IDLE_TIMEOUT_S=3
EOF
)

echo "2) off-scope host refused (expect rc=3)"
printf '%s\n' "$GREEN" > "$TDIR/leash.env"
LS "$TDIR" 10.99.99.99 "$PORT" --proto tcp; RC=$?
echo "   rc=$RC"; [ "$RC" -eq 3 ] || { echo "   FAIL: off-scope not refused"; FAIL=1; }

echo "3a) proto not on the allow-list refused (expect rc=5)"
printf '%s\n' "LEASH_SCOPE=127.0.0.1" "LEASH_SOCK_ENABLED=1" "LEASH_SOCK_PROTOS=tcp" > "$TDIR/leash.env"
LS "$TDIR" 127.0.0.1 "$PORT" --proto ws; RC=$?
echo "   rc=$RC"; [ "$RC" -eq 5 ] || { echo "   FAIL: proto allow-list not enforced"; FAIL=1; }

echo "3b) port not on the allow-list refused (expect rc=5)"
printf '%s\n' "LEASH_SCOPE=127.0.0.1" "LEASH_SOCK_ENABLED=1" "LEASH_SOCK_PROTOS=tcp" "LEASH_SOCK_PORTS=9999" > "$TDIR/leash.env"
LS "$TDIR" 127.0.0.1 "$PORT" --proto tcp; RC=$?
echo "   rc=$RC"; [ "$RC" -eq 5 ] || { echo "   FAIL: port allow-list not enforced"; FAIL=1; }

echo "4) a held conversation writes a transcript with matching send/recv frame counts (expect rc=0, 3+3)"
printf '%s\n' "$GREEN" > "$TDIR/leash.env"
cat > "$TDIR/c4.expect" <<'EOF'
send alpha
recvline
send bravo
recvline
send charlie
recvline
EOF
LS "$TDIR" 127.0.0.1 "$PORT" --proto tcp --script "$TDIR/c4.expect" --label t4; RC=$?
T4="$(ls "$TDIR"/raw/t4/sock-tcp-*.jsonl 2>/dev/null | head -1)"
S=0; R=0
[ -n "$T4" ] && { S=$(dir_count "$T4" send); R=$(dir_count "$T4" recv); }
echo "   rc=$RC transcript=$([ -n "$T4" ] && echo yes || echo NO) send=$S recv=$R (expect rc=0, send=3, recv=3)"
{ [ "$RC" -eq 0 ] && [ -n "$T4" ] && [ "$S" -eq 3 ] && [ "$R" -eq 3 ]; } || { echo "   FAIL: transcript/frame-count wrong"; FAIL=1; }

echo "5) the frame cap trips (max_frames=6, 4 send/recv pairs => rc=7 + a limit event)"
printf '%s\n%s\n' "$GREEN" "LEASH_SOCK_MAX_FRAMES=6" > "$TDIR/leash.env"
cat > "$TDIR/c5.expect" <<'EOF'
send a
recvline
send b
recvline
send c
recvline
send d
recvline
EOF
LS "$TDIR" 127.0.0.1 "$PORT" --proto tcp --script "$TDIR/c5.expect" --label t5; RC=$?
T5="$(ls "$TDIR"/raw/t5/sock-tcp-*.jsonl 2>/dev/null | head -1)"
LIM=0; [ -n "$T5" ] && LIM=$(limit_count "$T5" max_frames)
echo "   rc=$RC limit-events(max_frames)=$LIM (expect rc=7, >=1)"
{ [ "$RC" -eq 7 ] && [ "$LIM" -ge 1 ]; } || { echo "   FAIL: frame cap not enforced"; FAIL=1; }

echo "6) the session-time cap trips (max_session_s=1, sleep 2 mid-convo => rc=7 + a limit event)"
printf '%s\n%s\n' "$GREEN" "LEASH_SOCK_MAX_SESSION_S=1" > "$TDIR/leash.env"
cat > "$TDIR/c6.expect" <<'EOF'
send a
recvline
sleep 2
send b
EOF
LS "$TDIR" 127.0.0.1 "$PORT" --proto tcp --script "$TDIR/c6.expect" --label t6; RC=$?
T6="$(ls "$TDIR"/raw/t6/sock-tcp-*.jsonl 2>/dev/null | head -1)"
LIM=0; [ -n "$T6" ] && LIM=$(limit_count "$T6" max_session_s)
echo "   rc=$RC limit-events(max_session_s)=$LIM (expect rc=7, >=1)"
{ [ "$RC" -eq 7 ] && [ "$LIM" -ge 1 ]; } || { echo "   FAIL: session-time cap not enforced"; FAIL=1; }

[ "$FAIL" -eq 0 ] && echo "SMOKE-SOCK: PASS" || { echo "SMOKE-SOCK: FAIL"; exit 1; }
