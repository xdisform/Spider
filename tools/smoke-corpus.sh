#!/usr/bin/env bash
# Offline proof that the fix3 senior-brain G-tools hold their contracts: corpus_index.py validates +
# asserts class-domain, and retrieve.py filters patched-instances / down-weights OMITTED / honors top-K.
# No corpus on disk required and NO target traffic — both tools run their in-memory --self-test. Run: tools/smoke-corpus.sh
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PYTHON:-python}"
FAIL=0

echo "1) corpus_index.py --self-test (expect exit 0 + SELF-TEST OK)"
OUT1="$("$PY" "$ROOT/tools/corpus_index.py" --self-test 2>&1)"; RC1=$?
echo "   $OUT1"
{ [ "$RC1" -eq 0 ] && printf '%s' "$OUT1" | grep -q "SELF-TEST OK"; } \
  || { echo "   FAIL: corpus_index self-test"; FAIL=1; }

echo "2) retrieve.py --self-test (expect exit 0 + SELF-TEST OK)"
OUT2="$("$PY" "$ROOT/tools/retrieve.py" --self-test 2>&1)"; RC2=$?
echo "   $OUT2"
{ [ "$RC2" -eq 0 ] && printf '%s' "$OUT2" | grep -q "SELF-TEST OK"; } \
  || { echo "   FAIL: retrieve self-test"; FAIL=1; }

[ "$FAIL" -eq 0 ] && echo "SMOKE-CORPUS: PASS" || { echo "SMOKE-CORPUS: FAIL"; exit 1; }
