#!/usr/bin/env bash
# Execute every workflow script end-to-end with mocked agents to catch runtime control-flow bugs that
# `node --check` cannot (it only parses). Caught a real `CLIENT_SIDE is not defined` in attack.mjs's
# validator, 2026-11. No target traffic. Run: tools/smoke-workflows.sh   (RUNS=N for more random coverage)
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
command -v node >/dev/null 2>&1 || { echo "smoke-workflows: node not found on PATH"; exit 3; }
echo "Executing workflows with mocked agents (RUNS=${RUNS:-6} random branches each for attack/chain)..."
node "$ROOT/tools/smoke-workflows.mjs"
