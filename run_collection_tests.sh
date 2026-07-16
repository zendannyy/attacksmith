#!/usr/bin/env bash
# Test Orchestrator — run the full ATT&CKSMITH pipeline on demand
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

exec python3 run_collection_tests.py "$@"