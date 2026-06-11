#!/usr/bin/env bash
# One-command reproduction script for the LiteZero artefact evaluation.
#
# This script re-runs every experiment reported in the paper from a clean
# working tree and prints a pass/fail summary. It targets ACM reproducibility
# badges (Artifacts Available + Artifacts Evaluated — Reusable): deterministic
# seed, pinned Node version, text-only outputs, single entry point.
#
# Usage:
#   bash scripts/reproduce.sh
#
# Output directory: ./out/
#   - attack-log.txt          : PASS/FAIL for each of the 19 attack scenarios
#   - bench-node.{json,csv}   : microbenchmarks under Node
#   - bench-bun.{json,csv}    : microbenchmarks under Bun (skipped if absent)
#   - demo-log.txt            : successful single-session handshake log
#   - summary.txt             : top-level pass/fail digest
#
# Exit code: 0 if every attack is defended AND the full-handshake demo
# completes AND at least one runtime's benchmarks were collected.

set -euo pipefail

HERE=$(cd -- "$(dirname -- "$0")/.." && pwd)
cd "$HERE"
mkdir -p out

RED='\033[0;31m'; GREEN='\033[0;32m'; NC='\033[0m'
pass() { printf "${GREEN}PASS${NC}  %s\n" "$1" | tee -a out/summary.txt; }
fail() { printf "${RED}FAIL${NC}  %s\n" "$1" | tee -a out/summary.txt; }

: > out/summary.txt

echo "[reproduce] node=$(node --version) $(bun --version 2>/dev/null || echo 'bun: not installed')"

# Deterministic seed used for reproducible bench inputs (never for real keys;
# primitives.ts assertUnseeded() guards ephemeral ECDH and ECDSA key-gen).
export BENCH_SEED=${BENCH_SEED:-0xC0FFEE}

# --- 1) demo: a single successful handshake end-to-end ---
if node --experimental-transform-types --no-warnings scripts/run-demo.ts > out/demo-log.txt 2>&1; then
    pass "demo handshake"
else
    fail "demo handshake"
fi

# --- 2) attack battery: all 19 scenarios must be DEFENDED (40 runs each) ---
if node --experimental-transform-types --no-warnings scripts/run-attacks.ts > out/attack-log.txt 2>&1; then
    pass "attack battery (all 19 defended, 40 runs each)"
else
    fail "attack battery"
fi

# --- 3) microbenchmarks under Node ---
if BENCH_TRIALS=${BENCH_TRIALS:-10000} node --experimental-transform-types --no-warnings scripts/bench.ts > out/bench-node.log 2>&1; then
    pass "bench (Node)"
else
    fail "bench (Node)"
fi

# --- 4) microbenchmarks under Bun (optional) ---
if command -v bun >/dev/null 2>&1; then
    if BENCH_TRIALS=${BENCH_TRIALS:-10000} bun scripts/bench.ts > out/bench-bun.log 2>&1; then
        pass "bench (Bun)"
    else
        fail "bench (Bun)"
    fi
else
    echo "[reproduce] bun not installed — skipping Bun column (Table III)"
fi

echo "[reproduce] artefacts written to $HERE/out/"
grep -q '^FAIL' out/summary.txt && exit 1 || exit 0
