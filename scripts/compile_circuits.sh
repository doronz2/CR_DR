#!/usr/bin/env bash
# Compile a FilterAndTally circuit variant to R1CS + wasm witness gen.
# Usage: scripts/compile_circuits.sh [small|small_naive|medium|medium_naive]
# (default: small). *_naive = Strategy A duplicates; others = Strategy B.
set -euo pipefail
cd "$(dirname "$0")/.."

VARIANT="${1:-small}"
NAME="filter_and_tally_${VARIANT}"
OUT="build/circuits"
mkdir -p "$OUT"

# Resolve a circom 2 compiler (a stale circom 0.5 may shadow it in PATH).
CIRCOM="${CIRCOM:-circom}"
if ! "$CIRCOM" --version 2>/dev/null | grep -q "circom compiler 2"; then
  if "$HOME/.cargo/bin/circom" --version 2>/dev/null | grep -q "circom compiler 2"; then
    CIRCOM="$HOME/.cargo/bin/circom"
  else
    echo "circom 2 not found (run scripts/install_circom_deps.sh)"; exit 1
  fi
fi

"$CIRCOM" "circuits/main/${NAME}.circom" --r1cs --wasm --sym -o "$OUT" -l node_modules

node node_modules/snarkjs/cli.js r1cs info "$OUT/${NAME}.r1cs"
echo "OK: compiled ${NAME} -> ${OUT}"
