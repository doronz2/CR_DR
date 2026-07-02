#!/usr/bin/env bash
# Compile the FilterAndTally circuit variant to R1CS + wasm witness gen.
# Usage: scripts/compile_circuits.sh [small|medium]   (default: small)
set -euo pipefail
cd "$(dirname "$0")/.."

VARIANT="${1:-small}"
NAME="filter_and_tally_${VARIANT}"
OUT="build/circuits"
mkdir -p "$OUT"

circom "circuits/main/${NAME}.circom" --r1cs --wasm --sym -o "$OUT" -l node_modules

node node_modules/snarkjs/cli.js r1cs info "$OUT/${NAME}.r1cs"
echo "OK: compiled ${NAME} -> ${OUT}"
