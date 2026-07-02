#!/usr/bin/env bash
# Generate a Groth16 proof for an input.json.
# Usage: scripts/prove.sh <input.json> [small|medium] [out_dir]
set -euo pipefail
cd "$(dirname "$0")/.."

INPUT="${1:?usage: prove.sh <input.json> [variant] [out_dir]}"
VARIANT="${2:-small}"
OUTDIR="${3:-build/proofs}"
NAME="filter_and_tally_${VARIANT}"
OUT="build/circuits"
SNARKJS="node node_modules/snarkjs/cli.js"
mkdir -p "$OUTDIR"

node "$OUT/${NAME}_js/generate_witness.js" "$OUT/${NAME}_js/${NAME}.wasm" \
    "$INPUT" "$OUTDIR/witness.wtns"
$SNARKJS groth16 prove "$OUT/${NAME}.zkey" "$OUTDIR/witness.wtns" \
    "$OUTDIR/proof.json" "$OUTDIR/public.json"

echo "OK: $OUTDIR/proof.json $OUTDIR/public.json"
