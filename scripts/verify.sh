#!/usr/bin/env bash
# Verify a Groth16 proof.
# Usage: scripts/verify.sh [proof.json] [public.json] [small|medium]
set -euo pipefail
cd "$(dirname "$0")/.."

PROOF="${1:-build/proofs/proof.json}"
PUBLIC="${2:-build/proofs/public.json}"
VARIANT="${3:-small}"
NAME="filter_and_tally_${VARIANT}"

node node_modules/snarkjs/cli.js groth16 verify \
    "build/circuits/${NAME}_verification_key.json" "$PUBLIC" "$PROOF"
