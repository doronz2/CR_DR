#!/usr/bin/env bash
# Groth16 setup for a compiled circuit variant.
#
# *** WARNING: DEV SETUP ONLY ***
# The powers-of-tau and the circuit-specific phase-2 are generated locally
# with no real ceremony. Anyone with the toxic waste can forge proofs.
# Never use these keys outside development. Groth16 setup is also
# circuit-specific: recompile => redo setup.
#
# Usage: scripts/setup_groth16.sh [small|medium]   (default: small)
set -euo pipefail
cd "$(dirname "$0")/.."

VARIANT="${1:-small}"
NAME="filter_and_tally_${VARIANT}"
OUT="build/circuits"
PTAU_DIR="build/ptau"
SNARKJS="node node_modules/snarkjs/cli.js"
mkdir -p "$PTAU_DIR"

[ -f "$OUT/${NAME}.r1cs" ] || { echo "run scripts/compile_circuits.sh ${VARIANT} first"; exit 1; }

# Pick the smallest power of tau whose domain fits the constraint count
# (snarkjs domain = next power of two >= constraints + public wires; the
# +512 slack covers the public wires without jumping a whole power).
CONSTRAINTS=$($SNARKJS r1cs info "$OUT/${NAME}.r1cs" | sed -n 's/.*# of Constraints: *//p' | tr -d '[:space:]')
POWER=12
while [ $((1 << POWER)) -lt $((CONSTRAINTS + 512)) ]; do POWER=$((POWER + 1)); done
echo "constraints: $CONSTRAINTS -> using power 2^$POWER"

PTAU_FINAL="$PTAU_DIR/pot${POWER}_final.ptau"
# A larger existing ptau works for any smaller circuit: reuse it.
if [ ! -f "$PTAU_FINAL" ]; then
  for BIGGER in $(seq $((POWER + 1)) 28); do
    if [ -f "$PTAU_DIR/pot${BIGGER}_final.ptau" ]; then
      PTAU_FINAL="$PTAU_DIR/pot${BIGGER}_final.ptau"
      echo "reusing existing pot${BIGGER}_final.ptau"
      break
    fi
  done
fi
if [ ! -f "$PTAU_FINAL" ]; then
  echo "Generating dev powers-of-tau 2^$POWER (single local contribution)..."
  $SNARKJS powersoftau new bn128 "$POWER" "$PTAU_DIR/pot${POWER}_0000.ptau" -v
  $SNARKJS powersoftau contribute "$PTAU_DIR/pot${POWER}_0000.ptau" \
      "$PTAU_DIR/pot${POWER}_0001.ptau" --name="dev contribution" -v \
      -e="cr-dr dev entropy $(date +%s)"
  $SNARKJS powersoftau prepare phase2 "$PTAU_DIR/pot${POWER}_0001.ptau" "$PTAU_FINAL" -v
  rm -f "$PTAU_DIR/pot${POWER}_0000.ptau" "$PTAU_DIR/pot${POWER}_0001.ptau"
fi

$SNARKJS groth16 setup "$OUT/${NAME}.r1cs" "$PTAU_FINAL" "$OUT/${NAME}_0000.zkey"
$SNARKJS zkey contribute "$OUT/${NAME}_0000.zkey" "$OUT/${NAME}.zkey" \
    --name="dev phase2 contribution" -v -e="cr-dr dev phase2 entropy $(date +%s)"
rm -f "$OUT/${NAME}_0000.zkey"
$SNARKJS zkey export verificationkey "$OUT/${NAME}.zkey" "$OUT/${NAME}_verification_key.json"

echo "OK: dev Groth16 keys for ${NAME} in ${OUT} (DO NOT USE IN PRODUCTION)"
