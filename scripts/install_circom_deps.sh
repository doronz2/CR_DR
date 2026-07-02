#!/usr/bin/env bash
# Install the ZK toolchain dependencies (dev/prototype use only).
#
# Prerequisites you must already have:
#   - Rust toolchain (cargo) — for the circom 2 compiler
#   - Node.js >= 18 + npm    — for snarkjs and circomlib
set -euo pipefail
cd "$(dirname "$0")/.."

# circom 2 (the Rust compiler; NOT the legacy JS circom 0.x)
if circom --version 2>/dev/null | grep -q "circom compiler 2"; then
  echo "circom 2 already installed: $(circom --version)"
else
  echo "Installing circom v2.1.9 from source (cargo install)..."
  cargo install --git https://github.com/iden3/circom --tag v2.1.9 circom
fi

# snarkjs + circomlib, local to this repo
if [ ! -f package.json ]; then
  cat > package.json <<'EOF'
{
  "name": "cr_dr_zk_deps",
  "private": true,
  "description": "ZK toolchain deps for the CR-DR reference implementation",
  "dependencies": {
    "circomlib": "^2.0.5",
    "snarkjs": "^0.7.5"
  }
}
EOF
fi
npm install
echo "OK: circom, snarkjs and circomlib are ready."
