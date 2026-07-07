#!/usr/bin/env bash
# Build the rapidsnark NATIVE Groth16 prover (optional fast path).
#
# rapidsnark (iden3) is a drop-in replacement for `snarkjs groth16 prove`:
# it reads the same .zkey/.wtns and emits proofs that verify under the same
# verification keys. Witness generation and verification stay on snarkjs.
#
# Requires: cmake, a C++ toolchain, and GMP (brew install gmp on macOS —
# the script links the Homebrew GMP instead of building GMP from source,
# which also sidesteps broken m4 setups).
set -euo pipefail
cd "$(dirname "$0")/.."

SRC=build/rapidsnark-src
if [ ! -d "$SRC" ]; then
  git clone --depth 1 https://github.com/iden3/rapidsnark.git "$SRC"
  (cd "$SRC" && git submodule update --init --recursive)
fi

case "$(uname -s)-$(uname -m)" in
  Darwin-arm64)
    TARGET=macos_arm64
    GMP_PREFIX="${GMP_PREFIX:-$(brew --prefix gmp 2>/dev/null || echo /opt/homebrew/opt/gmp)}"
    [ -d "$GMP_PREFIX/lib" ] || { echo "GMP not found; brew install gmp"; exit 1; }
    mkdir -p "$SRC/depends/gmp/package_${TARGET}"
    ln -sfn "$GMP_PREFIX/include" "$SRC/depends/gmp/package_${TARGET}/include"
    ln -sfn "$GMP_PREFIX/lib" "$SRC/depends/gmp/package_${TARGET}/lib"
    ;;
  Darwin-x86_64)
    TARGET=macos_x86_64
    (cd "$SRC" && ./build_gmp.sh macos_x86_64)
    ;;
  Linux-x86_64)
    TARGET=host
    (cd "$SRC" && ./build_gmp.sh host)
    ;;
  *)
    echo "unsupported platform $(uname -s)-$(uname -m); see rapidsnark README"; exit 1
    ;;
esac

(cd "$SRC" && make "$TARGET")

BIN="$SRC/package_${TARGET}/bin/prover"
[ "$TARGET" = host ] && BIN="$SRC/package/bin/prover"
[ -x "$BIN" ] || { echo "build finished but $BIN is missing"; exit 1; }
echo "OK: rapidsnark prover at $BIN (auto-discovered by RapidsnarkBackend)"
