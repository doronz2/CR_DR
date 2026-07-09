#!/usr/bin/env bash
# One-shot measurement campaign for the N=10^4 scalability section
# (BENCHMARKS.md "Measured scalability result"). Run detached; writes
# campaign.log alongside per-step artifacts in build/campaign/.
set -euo pipefail
cd "$(dirname "$0")/.."
OUT=build/campaign
mkdir -p "$OUT"
export NODE_OPTIONS="--max-old-space-size=16384"

echo "=== [1/6] depth-14 validity-chunk sizing compile ==="
scripts/compile_circuits.sh vchunk128_d14

echo "=== [2/6] full criterion bench suite ==="
cargo bench --bench prover

echo "=== [3/6] peak-RSS: medium witness gen + snarkjs prove + rapidsnark prove ==="
cargo run --release --bin gen_example_inputs -- medium
/usr/bin/time -l node build/circuits/filter_and_tally_medium_js/generate_witness.js \
    build/circuits/filter_and_tally_medium_js/filter_and_tally_medium.wasm \
    build/inputs/medium_valid_input.json "$OUT/medium.wtns" 2> "$OUT/rss_witgen_medium.txt"
/usr/bin/time -l node node_modules/snarkjs/cli.js groth16 prove \
    build/circuits/filter_and_tally_medium.zkey "$OUT/medium.wtns" \
    "$OUT/medium_proof.json" "$OUT/medium_public.json" 2> "$OUT/rss_snarkjs_medium.txt"
RAPIDSNARK=$(ls build/rapidsnark-src/package_*/bin/prover | head -1)
/usr/bin/time -l "$RAPIDSNARK" \
    build/circuits/filter_and_tally_medium.zkey "$OUT/medium.wtns" \
    "$OUT/medium_proof_rs.json" "$OUT/medium_public_rs.json" 2> "$OUT/rss_rapidsnark_medium.txt"
ls -la "$OUT"/medium_proof.json "$OUT"/medium_public.json

echo "=== [4/6] N=10^4 headline: prove_chunked 20480 (with RSS sampler) ==="
( while sleep 5; do ps -eo rss=,comm= | grep -E "prover$" || true; done > "$OUT/rss_samples_chunked.txt" ) &
SAMPLER=$!
cargo run --release --bin prove_chunked -- --ballots 20480
kill $SAMPLER 2>/dev/null || true

echo "=== [5/6] e2e points: 1000 and 500 ballots ==="
cargo run --release --bin prove_chunked -- --ballots 1000
cargo run --release --bin prove_chunked -- --ballots 500

echo "=== [6/6] proof/public sizes ==="
wc -c "$OUT/medium_proof.json" "$OUT/medium_public.json"
echo CAMPAIGN_DONE
