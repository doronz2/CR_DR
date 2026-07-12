#!/usr/bin/env bash
# Post-widening campaign: wait for zkey setups, test, measure the TRUE
# 10^4-registered-voter chunked run, re-bench the chunked group.
set -euo pipefail
cd "$(dirname "$0")/.."
until grep -q WIDEN_SETUP_DONE regen_zkeys.log 2>/dev/null; do sleep 30; done
echo "=== [1/3] full test suite (real proofs on widened circuits) ==="
cargo test 2>&1 | grep -E "test result"
echo "=== [2/3] TRUE 10^4-registered-voter chunked run (depth 14, 14-bit ids) ==="
( while sleep 5; do ps -eo rss=,comm= | grep -E "prover$" || true; done > build/campaign/rss_widen.txt ) &
SAMPLER=$!
cargo run --release --bin prove_chunked
kill $SAMPLER 2>/dev/null || true
sort -rn build/campaign/rss_widen.txt | head -1
echo "=== [3/3] chunked bench group ==="
cargo bench --bench prover -- chunked
echo WIDEN_CAMPAIGN_DONE
