# CR-DR single-prover benchmark report

**Scope.** Tier-1 SINGLE PROVER only: one logical prover holds the full
witness (including authorized ≥ t reconstructions of the threshold-shared
`R_EA,i`) and generates the Groth16 proof. **No decentralized/threshold
proving is claimed or benchmarked.**

## Environment

| | |
|---|---|
| Machine | Apple M3 Max, 14 cores, 36 GB RAM, macOS 14.3 |
| Rust | rustc 1.96.1 (criterion `bench` profile) |
| Node.js | v26.4.0 |
| circom | 2.1.9 |
| snarkjs | 0.7.6 (CLI, multi-threaded prover) |
| rapidsnark | iden3 native C++ prover, built from master via `scripts/install_rapidsnark.sh` (Homebrew GMP) |
| Trusted setup | small: dev-only local ptau (2^18); medium: public Hermez `powersOfTau28_hez_final_21.ptau` + **dev-only local phase-2** — timings valid, keys not for production |

## Commands run

```bash
cargo test                                # 94 passed, 0 failed
scripts/compile_circuits.sh small         # + small_naive, medium, medium_naive
scripts/setup_groth16.sh small            # + small_naive, medium, medium_naive
cargo bench --bench prover                # all groups below
cargo run --release --bin gen_example_inputs -- medium   # 128-slot input for memory runs
scripts/install_rapidsnark.sh            # native prover (optional fast path)
/usr/bin/time -l <prover> ...             # peak RSS (snarkjs and rapidsnark)
```

Pass/fail: `cargo test` **94 passed / 0 failed** (includes Groth16
integration tests: real prove+verify, tampered-public-input rejection,
wrong-tally unprovability, cross-instance rejection, no witness data in the
proof; plus the new hard-indexed-row and state-separation tests). All four
circuit variants prove and verify their instances; Strategy B and Strategy A
circuits accept the same witness input and bind **identical public inputs**
(checked explicitly on the small pair).

## Instances

| | small | medium |
|---|---|---|
| Ballot slots (nB) | 16 | 128 |
| Candidates (nC) | 3 | 3 |
| Merkle depth | 4 | 6 |
| Registered voters | 6 | 40 |
| Real ballots | 6 | 40 |
| Fake-compliance ballots | 1 | 5 |
| Chaff ballots | 9 | 83 |
| Threshold params | t=2, k=3 | t=2, k=3 |
| Tally | [1, 2, 3] | [5, 17, 18] |

Constraint counts (circom 2.1.9 → `snarkjs r1cs info`):

| circuit | duplicate strategy | constraints | public inputs |
|---|---|---|---|
| `filter_and_tally_small` | B (sorted network) | 116,035 | 11 |
| `filter_and_tally_small_naive` | A (naive O(B²)) | 114,996 | 11 |
| `filter_and_tally_medium` | B (sorted network) | 1,009,483 | 11 |
| `filter_and_tally_medium_naive` | A (naive O(B²)) | 1,008,548 | 11 |

At 16 slots the Batcher network (63 comparators) costs ~1k constraints more
than the naive scan (120 pairs); at 128 slots (1,471 comparators vs 8,128
pairs) the two are within 0.1%. The in-circuit crossover is ≈128 slots;
beyond it the naive O(B²) term grows quadratically while the network grows
as O(B log² B) — at 1024 slots the naive scan alone would need ~33 M
constraint-equivalents of pair checks vs ~0.6 M for the network.

## Native end-to-end pipeline (criterion, mean)

| stage | small (16 slots) | medium (128 slots) |
|---|---|---|
| `setup_election` | 156 µs | 153 µs |
| `preprocess_voter` (threshold-private, per voter) | 268 µs | 285 µs |
| `finalize_registration` (indexed Merkle root) | 420 µs | 1.77 ms |
| `cast_vote` | 522 µs | 549 µs |
| `fake_compliance_ballot` | 512 µs | 552 µs |
| `chaff_ballot` | 643 µs | 615 µs |
| `anonymous_channel_flush` (shuffle, full board) | 2.2 µs | 16.7 µs |
| `filter_and_tally_native` (exact tally) | 13.6 ms | 106 ms |
| `build_tally_statement` | 518 µs | 3.7 ms |
| `build_tally_witness` | 20.1 ms | 159 ms |
| `relation_check_native` (mock backend, incl. sort network) | 14.0 ms | 122 ms |
| `generate_witness_input` (input.json) | 137 µs | 1.21 ms |

Native tally/witness cost is dominated by per-ballot Schnorr verification
and the per-ballot authorized share reconstruction of `R_EA,i` (Lagrange
over t=2 shares, recomputed per ballot rather than cached —
research-prototype simplicity).

## Duplicate handling: Strategy A vs Strategy B (native, criterion)

| records | A: naive O(B²) | B: sort + linear scan | B/A |
|---|---|---|---|
| 16 | 52 ns | 104 ns | 2.0× slower |
| 128 | 2.11 µs | 1.15 µs | 1.8× faster |
| 1024 | 157 µs | 12.6 µs | 12.5× faster |

Both strategies agree on all inputs (fixed and randomized tests). Strategy B
is the main strategy: it is what the circuit implements, and natively it
includes the explicit multiset-equality (permutation) check.

## Groth16 stages — single prover (criterion, sample size 10)

| stage | small B | small A | medium B | medium A |
|---|---|---|---|---|
| circuit witness generation (wasm) | 0.64 s | 0.65 s | 4.09 s | 4.12 s |
| Groth16 prove — snarkjs (incl. witness gen) | 4.17 s | 4.19 s | 30.8 s | 30.6 s |
| **Groth16 prove — rapidsnark (prove step only)** | **0.25 s** | 0.25 s | **2.18 s** | 2.19 s |
| Groth16 verify (snarkjs) | 0.21 s | 0.21 s | 0.21 s | 0.21 s |

### snarkjs vs rapidsnark (same .zkey, same .wtns, same verification key)

The rapidsnark rows measure the PROVE STEP alone from a pre-generated
witness; the snarkjs `prove` rows include wasm witness generation (that is
what `SnarkjsBackend::prove` does). Comparing like with like:

| | small (116k) | medium (1.01M) |
|---|---|---|
| prove step, snarkjs (est. = prove − witgen) | ~3.5 s | ~26.7 s |
| prove step, rapidsnark | 0.25 s | 2.18 s |
| **prove-step speedup** | **~14×** | **~12×** |
| end-to-end witgen+prove, snarkjs | 4.17 s | 30.8 s |
| end-to-end witgen+prove, rapidsnark path | 0.89 s | 6.28 s |
| prove peak RSS, snarkjs | 2.70 GB | 7.62 GB |
| prove peak RSS, rapidsnark | 0.15 GB | 1.13 GB |

rapidsnark proofs verify under the unchanged snarkjs verification keys and
bind public inputs identical to the snarkjs prover's (integration-tested:
`groth16_integration_tests::rapidsnark_proves_and_snarkjs_verifies`). With
the native prover, the wasm witness calculator becomes the pipeline
bottleneck (0.64 s / 4.1 s) — circom's C++ witness generator would be the
next lever.

Proof/statement sizes (independent of board size): `proof.json` ≈ **0.8 KB**
(805 bytes pretty-printed / 723 compact — 3 group elements + metadata),
`public.json` ≈ **0.4 KB** (11 public inputs).

Peak prover memory (`/usr/bin/time -l`, max resident set of the prove
process):

| circuit | snarkjs prove | rapidsnark prove | witness gen (wasm) |
|---|---|---|---|
| small B (116k constraints) | 2.70 GB | 0.15 GB | — |
| medium B (1.01M constraints) | 7.62 GB | 1.13 GB | 0.51 GB |
| medium A (1.01M constraints) | 8.27 GB | — | — |

## Chunked pipeline (implemented; boards beyond one circuit)

The chunked route (CHUNKED_TALLY_DESIGN.md) is implemented end-to-end:
K x ValidityChunk (1,017,911 constraints, C = 128 slots) + K x
SortedRunChunk (92,235) + 1 x TallySum (~2.4k), with blinded record/run
commitments, a Fiat-Shamir grand-product permutation argument (both sides
committed BEFORE the challenge), hiding boundary-record and partial-tally
commitments, and native aggregate verification. Tests cover acceptance,
tally agreement with the monolithic relation, and rejection of tampered
sorted records / shifted partial tallies / forged challenges /
invalidated records.

Measured (rapidsnark prove, wasm witness gen, criterion sample 10):

| stage | time |
|---|---|
| validity chunk: witness gen / prove | 3.99 s / 2.23 s |
| sorted-run chunk: witness gen / prove | 0.21 s / 0.27 s |
| tally-sum proof | negligible |
| **e2e 500 ballots (K=4, 9 proofs, sequential)** | **27.2 s** (verify-all 1.9 s) |
| **e2e 1,000 ballots (K=8, 17 proofs, sequential)** | **55.4 s** (verify-all 3.5 s) |

Per-chunk composite ~6.9 s, dominated by wasm witness generation; peak
memory bounded by the ~1.1 GB validity chunk regardless of board size.
Composed projection at B = 2N (measured per-chunk cost x K; SnarkPack
figures cited for the optional O(log n) aggregate):

| | N = 10^4 | N = 10^5 | N = 10^6 |
|---|---|---|---|
| chunks K / proofs 2K+1 | 160 / 321 | 1,600 / 3,201 | 16,000 / 32,001 |
| prove, this M3 Max (jobs=2) | **10.8 min MEASURED** | ~1.8 h (proj.) | ~18 h (proj.) |
| prove, 90-vCPU cloud box (jobs~15) | ~1.5-2 min (proj.) | ~15-20 min (proj.) | ~2.5-3 h (proj.) |
| verify all proofs | **67.5 s MEASURED** (per-proof CLI) | ~11 min CLI / ~10 s in-process | ~96 s in-process |

The N = 10^4 row is now MEASURED end-to-end on the laptop via
`cargo run --release --bin prove_chunked -- --ballots 20480` (24-bit board
positions; 645.8 s prove wall at 2 concurrent rapidsnark jobs = 4.04 s
per chunk-pair amortized; instance generation + witness/commitments add
~70 s). GCP_RUNBOOK.md gives the one-command cloud recipe for the faster
run; the 10^5/10^6 columns remain projections from the same measured
per-chunk cost.

## Reading the numbers

* **Proving scales with circuit size, not board occupancy** — small→medium
  is 8.7× the constraints and ~7–9× the prove time on both provers
  (snarkjs 4.17 s → 30.8 s; rapidsnark 0.25 s → 2.18 s). One proof covers
  the whole board: the cost is per-tally, not per-ballot.
* **Verification is flat** (~0.21 s at both sizes) and dominated by
  node/snarkjs process startup, not the pairing check.
* **Strategy B ≈ Strategy A inside the circuit at these sizes** (within
  1–5% prove time, within 0.1% constraints at 128): per-ballot validity
  (Schnorr, Poseidon, the strict 254-bit id decomposition and the hard
  indexed-row Merkle check) dominates the circuit. The sorted-record
  relation is the strategy that stays feasible as boards grow past ~128.
* **Native pipeline is negligible** next to proving: everything the
  authority does outside snarkjs — exact tally, witness build, native
  relation check — totals ~0.4 s even at 128 slots.
* **The native prover changes the scaling picture**: rapidsnark proves the
  1M-constraint circuit in 2.2 s using 1.1 GB (vs ~27 s / 7.6 GB for the
  snarkjs prove step). Extrapolating roughly linearly, a 1024-slot board
  (~8M constraints with Strategy B) looks like ~20 s and ~9 GB with
  rapidsnark — feasible on this machine, where snarkjs would already be
  out of memory. Witness generation (wasm) then dominates the pipeline;
  circom's C++ witness calculator is the next lever, orthogonal to the
  relation design.
