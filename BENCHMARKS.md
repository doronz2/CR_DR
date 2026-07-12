# CR-DR single-prover benchmark report

**Scope.** Tier-1 SINGLE PROVER only: one logical prover holds the full
witness (including authorized ≥ t reconstructions of the threshold-shared
`R_EA,i`) and generates the Groth16 proof. **No decentralized/threshold
proving is claimed or benchmarked.**


> **ADMISSION PATHS.** Every benchmark documents its admission path:
> the tally groups (`e2e_*`, `groth16_*`, `chunked`, `prove_chunked`) are
> ADMISSION-PATH INDEPENDENT — they process an already-admitted board
> BB_adm = [com_1..com_M] plus the EA-private openings store (the
> `admitted_from_ballots` helper), exactly what both Path 1 (public
> cast-ZK, BB_adm = Clean(BB_raw)) and Path 2 (EA-mediated private
> submission with signed receipts) produce. Path-1 PER-VOTER costs are the
> `cast` group (seal_ballot / prove_cast / verify_cast_entry). Path 2 has
> no per-voter ZK cost; its recorded-as-cast machinery is plain
> signatures (<1 ms).
>
> **FORMAT CHANGE (CAST-ZK).** The ballot format is
> B_j = (com, ct_open, pi_cast): real BabyJubJub-ElGamal hybrid encryption
> of the opening on the public board, a per-ballot cast proof (6,095
> constraints, 136 ms snarkjs prove incl. witness gen, verified publicly
> BEFORE tallying), a HARD commitment opening inside the tally circuit,
> and a SOFT-SAFE Schnorr gadget (complete Edwards double-and-add, soft
> on-curve flags, and a soft S-canonicity flag matching the native
> verifier's rule — see tests/soft_safety_tests.rs). Tally circuits grew
> ~22-24% relative to the pre-CAST format: small 116,035 -> 144,339
> (naive 143,300), medium 1,009,483 -> 1,235,915 (naive 1,234,980),
> validity chunk 1,017,911 -> 1,493,956 (now incl. depth-14/14-bit-id
> registration). **All tables below are re-measured
> on the current circuits** with freshly generated zkeys; the per-ballot
> Path-1 costs are in the "CAST-ZK per-ballot costs" section at the end.

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
cargo test                                # 129 passed, 0 failed
scripts/compile_circuits.sh small         # + small_naive, medium, medium_naive
scripts/setup_groth16.sh small            # + small_naive, medium, medium_naive
cargo bench --bench prover                # all groups below
cargo run --release --bin gen_example_inputs -- medium   # 128-slot input for memory runs
scripts/install_rapidsnark.sh            # native prover (optional fast path)
/usr/bin/time -l <prover> ...             # peak RSS (snarkjs and rapidsnark)
```

Pass/fail: `cargo test` **129 passed / 0 failed** (includes Groth16
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
| `filter_and_tally_small` | B (sorted network) | 144,339 | 11 |
| `filter_and_tally_small_naive` | A (naive O(B²)) | 143,300 | 11 |
| `filter_and_tally_medium` | B (sorted network) | 1,235,915 | 11 |
| `filter_and_tally_medium_naive` | A (naive O(B²)) | 1,234,980 | 11 |
| `filter_and_tally_cast` (per-ballot pi_cast) | — | 6,095 | 15 |

At 16 slots the Batcher network (63 comparators) costs ~1k constraints more
than the naive scan (120 pairs); at 128 slots (1,471 comparators vs 8,128
pairs) the two are within 0.1%. The in-circuit crossover is ≈128 slots;
beyond it the naive O(B²) term grows quadratically while the network grows
as O(B log² B) — at 1024 slots the naive scan alone would need ~33 M
constraint-equivalents of pair checks vs ~0.6 M for the network.

## Native end-to-end pipeline (criterion, mean)

| stage | small (16 slots) | medium (128 slots) |
|---|---|---|
| `setup_election` | 111 µs | 112 µs |
| `preprocess_voter` (threshold-private, incl. vk validation) | 239 µs | 239 µs |
| `finalize_registration` (indexed Merkle root) | 306 µs | 1.29 ms |
| `cast_vote` (incl. seal: com + hybrid ct_open) | 822 µs | 832 µs |
| `fake_compliance_ballot` | 837 µs | 840 µs |
| `chaff_ballot` | 902 µs | 914 µs |
| `anonymous_channel_flush` (shuffle, full board) | 1.4 µs | 10.4 µs |
| `filter_and_tally_native` (exact tally over BB_adm) | 8.9 ms | 73.6 ms |
| `build_tally_statement` | 377 µs | 2.71 ms |
| `build_tally_witness` | 11.9 ms | 96.3 ms |
| `relation_check_native` (mock backend, incl. sort network) | 9.9 ms | 85.6 ms |
| `generate_witness_input` (input.json) | 98 µs | 852 µs |

Native tally/witness cost is dominated by per-ballot Schnorr verification
and the per-ballot authorized share reconstruction of `R_EA,i` (Lagrange
over t=2 shares, recomputed per ballot rather than cached —
research-prototype simplicity). Ballot creation now includes the CAST-ZK
seal (Poseidon commitment + BabyJubJub-ElGamal hybrid encryption of the
opening), which is why `cast_vote` grew from ~0.55 ms to ~0.83 ms.

## Duplicate handling: Strategy A vs Strategy B (native, criterion)

| records | A: naive O(B²) | B: sort + linear scan | B/A |
|---|---|---|---|
| 16 | 51 ns | 108 ns | 2.1× slower |
| 128 | 2.09 µs | 1.15 µs | 1.8× faster |
| 1024 | 144 µs | 12.6 µs | 11.5× faster |

Both strategies agree on all inputs (fixed and randomized tests). Strategy B
is the main strategy: it is what the circuit implements, and natively it
includes the explicit multiset-equality (permutation) check.

## Groth16 stages — single prover (criterion, sample size 10)

| stage | small B | small A | medium B | medium A |
|---|---|---|---|---|
| circuit witness generation (wasm) | 0.75 s | 0.75 s | 5.11 s | 5.13 s |
| Groth16 prove — snarkjs (incl. witness gen) | 5.58 s | 5.58 s | 42.1 s | 42.0 s |
| **Groth16 prove — rapidsnark (prove step only)** | **0.38 s** | 0.37 s | **3.11 s** | 3.09 s |
| Groth16 verify (snarkjs) | 0.21 s | 0.21 s | 0.21 s | 0.21 s |

### snarkjs vs rapidsnark (same .zkey, same .wtns, same verification key)

The rapidsnark rows measure the PROVE STEP alone from a pre-generated
witness; the snarkjs `prove` rows include wasm witness generation (that is
what `SnarkjsBackend::prove` does). Comparing like with like:

| | small (144k) | medium (1.24M) |
|---|---|---|
| prove step, snarkjs (est. = prove − witgen) | ~4.8 s | ~37.0 s |
| prove step, rapidsnark | 0.38 s | 3.11 s |
| **prove-step speedup** | **~13×** | **~12×** |
| end-to-end witgen+prove, snarkjs | 5.58 s | 42.1 s |
| end-to-end witgen+prove, rapidsnark path | 1.13 s | 8.22 s |
| prove peak RSS, snarkjs | — | 9.26 GB |
| prove peak RSS, rapidsnark | — | 1.56 GB |
| witness generation peak RSS (wasm) | — | 0.47 GB |

rapidsnark proofs verify under the unchanged snarkjs verification keys and
bind public inputs identical to the snarkjs prover's (integration-tested:
`groth16_integration_tests::rapidsnark_proves_and_snarkjs_verifies`). With
the native prover, the wasm witness calculator becomes the pipeline
bottleneck (0.75 s / 5.2 s) — circom's C++ witness generator would be the
next lever.

Proof/statement sizes (independent of board size): `proof.json` ≈ **0.8 KB**
(805 bytes pretty-printed / 723 compact — 3 group elements + metadata),
`public.json` ≈ **0.4 KB** (11 public inputs).

Peak prover memory (`/usr/bin/time -l`, max resident set of the prove
process, current circuits):

| circuit | snarkjs prove | rapidsnark prove | witness gen (wasm) |
|---|---|---|---|
| medium B (1,235,915 constraints) | 9.26 GB | 1.56 GB | 0.47 GB |
| validity chunk (1,493,956; sampled during the N=10^4 run) | — | 1.70 GB | — |

## Chunked pipeline (implemented; boards beyond one circuit)

The chunked route (CHUNKED_TALLY_DESIGN.md) is implemented end-to-end:
K x ValidityChunk (1,493,956 constraints, C = 128 slots, depth-14
registration, 14-bit ids) + K x SortedRunChunk (96,920) + 1 x TallySum
(48,000 at K=160), with blinded record/run
commitments, a Fiat-Shamir grand-product permutation argument (both sides
committed BEFORE the challenge; the running products cross chunk
boundaries ONLY as hiding commitments, and the final equality is proven
inside the tally-sum circuit — no product value or per-chunk ratio is
public), hiding boundary-record and partial-tally commitments, and a
PUBLIC transcript verifier (`verify_chunked_public_transcript`: statement
+ admitted board + transcript + proof objects only). Tests cover
acceptance, tally agreement with the monolithic relation, rejection of
tampered sorted records / shifted partial tallies / forged challenges /
invalidated records, and malicious public transcripts (swapped chunks,
broken board/boundary/product chains, dropped admitted commitments,
cross-chunk duplicates counted once).

Measured (rapidsnark prove, wasm witness gen, criterion sample 10;
`prove_chunked` for the e2e rows, jobs=2):

| stage | time |
|---|---|
| validity chunk: witness gen / prove | 5.13 s / 3.19 s |
| sorted-run chunk: witness gen / prove | 0.20 s / 0.26 s |
| tally-sum proof | negligible |
| e2e 500 ballots, 200 voters (K=4, 9 proofs) | 23.9 s (verify-all 1.9 s) |
| e2e 1,000 ballots, 400 voters (K=8, 17 proofs) | 48.4 s (verify-all 3.6 s) |

## Measured scalability result (N = 10^4)

**The headline result of this report**: a TRUE 10^4-registered-voter
election — 10,000 registered voters on a depth-14 indexed registration
tree with 14-bit identities, 20,480 board slots (B = 2N) — proven and
verified end-to-end on one laptop.

### Reproducibility record

| | |
|---|---|
| Commit | `45eabdf` ("Widen chunked pipeline to 14-bit identities"; the benchmarked tree — this file's numbers were added in the follow-up docs commit) |
| Hardware | Apple M3 Max, 14 cores, 36 GB RAM |
| OS | macOS 14.3 (Darwin 23.3.0) |
| Toolchain | rustc 1.96.1; Node.js v26.4.0; circom 2.1.9; snarkjs 0.7.6; rapidsnark master (built via `scripts/install_rapidsnark.sh`) |
| Trusted setup | public Hermez `powersOfTau28_hez_final_21.ptau` + dev-only local phase-2 (timings valid; keys NOT for production) |

Commands:

```bash
scripts/compile_circuits.sh vchunk128   # + srun128, tsum160
scripts/setup_groth16.sh   vchunk128    # + srun128, tsum160
cargo run --release --bin prove_chunked   # defaults: --ballots 20480 --voters 10000
```

Instance (synthetic, deterministic from `--seed 5000`; ADMISSION-PATH
INDEPENDENT — `prove_chunked` models an already-admitted board, exactly
what Path 1's public Clean or Path 2's EA admission produce; Path-1
per-voter costs are the `cast` group below):

| parameter | value |
|---|---|
| registered voters N | **10,000** (dense ids 0..9,999 on the indexed table) |
| board slots B | 20,480 (24-bit positions: POS_BITS = 24, boards to 2^24) |
| candidates | 3 |
| real / fake-compliance / chaff ballots | 10,000 / 5 / 10,475 |
| chunk size C / chunks K / proofs 2K+1 | 128 / 160 / 321 |
| ID_BITS / POS_BITS / MERKLE_DEPTH | 14 / 24 / 14 (capacity 16,384 voters) |
| circuits (constraints) | vchunk128: 1,493,956; srun128: 96,920; tsum160: 48,000 |

Measured results:

| stage | measured |
|---|---|
| instance generation (native, incl. 10^4 voter preprocessings) | 21.4 s |
| witness rows + records + commitments (native) | 73.2 s |
| prove, 321 proofs (rapidsnark, jobs=2) | **1000.6 s wall** (16.7 min; 6.25 s/chunk-pair amortized) |
| verify all 321 proofs (per-proof snarkjs CLI) | **67.6 s** (~3 ms/proof in-process pairing) |
| peak memory per prover worker | 1.70 GB |
| proof / public size (per proof) | 805 B / ≤449 B |

Cross-check: the previous depth-6/8-bit run measured 847.5 s and the
compiled depth-14 sizing predicted a x1.2 factor (~1017 s); the true
widened run measured 1000.6 s — the projection methodology held.

### Scaling parameters beyond 10^4

Chunk-circuit size is what scales with the ELECTORATE (the board scales
only K). 10^5 registered voters need ID_BITS/MERKLE_DEPTH = 17 (+3
Merkle levels per slot ≈ +6% constraints over the compiled depth-14
circuits); 10^6 need 20 (+6 levels ≈ +13%). Both are one-line
instantiation changes of the SAME parameterized templates
(`ValidityChunk(C, nC, depth, idBits)` / `SortedRunChunk(C, nC, idBits)`)
plus a fresh dev setup; neither is compiled here, so the 10^5/10^6
columns below carry those growth factors as projections.

### Measured 10^4 vs projected 10^5 / 10^6

Projections = measured per-chunk cost x K x the depth-growth factor
above, same jobs scaling; they assume chunk independence (measured:
chunks share no witness data) and linear aggregation checks (sub-second
even at K=2^14).

| | N = 10^4 | N = 10^5 | N = 10^6 |
|---|---|---|---|
| board slots B = 2N | 20,480 | 204,800 | 2,048,000 |
| chunks K / proofs 2K+1 | 160 / 321 | 1,600 / 3,201 | 16,000 / 32,001 |
| ID_BITS / MERKLE_DEPTH | **14 / 14 (compiled)** | 17 / 17 (projected) | 20 / 20 (projected) |
| prove, this M3 Max (jobs=2) | **16.7 min MEASURED** | ~2.9 h (proj.) | ~31 h (proj.) |
| prove, 90-vCPU cloud box (jobs~15) | ~2.2 min (proj.) | ~24 min (proj.) | ~4.2 h (proj.) |
| verify all proofs (in-process, ~3 ms each) | ~1 s | ~10 s | ~96 s |
| peak memory per worker | **1.70 GB MEASURED** | ~1.8 GB (proj.) | ~1.9 GB (proj.) |

The N = 10^4 column is MEASURED end-to-end on the true 10^4-voter
instance (this section); N = 10^5 and N = 10^6 are PROJECTIONS on the
correspondingly widened parameters. GCP_RUNBOOK.md gives the one-command
cloud recipe.

## Reading the numbers

* **Proving scales with circuit size, not board occupancy** — small→medium
  is 8.6× the constraints and ~8× the prove time on both provers
  (snarkjs 5.6 s → 42.1 s; rapidsnark 0.38 s → 3.11 s). One proof covers
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
  1.24M-constraint circuit in 3.1 s using 1.56 GB (vs ~37 s / 9.26 GB for
  the snarkjs prove step, both measured). Extrapolating roughly linearly,
  a 1024-slot board (~10M constraints with Strategy B) looks like ~26 s
  and ~13 GB with rapidsnark — feasible on this machine, where snarkjs
  would already be out of memory. Witness generation (wasm) then dominates
  the pipeline; circom's C++ witness calculator is the next lever,
  orthogonal to the relation design.

## CAST-ZK per-ballot costs (Path 1, measured)

The `cast` criterion group measures the Path-1 per-voter/per-entry costs
on the real 6,095-constraint cast circuit (fresh zkey, snarkjs backend):

| stage | who pays | time |
|---|---|---|
| `seal_ballot` (com + hybrid ct_open) | voter | 0.62 ms |
| `prove_cast` (pi_cast, incl. wasm witness gen) | voter | 135 ms |
| `verify_cast_entry` (publics binding + Groth16 verify + C1 subgroup check) | anyone (Clean, per entry) | 208 ms |

Verification time is dominated by node/snarkjs process startup (~0.2 s
flat, same as the tally verifies above), not the pairing check; a
long-running verifier process would amortize this away for bulk cleaning.
Path 2 has no per-voter ZK cost: admission is one commitment opening check
plus one BabyJubJub Schnorr receipt signature (<1 ms).
