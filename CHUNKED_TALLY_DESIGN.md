# Design note: chunked FilterAndTally proving (10^4–10^6 voters)

Status: IMPLEMENTED (circuits/main/{validity_chunk,sorted_run_chunk,tally_sum_chunk}.circom, src/zk/chunked.rs, tests/chunked_tests.rs; benchmarks in BENCHMARKS.md). Two review points were resolved during implementation: (1) the SORTED runs are also committed in phase 1 (sc_k) and the challenge is derived from rc AND sc — committing only the original side would let the prover pick the sorted side after seeing gamma; (2) the run-0 sentinel predecessor is excluded from the sortedness comparison in-circuit (its packed key would exceed the comparator range), which is sound because no multiset-bound record can carry the sentinel id. Companion
to BENCHMARKS.md, which shows why the monolithic circuit stops at ~10^4
voters (RAM, and the 2^28 public-ceremony ceiling).

## Goal

Prove the EXACT FilterAndTally relation over a board of B = 2N slots for
N up to 10^6 voters, while preserving every property of the monolithic
relation:

* exactness over the WHOLE board (no "some valid subset" proofs);
* validity before duplicates (first-valid-counts);
* the indexed registration table (ballot id ⇒ row, hard for in-range ids);
* privacy: no validity labels, identities, rejection reasons, sorted
  order, partial tallies, or per-chunk vote distributions become public;
* the same public statement: (eid_hash, MR, candidate_set_commitment,
  bb_commitment, num_ballots, num_voters, duplicate_rule_id,
  pk_ea_commitment, tally_counts[]).

## Why the sorting network does not shard

Strategy B's Batcher network is sound because it is one deterministic
circuit over all B records. Split into chunks, comparators cross chunk
boundaries at every merge layer — there is no local decomposition. The
chunked design therefore replaces the network with the OTHER sound
permutation argument: a grand-product multiset check under a challenge
sampled AFTER the records are committed. The two-phase structure that
Groth16 alone lacks is exactly what the aggregation layer provides.

## Architecture

Two fixed chunk circuits (each with its own one-time setup at a fixed
chunk size C, e.g. C = 128; reusable for every election and every N):

### Phase 1 — validity chunks (K = B/C proofs)

Chunk k processes board slots [kC, (k+1)C), exactly today's per-slot
stage: open/parse, soft flags, signature, STRICT id bits, HARD indexed
row fetch (path directions = id bits, root === MR), record
r_j = (valid, id, pos, m).

Public inputs of chunk k (beyond the shared statement fields):

| signal | meaning |
|---|---|
| `bb_in`, `bb_out` | running Poseidon chain over posted cts at the chunk's edges |
| `rc_k` | binding commitment to the chunk's C records (Poseidon chain) |

Chaining `bb_in/bb_out` across chunks with `bb_0 = 0` and
`bb_K = bb_commitment` reproduces the monolithic board binding. `rc_k`
is binding but reveals nothing (records are hashed with a blinding term).

### Challenge derivation (between phases)

    gamma, delta = H(statement, rc_1, ..., rc_K)

Fiat–Shamir over the phase-1 commitments. Soundness of the multiset
argument is Schwartz–Zippel over the BN254 scalar field: error
O(B / |F|) ≈ 2^-230 for B ≤ 2^21. The verifier (or the aggregation
circuit) recomputes gamma, delta from the rc_k, so the prover cannot
grind the challenge after choosing the sorted sequence.

### Phase 2 — sorted-run chunks (K proofs)

The prover sorts all B records by (-valid, id, pos) and splits the sorted
sequence into K runs of C. Sorted-run chunk k proves, over private
records s_1..s_C:

1. **in-run sortedness**: key(s_i) <= key(s_{i+1}) (key packing as today,
   widened to log2 N + log2 B + 1 bits);
2. **cross-run sortedness**: key(boundary_in) <= key(s_1), and
   boundary_out = s_C, where boundary_in/out are HIDING commitments to
   the neighbouring runs' edge records (opened in-circuit; adjacent
   chunks' commitments are equated by the aggregator). The first chunk
   takes a fixed sentinel;
3. **first-valid counting**: counted_i = valid_i * (1 - same_id(s_{i-1},
   s_i)), with s_0 = boundary_in — identical to today's adjacent rule,
   working across runs;
4. **partial tally**: t_k[c] = sum_i counted_i * [m_i = c], carried OUT
   only as a hiding (Pedersen) commitment `tc_k`;
5. **multiset accumulators**: the chunk outputs partial grand products
   over its own records:
       P_k = prod_i (gamma - (s_i.valid + delta*s_i.id + delta^2*s_i.pos + delta^3*s_i.m))
   and phase-1 chunks output the same product Q_k over their (original-
   order) records — either recomputed from rc_k openings in phase 2, or
   emitted by phase 1 as a second public value once gamma is known (this
   forces phase 1 to run twice or phase 2 to re-open rc_k; the sketch
   prefers re-opening rc_k inside the phase-2 chunk, which keeps phase 1
   single-pass).

### Aggregation layer

The aggregator (a verifier program, NOT trusted: everything it checks is
re-checkable by anyone) verifies:

* all 2K Groth16 proofs (or one SnarkPack aggregate of them, ~40 KB);
* `bb` chain: bb_0 = 0, adjacent equality, bb_K = bb_commitment;
* boundary chain: adjacent boundary commitments equal; sentinel at 0;
* challenge: gamma, delta recomputed from (statement, rc_1..rc_K);
* multiset: prod_k P_k == prod_k Q_k  (the permutation check);
* tally: sum of Pedersen commitments tc_k opens to the public
  tally_counts — the homomorphic sum reveals ONLY the total, never a
  partial tally.

## Privacy accounting

Everything that crosses a chunk boundary is either already public
(bb chain values are functions of the public board) or a hiding
commitment (records rc_k, boundary records, partial tallies tc_k, partial
products — products of blinded terms; gamma-terms include the blinding in
the hash-committed record encoding). No per-chunk tally, no sorted order,
no validity bit is revealed. Chunk boundaries themselves are public
positions on an already-public board.

## Cost model (from BENCHMARKS.md rates)

Per validity chunk: ~C * 8-11k constraints (same as today). Per sorted-run
chunk: ~C * (few hundred) + commitment hashing — an order of magnitude
cheaper. Duplicates drop from ~2.9k/slot (network at 2^21) to ~200/slot
(accumulators). Wall-clock at 10^6 voters (B = 2^21, C = 128, K = 16,384):
~16k * 2.7 s ≈ 12 h on one M3 Max with rapidsnark, ~minutes-to-tens of
minutes on a modest cluster; ~1-2 GB per worker.

## Tier-3 remark

Chunks are the natural unit of DISTRIBUTED proving: each threshold
authority (or worker) proves disjoint chunks with only its slice of the
witness plus the boundary commitments. The same interfaces that isolate
`r_ea()` reconstruction today would hand each chunk prover only the
nonces for its slots.

## Open questions for review

1. Phase-1/phase-2 record binding: re-opening rc_k inside phase 2 costs
   ~C Poseidon openings per chunk — acceptable, but an alternative is a
   3-move design where phase 1 emits Q_k after gamma (two passes over
   phase 1). Pick one.
2. Blinding discipline for the grand-product terms (the record encoding
   entering P_k/Q_k must be identical on both sides INCLUDING blinding,
   or the products diverge — needs a worked term layout).
3. Pedersen vs Poseidon commitments for tc_k (homomorphic sum wants
   Pedersen on BabyJubJub; verify cost inside the aggregate).
4. SnarkPack vs recursive aggregation: SnarkPack keeps the two chunk
   circuits as the only ceremonies but leaves 2K public-input sets for
   the verifier to walk; a recursive aggregator hides them but needs a
   pairing-friendly cycle (BW6-style) and a much bigger engineering
   lift.
5. Whether `num_voters`/MR consistency needs restating per chunk or can
   remain a shared statement input (it can: both are constants across
   chunks and bound by every chunk proof).
