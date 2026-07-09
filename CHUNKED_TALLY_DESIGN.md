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

    gamma, delta = H(statement, rc_1, ..., rc_K, sc_1, ..., sc_K)

Fiat–Shamir over ALL phase-1 commitments — BOTH the original-order rc_k
and the sorted-run sc_k precede the challenge (committing only one side
would let the prover grind the other). Soundness of the multiset
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
5. **multiset accumulators (hiding running-product chain)**: the chunk
   continues two RUNNING grand products
       P_k = P_{k-1} * prod_i (gamma - enc(s_i)),   enc as below,
       Q_k = Q_{k-1} * prod_i (gamma - enc(orig_i))
   over its sorted run (P) and its re-opened original records (Q). The
   running products cross the chunk boundary ONLY as hiding commitments
   acc_p_cm_k = Poseidon(P_k, blind), acc_q_cm_k = Poseidon(Q_k, blind)
   — chained exactly like the boundary records (the chain starts at the
   public commitment to 1 with blind 0). The final tally-sum proof opens
   acc_p_cm_K and acc_q_cm_K and constrains P_K = Q_K WITHOUT revealing
   the value: the permutation check yields only its accept bit.

   NOTE — an earlier revision published per-chunk products pp_k =
   rho_k*P_k and qq_k = rho_k*Q_k with a SHARED blind rho_k, checking
   prod pp = prod qq publicly. That design leaks: the public ratio
   pp_k/qq_k = P_k/Q_k is a deterministic function of the private
   records (enc has no per-record blinding), so anyone holding a guess
   of the two record multisets of chunk k can CONFIRM the guess against
   the public ratio — a confirmation channel on exactly the data
   (per-ballot validity) the protocol hides. The hiding accumulator
   chain removes the channel at the cost of 4 Poseidon hashes per run
   proof and 2 openings + 1 equality in the tally-sum proof.

### Aggregation layer

The aggregator (a verifier program, NOT trusted: everything it checks is
re-checkable by anyone) verifies:

* all 2K+1 Groth16 proofs (or one SnarkPack aggregate of them, ~40 KB);
* `bb` chain: bb_0 = 0, adjacent equality, bb_K = bb_commitment
  (recomputed from the admitted board itself);
* boundary chain: adjacent boundary commitments equal; sentinel at 0;
* product chains: acc_p_cm_0 = acc_q_cm_0 = commit(1, 0); adjacency via
  the shared publics of consecutive run proofs; equality of the FINAL
  accumulators proven by the tally-sum circuit (the permutation check);
* challenge: gamma, delta recomputed from (statement, rc_1..K, sc_1..K);
* tally: the tally-sum proof opens the tc_k and constrains their sum to
  the public tally_counts — revealing ONLY the total, never a partial
  tally.

This is implemented as `zk::chunked::verify_chunked_public_transcript`
(public data + proof objects only; `prove_chunked` routes its aggregate
verification through it, and `tests/chunked_transcript_tests.rs` checks
every malicious-transcript mutation).

## Public values and leakage

The complete public transcript (`zk::chunked::ChunkedTranscript`, audited
by `chunked_transcript_tests::public_transcript_field_audit`):

| value | what it is | why it does not leak |
|---|---|---|
| `bb_0..bb_K` | board-chain snapshots at chunk boundaries | deterministic functions of the PUBLIC admitted board (Poseidon fold of the commitments); anyone can recompute them |
| `rc_1..rc_K` | per-chunk record commitments (board order) | blinded Poseidon chains — hiding; records never appear |
| `sc_1..sc_K` | per-run sorted-record commitments | blinded Poseidon chains — hiding; the sorted order never appears |
| `boundary_cm_0..K` | run-edge record commitments | hiding (fresh blind per link); cm_0 is the public sentinel |
| `tc_1..tc_K` | partial-tally commitments | hiding; only the SUM is ever opened (by the tally-sum proof) against the public tally |
| `acc_p_cm_0..K`, `acc_q_cm_0..K` | running grand-product commitments | hiding (fresh blind per link); cm_0 is the public commit(1,0); no product value or per-chunk ratio is public |
| `gamma`, `delta` | Fiat–Shamir challenges | derived from public data (statement + rc + sc) |

Consequently: accepted identities, per-ballot validity flags, sorted
records, per-chunk partial tallies, and the nonces R_i / R_EA,i appear
in NO public transcript value — each is covered by at least one fresh
uniformly random blind inside a Poseidon commitment, and the only
non-hiding values (bb chain, challenges) are functions of already-public
data. Chunk boundaries themselves are public positions on an
already-public board. The Groth16 proofs are zero-knowledge, so they add
nothing beyond their public inputs.

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
