pragma circom 2.0.0;

// PROJECTION-SIZING variant (compiled ONLY for its constraint count, not
// benchmarked and NOT a working 16k-voter circuit): ValidityChunk with
// C = 128 slots, 3 candidates, Merkle depth 14. It widens ONLY the Merkle
// path — the dominant cost of a deeper registration tree. Identities are
// still 8-bit throughout (BallotValidity's in-range check, the sort-key
// packing, and ValidityChunk's Num2Bits(8) on num_voters), so this
// variant still admits at most 2^8 identities; a REAL 10^4-voter
// electorate additionally needs the identity width parameterized to
// >= 14 bits (a few extra comparator bits per slot, estimated < 1% —
// not yet implemented). See BENCHMARKS.md "Measured scalability result".

include "./validity_chunk.circom";

component main {
    public [
        eid_hash,
        mr,
        candidate_set_commitment,
        num_ballots,
        num_voters,
        duplicate_rule_id,
        chunk_base,
        bb_in,
        bb_out,
        rc
    ]
} = ValidityChunk(128, 3, 14);
