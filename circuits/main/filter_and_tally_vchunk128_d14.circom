pragma circom 2.0.0;

// PROJECTION-SIZING variant (compiled for its constraint count, not
// benchmarked end-to-end): ValidityChunk with C = 128 slots, 3
// candidates, Merkle depth 14 (registration table up to 2^14 = 16,384
// voters — the depth a REAL 10^4-voter electorate needs, vs the depth-6
// circuit the measured runs use). See BENCHMARKS.md "Measured
// scalability result".

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
