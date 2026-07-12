pragma circom 2.0.0;

// Chunked pipeline, phase 1: ValidityChunk with C = 128 slots,
// 3 candidates, Merkle depth 14 and 14-bit identities (NUM_VOTERS up to
// 2^14 = 16,384 registered voters). Boards up to 2^24 slots via 24-bit
// global positions.

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
} = ValidityChunk(128, 3, 14, 14);
