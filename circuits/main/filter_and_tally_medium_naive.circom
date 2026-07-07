pragma circom 2.0.0;

// Medium variant, Strategy A (naive O(B^2) duplicates, benchmark baseline):
// NUM_BALLOTS = 128, NUM_CANDIDATES = 3, MERKLE_DEPTH = 6 (NUM_VOTERS <= 64).
// Compile with scripts/compile_circuits.sh medium.

include "./filter_and_tally.circom";

component main {
    public [
        eid_hash,
        mr,
        candidate_set_commitment,
        bb_commitment,
        num_ballots,
        num_voters,
        duplicate_rule_id,
        pk_ea_commitment,
        tally_counts
    ]
} = FilterAndTally(128, 3, 6, 0);
