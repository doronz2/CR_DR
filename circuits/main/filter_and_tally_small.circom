pragma circom 2.0.0;

// Small variant, Strategy B (sorted-record duplicates):
// NUM_BALLOTS = 16, NUM_CANDIDATES = 3, MERKLE_DEPTH = 4 (NUM_VOTERS <= 16).
// Matches cr_dr::zk::SMALL_SHAPE.

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
} = FilterAndTally(16, 3, 4, 1);
