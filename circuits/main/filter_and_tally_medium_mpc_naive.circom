pragma circom 2.0.0;

// TIER-3 full-relation instantiation: medium_mpc_naive (dupStrategy=0, nb=128, depth=6).
// dupStrategy 0 = Strategy A (naive, co-circom-MPC-friendly);
//             1 = Strategy B (sorted network; not used for the MPC path).
// See circuits/components/filter_and_tally_mpc.circom + TIER3_DESIGN.md.

include "../components/filter_and_tally_mpc.circom";

component main {
    public [
        eid_hash, mr, candidate_set_commitment, bb_commitment,
        num_ballots, num_voters, duplicate_rule_id, pk_ea_commitment
    ]
} = FilterAndTallyMpc(128, 3, 6, 0);
