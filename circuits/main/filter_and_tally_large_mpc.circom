pragma circom 2.0.0;
include "../components/filter_and_tally_mpc_large.circom";
component main {
    public [ eid_hash, mr, candidate_set_commitment, bb_commitment,
        num_ballots, num_voters, duplicate_rule_id, pk_ea_commitment ]
} = FilterAndTallyMpcLarge(2048, 3, 11, 11, 11);
