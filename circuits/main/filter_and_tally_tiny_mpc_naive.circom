pragma circom 2.0.0;
include "../components/filter_and_tally_mpc.circom";
component main {
    public [ eid_hash, mr, candidate_set_commitment, bb_commitment,
        num_ballots, num_voters, duplicate_rule_id, pk_ea_commitment ]
} = FilterAndTallyMpc(4, 3, 4, 0);
