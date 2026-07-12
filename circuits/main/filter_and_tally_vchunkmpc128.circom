pragma circom 2.0.0;

// TIER-3 chunked pipeline, phase 1: ValidityChunkMpc with C = 128 slots,
// 3 candidates, Merkle depth 14, 14-bit identities, threshold t = 2.
// R_EA is reconstructed in-circuit from its two Shamir shares per slot, so
// it is never a witness input. Public inputs are byte-for-byte identical
// to filter_and_tally_vchunk128 (Tier-1), so the two are interchangeable
// in the chunked aggregate verifier.

include "./validity_chunk_mpc.circom";

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
} = ValidityChunkMpc(128, 3, 14, 14, 2);
