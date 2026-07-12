pragma circom 2.0.0;

// TIER-3 DEMO circuit: ValidityChunkMpc at REDUCED width C = 8 slots
// (3 candidates, Merkle depth 14, 14-bit identities, threshold t = 2).
//
// This proves EXACTLY the same tally-validity relation as the full
// vchunkmpc128 (ballot openings, in-circuit R_EA Lagrange combine from
// two Shamir shares, indexed registration, record emission) — only the
// number of slots per chunk differs. It exists so the 3-party MPC
// (co-circom REP3) proof of the validity relation completes quickly enough
// to run end-to-end and verify in tests/CI; the chunk width C is purely a
// performance knob (fewer slots per MPC proof, more chunks per board),
// NOT a change to the relation. See TIER3_DESIGN.md.

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
} = ValidityChunkMpc(8, 3, 14, 14, 2);
