pragma circom 2.0.0;

// Phase-1 chunk of the CHUNKED FilterAndTally pipeline (see
// CHUNKED_TALLY_DESIGN.md): per-slot validity for C consecutive board
// slots, plus the two cross-chunk bindings:
//
//   * bulletin-board chain segment: bb_in -> bb_out over the chunk's
//     posted ciphertexts (chaining all chunks with bb_0 = 0 and
//     bb_K = bb_commitment reproduces the monolithic board binding);
//   * blinded record commitment rc over the chunk's records
//     r_j = (valid, id, pos = chunk_base + j, m), published BEFORE the
//     multiset challenge is derived.
//
// Per-slot validity is EXACTLY the monolithic relation's stage
// (BallotValidity: soft flags, deterministic in-range, HARD indexed
// registration-row fetch). Duplicate handling lives in phase 2
// (sorted_run_chunk.circom). Board positions are global (16-bit), so the
// chunk pipeline supports boards up to 2^16 slots.

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/bitify.circom";
include "../components/ballot_validity.circom";
include "../components/record_chain.circom";

template ValidityChunk(C, nC, depth) {
    // ---------------- public inputs ----------------
    signal input eid_hash;
    signal input mr;
    signal input candidate_set_commitment;
    signal input num_ballots;               // GLOBAL board size (16-bit)
    signal input num_voters;
    signal input duplicate_rule_id;
    signal input chunk_base;                // k * C (16-bit)
    signal input bb_in;                     // board-chain state entering
    signal input bb_out;                    // board-chain state leaving
    signal input rc;                        // blinded record commitment

    // ---------------- private witness ----------------
    signal input candidates[nC];
    signal input ct[C];
    signal input pt[C][9];
    signal input rho[C];
    signal input r_ea[C];
    signal input reg_vkx[C];
    signal input reg_vky[C];
    signal input reg_h[C];
    signal input path_elements[C][depth];
    signal input rc_blind;

    duplicate_rule_id === 1;

    component cc = Poseidon(nC);
    for (var c = 0; c < nC; c++) {
        cc.inputs[c] <== candidates[c];
    }
    cc.out === candidate_set_commitment;

    // range checks for the comparator inputs below
    component nbBits = Num2Bits(16);
    nbBits.in <== num_ballots;
    component cbBits = Num2Bits(16);
    cbBits.in <== chunk_base;
    component nvBits = Num2Bits(8);
    nvBits.in <== num_voters;
    if (depth < 8) {
        component nvCap = LessEqThan(9);
        nvCap.in[0] <== num_voters;
        nvCap.in[1] <== 1 << depth;
        nvCap.out === 1;
    }

    // active[j] = (chunk_base + j < num_ballots), positions are global
    component activeLt[C];
    signal active[C];
    for (var j = 0; j < C; j++) {
        activeLt[j] = LessThan(17);
        activeLt[j].in[0] <== chunk_base + j;
        activeLt[j].in[1] <== num_ballots;
        active[j] <== activeLt[j].out;
    }

    // per-slot validity — identical to the monolithic stage
    component bv[C];
    for (var j = 0; j < C; j++) {
        bv[j] = BallotValidity(depth, nC);
        bv[j].eid_hash <== eid_hash;
        bv[j].mr <== mr;
        bv[j].num_voters <== num_voters;
        bv[j].active <== active[j];
        for (var c = 0; c < nC; c++) {
            bv[j].candidates[c] <== candidates[c];
        }
        bv[j].ct <== ct[j];
        for (var i = 0; i < 9; i++) {
            bv[j].pt[i] <== pt[j][i];
        }
        bv[j].rho <== rho[j];
        bv[j].r_ea <== r_ea[j];
        bv[j].reg_vkx <== reg_vkx[j];
        bv[j].reg_vky <== reg_vky[j];
        bv[j].reg_h <== reg_h[j];
        for (var d = 0; d < depth; d++) {
            bv[j].pathElements[d] <== path_elements[j][d];
        }
    }

    // bulletin-board chain segment over the active slots
    component bbh[C];
    signal acc[C + 1];
    acc[0] <== bb_in;
    for (var j = 0; j < C; j++) {
        bbh[j] = Poseidon(2);
        bbh[j].inputs[0] <== acc[j];
        bbh[j].inputs[1] <== ct[j];
        acc[j + 1] <== acc[j] + active[j] * (bbh[j].out - acc[j]);
    }
    acc[C] === bb_out;

    // record commitment: r_j = (valid, id_eff, chunk_base + j, m)
    component rchain = RecordChain(C);
    rchain.blind <== rc_blind;
    for (var j = 0; j < C; j++) {
        rchain.records[j][0] <== bv[j].valid;
        rchain.records[j][1] <== bv[j].id_eff;
        rchain.records[j][2] <== chunk_base + j;
        rchain.records[j][3] <== bv[j].m;
    }
    rchain.out === rc;
}
