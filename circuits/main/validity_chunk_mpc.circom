pragma circom 2.0.0;

// TIER-3 (decentralized / coSNARK) variant of ValidityChunk.
//
// IDENTICAL to validity_chunk.circom in every public input, every check,
// and every emitted record — with ONE change: the authority nonce R_EA is
// NOT a witness input. Instead each slot carries the t Shamir SHARES of
// R_EA, and R_EA is reconstructed IN-CIRCUIT via LagrangeCombine
// (see components/lagrange_combine.circom). Consequently:
//
//   * no party ever holds R_EA in the clear — under co-circom MPC witness
//     extension each authority contributes its own secret-shared share
//     column, and the Lagrange combine runs on shares;
//   * the PUBLIC inputs are byte-for-byte those of ValidityChunk, so the
//     chunked aggregate verifier, Fiat-Shamir derivation, and public
//     transcript are unchanged — a Tier-3 proof drops into the exact same
//     pipeline as a Tier-1 one and verifies under the same key.
//
// t is the reconstruction threshold (default 2, the compiled instance).

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/bitify.circom";
include "../components/ballot_validity.circom";
include "../components/record_chain.circom";
include "../components/lagrange_combine.circom";

template ValidityChunkMpc(C, nC, depth, idBits, t) {
    assert(t == 2); // only the t=2 Lagrange combine is instantiated

    // ---------------- public inputs (identical to ValidityChunk) --------
    signal input eid_hash;
    signal input mr;
    signal input candidate_set_commitment;
    signal input num_ballots;
    signal input num_voters;
    signal input duplicate_rule_id;
    signal input chunk_base;
    signal input bb_in;
    signal input bb_out;
    signal input rc;

    // ---------------- private witness ----------------
    signal input candidates[nC];
    signal input ct[C];
    signal input pt[C][9];
    signal input rho[C];
    // TIER-3: per-slot Shamir SHARES of R_EA (index 1 and index 2), NOT
    // R_EA. Two SEPARATELY-NAMED arrays so that each authority is an
    // independent co-circom input provider: authority 1 supplies (and
    // secret-shares) only `r_ea_share_a`, authority 2 only `r_ea_share_b`;
    // co-circom `merge-input-shares` combines them by name on shares, so
    // neither authority's share array is ever revealed to the other and
    // R_EA itself is reconstructed only inside the MPC (LagrangeCombineT2).
    signal input r_ea_share_a[C];   // authority 1's share (Shamir index 1)
    signal input r_ea_share_b[C];   // authority 2's share (Shamir index 2)
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

    component nbBits = Num2Bits(24);
    nbBits.in <== num_ballots;
    component cbBits = Num2Bits(24);
    cbBits.in <== chunk_base;
    component nvBits = Num2Bits(idBits);
    nvBits.in <== num_voters;
    if (depth < idBits) {
        component nvCap = LessEqThan(idBits + 1);
        nvCap.in[0] <== num_voters;
        nvCap.in[1] <== 1 << depth;
        nvCap.out === 1;
    }

    component activeLt[C];
    signal active[C];
    for (var j = 0; j < C; j++) {
        activeLt[j] = LessThan(25);
        activeLt[j].in[0] <== chunk_base + j;
        activeLt[j].in[1] <== num_ballots;
        active[j] <== activeLt[j].out;
    }

    // TIER-3: reconstruct R_EA[j] from its two shares, in-circuit.
    component comb[C];
    for (var j = 0; j < C; j++) {
        comb[j] = LagrangeCombineT2();
        comb[j].shares[0] <== r_ea_share_a[j];
        comb[j].shares[1] <== r_ea_share_b[j];
    }

    // per-slot validity — identical to the monolithic stage
    component bv[C];
    for (var j = 0; j < C; j++) {
        bv[j] = BallotValidity(depth, nC, idBits);
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
        bv[j].r_ea <== comb[j].r_ea;   // reconstructed inside the circuit
        bv[j].reg_vkx <== reg_vkx[j];
        bv[j].reg_vky <== reg_vky[j];
        bv[j].reg_h <== reg_h[j];
        for (var d = 0; d < depth; d++) {
            bv[j].pathElements[d] <== path_elements[j][d];
        }
    }

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
