pragma circom 2.0.0;

// FilterAndTallyMpc(nB, nC, depth, dupStrategy): the FULL monolithic tally
// relation for TIER-3 (decentralized / coSNARK) proving. See
// filter_and_tally.circom for the relation; the two TIER-3 differences:
//
//   * R_EA is NOT a witness input — per ballot, two Shamir shares are
//     combined in-circuit (LagrangeCombineT2), so no party reconstructs it;
//   * the tally is a public OUTPUT computed inside the circuit (revealed by
//     the MPC), not a checked public input.
//
// dupStrategy selects the duplicate-handling circuit; BOTH compute the
// identical FirstValidCounts tally:
//   * 1 = Strategy B (sorted-record, Batcher network) — matches Tier-1's
//     main circuit, but co-circom's MPC witness extension currently
//     miscompiles the sorting network's compare-exchange, so it is not
//     used for the MPC path (kept for parity / future co-circom fixes);
//   * 0 = Strategy A (naive O(nB^2), IsEqual + mul only) — co-circom's
//     MPC-VM handles it correctly, so it is the strategy the Tier-3 MPC
//     prover uses. Same relation, same tally.

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/bitify.circom";
include "./ballot_validity.circom";
include "./duplicate_sorted_out.circom";
include "./duplicate_first_valid.circom";
include "./tally_accumulator_out.circom";
include "./lagrange_combine.circom";

template FilterAndTallyMpc(nB, nC, depth, dupStrategy) {
    signal input eid_hash;
    signal input mr;
    signal input candidate_set_commitment;
    signal input bb_commitment;
    signal input num_ballots;
    signal input num_voters;
    signal input duplicate_rule_id;
    signal input pk_ea_commitment;

    signal output tally_counts[nC];

    signal input candidates[nC];
    signal input ct[nB];
    signal input pt[nB][9];
    signal input rho[nB];
    signal input r_ea_share_a[nB];
    signal input r_ea_share_b[nB];
    signal input reg_vkx[nB];
    signal input reg_vky[nB];
    signal input reg_h[nB];
    signal input path_elements[nB][depth];

    duplicate_rule_id === 1;
    signal _pk_unused;
    _pk_unused <== pk_ea_commitment * 0;

    component cc = Poseidon(nC);
    for (var c = 0; c < nC; c++) {
        cc.inputs[c] <== candidates[c];
    }
    cc.out === candidate_set_commitment;

    component nbBits = Num2Bits(8);
    nbBits.in <== num_ballots;
    component nbOk = LessEqThan(8);
    nbOk.in[0] <== num_ballots;
    nbOk.in[1] <== nB;
    nbOk.out === 1;

    component nvBits = Num2Bits(8);
    nvBits.in <== num_voters;
    if (depth < 8) {
        component nvCap = LessEqThan(9);
        nvCap.in[0] <== num_voters;
        nvCap.in[1] <== 1 << depth;
        nvCap.out === 1;
    }

    component activeLt[nB];
    signal active[nB];
    for (var j = 0; j < nB; j++) {
        activeLt[j] = LessThan(8);
        activeLt[j].in[0] <== j;
        activeLt[j].in[1] <== num_ballots;
        active[j] <== activeLt[j].out;
    }

    component comb[nB];
    for (var j = 0; j < nB; j++) {
        comb[j] = LagrangeCombineT2();
        comb[j].shares[0] <== r_ea_share_a[j];
        comb[j].shares[1] <== r_ea_share_b[j];
    }

    component bv[nB];
    for (var j = 0; j < nB; j++) {
        bv[j] = BallotValidity(depth, nC, 8);
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
        bv[j].r_ea <== comb[j].r_ea;
        bv[j].reg_vkx <== reg_vkx[j];
        bv[j].reg_vky <== reg_vky[j];
        bv[j].reg_h <== reg_h[j];
        for (var d = 0; d < depth; d++) {
            bv[j].pathElements[d] <== path_elements[j][d];
        }
    }

    component bbh[nB];
    signal acc[nB + 1];
    acc[0] <== 0;
    for (var j = 0; j < nB; j++) {
        bbh[j] = Poseidon(2);
        bbh[j].inputs[0] <== acc[j];
        bbh[j].inputs[1] <== ct[j];
        acc[j + 1] <== acc[j] + active[j] * (bbh[j].out - acc[j]);
    }
    acc[nB] === bb_commitment;

    if (dupStrategy == 1) {
        component dt = DuplicateTallySortedOut(nB, nC);
        for (var j = 0; j < nB; j++) {
            dt.valid[j] <== bv[j].valid;
            dt.id[j] <== bv[j].id_eff;
            dt.m[j] <== bv[j].m;
        }
        for (var c = 0; c < nC; c++) {
            tally_counts[c] <== dt.tallyCounts[c];
        }
    } else {
        component dup = DuplicateFirstValid(nB);
        for (var j = 0; j < nB; j++) {
            dup.valid[j] <== bv[j].valid;
            dup.voterId[j] <== bv[j].id_eff;
        }
        component ta = TallyAccumulatorOut(nB, nC);
        for (var j = 0; j < nB; j++) {
            ta.counted[j] <== dup.counted[j];
            for (var c = 0; c < nC; c++) {
                ta.candSel[j][c] <== bv[j].candSel[c];
            }
        }
        for (var c = 0; c < nC; c++) {
            tally_counts[c] <== ta.tallyCounts[c];
        }
    }
}
