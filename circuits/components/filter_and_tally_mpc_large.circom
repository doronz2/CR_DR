pragma circom 2.0.0;

// LARGE monolithic Tier-3 relation: same as FilterAndTallyMpc but with a
// width-parameterized sort key (idBits/posBits) and configurable id width,
// so it holds boards of up to 2^posBits slots and 2^idBits identities
// (e.g. nb=2048, depth=11, idBits=11 for ~1000 voters). Validity records,
// the sort, duplicate counting and the tally are all internal wires; R_EA
// is combined in-circuit from per-authority shares; the tally is the public
// output. See TIER3_DESIGN.md.

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/bitify.circom";
include "./ballot_validity.circom";
include "./sort_records_wide.circom";
include "./lagrange_combine.circom";

template FilterAndTallyMpcLarge(nB, nC, depth, idBits, posBits) {
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
    for (var c = 0; c < nC; c++) { cc.inputs[c] <== candidates[c]; }
    cc.out === candidate_set_commitment;

    // num_ballots < 2^posBits; num_voters < 2^idBits and <= 2^depth
    component nbBits = Num2Bits(posBits);
    nbBits.in <== num_ballots;
    component nbOk = LessEqThan(posBits + 1);
    nbOk.in[0] <== num_ballots;
    nbOk.in[1] <== nB;
    nbOk.out === 1;

    component nvBits = Num2Bits(idBits);
    nvBits.in <== num_voters;
    if (depth < idBits) {
        component nvCap = LessEqThan(idBits + 1);
        nvCap.in[0] <== num_voters;
        nvCap.in[1] <== 1 << depth;
        nvCap.out === 1;
    }

    component activeLt[nB];
    signal active[nB];
    for (var j = 0; j < nB; j++) {
        activeLt[j] = LessThan(posBits + 1);
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
        bv[j] = BallotValidity(depth, nC, idBits);
        bv[j].eid_hash <== eid_hash;
        bv[j].mr <== mr;
        bv[j].num_voters <== num_voters;
        bv[j].active <== active[j];
        for (var c = 0; c < nC; c++) { bv[j].candidates[c] <== candidates[c]; }
        bv[j].ct <== ct[j];
        for (var i = 0; i < 9; i++) { bv[j].pt[i] <== pt[j][i]; }
        bv[j].rho <== rho[j];
        bv[j].r_ea <== comb[j].r_ea;
        bv[j].reg_vkx <== reg_vkx[j];
        bv[j].reg_vky <== reg_vky[j];
        bv[j].reg_h <== reg_h[j];
        for (var d = 0; d < depth; d++) { bv[j].pathElements[d] <== path_elements[j][d]; }
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

    // duplicates + tally via the WIDE sorted-record network; tally output
    component srt = SortRecordsWide(nB, idBits, posBits);
    for (var j = 0; j < nB; j++) {
        srt.rin[j][0] <== bv[j].valid;
        srt.rin[j][1] <== bv[j].id_eff;
        srt.rin[j][2] <== j;
        srt.rin[j][3] <== bv[j].m;
    }

    component sameId[nB];
    signal counted[nB];
    counted[0] <== srt.rout[0][0];
    for (var j = 1; j < nB; j++) {
        sameId[j] = IsEqual();
        sameId[j].in[0] <== srt.rout[j][1];
        sameId[j].in[1] <== srt.rout[j - 1][1];
        counted[j] <== srt.rout[j][0] * (1 - sameId[j].out);
    }

    component mEq[nB][nC];
    signal contrib[nB][nC];
    signal tacc[nC][nB + 1];
    for (var c = 0; c < nC; c++) {
        tacc[c][0] <== 0;
        for (var j = 0; j < nB; j++) {
            mEq[j][c] = IsEqual();
            mEq[j][c].in[0] <== srt.rout[j][3];
            mEq[j][c].in[1] <== c;
            contrib[j][c] <== counted[j] * mEq[j][c].out;
            tacc[c][j + 1] <== tacc[c][j] + contrib[j][c];
        }
        tally_counts[c] <== tacc[c][nB];
    }
}
