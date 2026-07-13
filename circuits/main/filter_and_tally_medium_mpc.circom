pragma circom 2.0.0;

// TIER-3 FULL-RELATION circuit: the ENTIRE monolithic FilterAndTally
// (validity -> records -> Batcher sort -> first-valid duplicate counting ->
// tally) proven in one co-circom MPC over a secret-shared witness. This is
// the vehicle for FULL decentralization: unlike the chunked pipeline
// (whose cross-chunk records, sorted records, grand products and partial
// tallies are computed by a central orchestrator), here EVERY intermediate
// — validity records, the sorted sequence, the duplicate/counted flags,
// the partial candidate sums — is an INTERNAL circuit wire, so under MPC
// witness extension none of them is ever centrally constructed or seen by
// any party. The only inputs are the per-ballot openings (provided by the
// opening provider) and the two R_EA Shamir-share arrays (one per
// authority provider); R_EA is reconstructed in-circuit (LagrangeCombineT2).
//
// Difference from FilterAndTally(nB,nC,depth,1):
//   * r_ea is NOT an input — per ballot, two Shamir shares are combined
//     in-circuit;
//   * the tally is a public OUTPUT (DuplicateTallySortedOut), computed in
//     MPC and revealed, not a checked public input.
// Public statement (eid_hash, mr, candidate-set/bb commitments,
// num_ballots, num_voters, duplicate_rule_id, pk_ea_commitment, and the
// output tally_counts) is exactly the TallyStatement the Tier-1 verifier
// checks — a Tier-3 proof establishes the same public statement.

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/bitify.circom";
include "../components/ballot_validity.circom";
include "../components/duplicate_sorted_out.circom";
include "../components/lagrange_combine.circom";

template FilterAndTallyMpc(nB, nC, depth) {
    // ---------------- public inputs ----------------
    signal input eid_hash;
    signal input mr;
    signal input candidate_set_commitment;
    signal input bb_commitment;
    signal input num_ballots;
    signal input num_voters;
    signal input duplicate_rule_id;
    signal input pk_ea_commitment;

    // ---------------- public OUTPUT (the decentralized result) ----------
    signal output tally_counts[nC];

    // ---------------- private witness ----------------
    signal input candidates[nC];
    signal input ct[nB];
    signal input pt[nB][9];
    signal input rho[nB];
    signal input r_ea_share_a[nB];   // authority 1 (Shamir index 1)
    signal input r_ea_share_b[nB];   // authority 2 (Shamir index 2)
    signal input reg_vkx[nB];
    signal input reg_vky[nB];
    signal input reg_h[nB];
    signal input path_elements[nB][depth];

    duplicate_rule_id === 1;
    // pk_ea_commitment carries no in-circuit constraint (as in Tier-1);
    // verifiers bind it natively via statement_matches_public_data.
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

    // in-circuit R_EA reconstruction from the two shares
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

    // duplicates + tally: sorted-record, counts revealed as output
    component dt = DuplicateTallySortedOut(nB, nC);
    for (var j = 0; j < nB; j++) {
        dt.valid[j] <== bv[j].valid;
        dt.id[j] <== bv[j].id_eff;
        dt.m[j] <== bv[j].m;
    }
    for (var c = 0; c < nC; c++) {
        tally_counts[c] <== dt.tallyCounts[c];
    }
}

component main {
    public [
        eid_hash,
        mr,
        candidate_set_commitment,
        bb_commitment,
        num_ballots,
        num_voters,
        duplicate_rule_id,
        pk_ea_commitment
    ]
} = FilterAndTallyMpc(128, 3, 6);
