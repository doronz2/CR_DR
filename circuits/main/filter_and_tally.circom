pragma circom 2.0.0;

// FilterAndTally(nB, nC, depth, dupStrategy): proves the EXACT FilterAndTally
// computation over the whole bulletin board. Stage structure:
//
//   For each public board slot j:
//     open/decrypt the posted ciphertext privately (soft),
//     parse plaintext fields,
//     compute active / in-range / format flags,
//     fetch+check the public INDEXED registration row Reg[id] (HARD for
//       active in-range ids: Merkle path directions = bits of id),
//     check vk equality against Reg[id] (soft),
//     check the signature (soft),
//     check the hidden nonce relation h = H_com(eid,id,vk,R,R_EA) (soft),
//     output the private record r_j = (valid_j, id_j, pos_j, m_j).
//   Then:
//     dupStrategy = 1 (Strategy B, default): sorting network realizes
//       permutation + sortedness by (-valid,id,pos); counted flags from
//       adjacent sorted records; accumulate candidate counts.
//     dupStrategy = 0 (Strategy A, benchmark baseline): naive O(nB^2)
//       pairwise first-valid-counts.
//     Constrain accumulated counts == public tally.
//
// Duplicates are resolved AFTER validity in both strategies (first-valid-
// counts): invalid ballots never consume a voter's slot.
//
// The proof reveals NOTHING about which ballots are valid or counted, voter
// identities, rejection reasons, sorted order, R_i, R_EA,i, Merkle paths,
// signatures or plaintexts — all of those are private witness signals. The
// public outputs are exactly: the tally and the statement inputs below.
//
// Instantiated by filter_and_tally_small.circom / _medium.circom (Strategy
// B) and *_naive.circom (Strategy A).

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/bitify.circom";
include "../components/ballot_validity.circom";
include "../components/duplicate_first_valid.circom";
include "../components/duplicate_sorted.circom";
include "../components/tally_accumulator.circom";

template FilterAndTally(nB, nC, depth, dupStrategy) {
    // ---------------- public inputs ----------------
    signal input eid_hash;
    signal input mr;                        // registration Merkle root
    signal input candidate_set_commitment;
    signal input bb_commitment;             // Poseidon chain over posted cts
    signal input num_ballots;
    signal input num_voters;                // in-range window of the indexed table
    signal input duplicate_rule_id;
    // pk_ea_commitment is bound into the proof by the Groth16 verification
    // equation but carries NO in-circuit constraints (the witness has no EA
    // key to check it against). Verifiers MUST check it natively against
    // the public election data — see
    // zk::statement::statement_matches_public_data, which the CLI runs on
    // every verify/dispute.
    signal input pk_ea_commitment;          // used by the ElGamal TODO backend
    signal input tally_counts[nC];

    // ---------------- private witness ----------------
    signal input candidates[nC];
    signal input ct[nB];
    signal input pt[nB][9];
    signal input rho[nB];
    signal input r_ea[nB];
    signal input reg_vkx[nB];               // registration row Reg[id]
    signal input reg_vky[nB];
    signal input reg_h[nB];
    signal input path_elements[nB][depth];  // siblings at leaf index id

    // duplicate rule is fixed: FirstValidCounts = 1 (both strategies
    // implement the same rule; the strategy is a circuit-shape choice, not
    // a statement choice)
    duplicate_rule_id === 1;

    // candidate-set commitment opens to the candidate list
    component cc = Poseidon(nC);
    for (var c = 0; c < nC; c++) {
        cc.inputs[c] <== candidates[c];
    }
    cc.out === candidate_set_commitment;

    // num_ballots is an 8-bit integer and at most nB
    component nbBits = Num2Bits(8);
    nbBits.in <== num_ballots;
    component nbOk = LessEqThan(8);
    nbOk.in[0] <== num_ballots;
    nbOk.in[1] <== nB;
    nbOk.out === 1;

    // num_voters is an 8-bit integer and at most the tree capacity 2^depth
    component nvBits = Num2Bits(8);
    nvBits.in <== num_voters;
    if (depth < 8) {
        component nvCap = LessEqThan(9);
        nvCap.in[0] <== num_voters;
        nvCap.in[1] <== 1 << depth;
        nvCap.out === 1;
    }

    // active[j] = (j < num_ballots)
    component activeLt[nB];
    signal active[nB];
    for (var j = 0; j < nB; j++) {
        activeLt[j] = LessThan(8);
        activeLt[j].in[0] <== j;
        activeLt[j].in[1] <== num_ballots;
        active[j] <== activeLt[j].out;
    }

    // per-ballot validity + record extraction
    component bv[nB];
    for (var j = 0; j < nB; j++) {
        bv[j] = BallotValidity(depth, nC, 8); // monolithic: 8-bit ids (num_voters <= 2^depth <= 64)
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

    // bulletin-board commitment chain over the active ballots
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

    // duplicates AFTER validity, then tally accumulation
    if (dupStrategy == 1) {
        // Strategy B: sorted records (permutation via sorting network)
        component dt = DuplicateTallySorted(nB, nC);
        for (var j = 0; j < nB; j++) {
            dt.valid[j] <== bv[j].valid;
            dt.id[j] <== bv[j].id_eff;
            dt.m[j] <== bv[j].m;
        }
        for (var c = 0; c < nC; c++) {
            dt.tallyCounts[c] <== tally_counts[c];
        }
    } else {
        // Strategy A: naive O(nB^2) pairwise scan
        component dup = DuplicateFirstValid(nB);
        for (var j = 0; j < nB; j++) {
            dup.valid[j] <== bv[j].valid;
            dup.voterId[j] <== bv[j].id_eff;
        }
        component ta = TallyAccumulator(nB, nC);
        for (var j = 0; j < nB; j++) {
            ta.counted[j] <== dup.counted[j];
            for (var c = 0; c < nC; c++) {
                ta.candSel[j][c] <== bv[j].candSel[c];
            }
        }
        for (var c = 0; c < nC; c++) {
            ta.tallyCounts[c] <== tally_counts[c];
        }
    }
}
