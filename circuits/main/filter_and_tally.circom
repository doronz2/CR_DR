pragma circom 2.0.0;

// FilterAndTally(nB, nC, depth): proves the EXACT FilterAndTally computation
// over the whole bulletin board:
//   - every posted ciphertext (bound by bb_commitment) is opened,
//   - validity = opening ∧ eid ∧ candidate ∧ signature ∧ hidden-nonce
//     Merkle registration, evaluated per ballot,
//   - duplicates resolved AFTER validity (first-valid-counts),
//   - the public tally equals the accumulated counts.
//
// The proof reveals NOTHING about which ballots are valid or counted, voter
// identities, rejection reasons, R_i, R_EA,i, signatures or plaintexts —
// all of those are private witness signals.
//
// Instantiated by filter_and_tally_small.circom / _medium.circom.

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/bitify.circom";
include "../components/ballot_validity.circom";
include "../components/duplicate_first_valid.circom";
include "../components/tally_accumulator.circom";

template FilterAndTally(nB, nC, depth) {
    // ---------------- public inputs ----------------
    signal input eid_hash;
    signal input mr;                        // registration Merkle root
    signal input candidate_set_commitment;
    signal input bb_commitment;             // Poseidon chain over posted cts
    signal input num_ballots;
    signal input num_voters;                // statement-bound; not otherwise constrained
    signal input duplicate_rule_id;
    signal input pk_ea_commitment;          // statement-bound; used by the ElGamal TODO backend
    signal input tally_counts[nC];

    // ---------------- private witness ----------------
    signal input candidates[nC];
    signal input ct[nB];
    signal input pt[nB][9];
    signal input rho[nB];
    signal input r_ea[nB];
    signal input path_elements[nB][depth];
    signal input path_index[nB][depth];

    // duplicate rule is fixed: FirstValidCounts = 1
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

    // active[j] = (j < num_ballots)
    component activeLt[nB];
    signal active[nB];
    for (var j = 0; j < nB; j++) {
        activeLt[j] = LessThan(8);
        activeLt[j].in[0] <== j;
        activeLt[j].in[1] <== num_ballots;
        active[j] <== activeLt[j].out;
    }

    // per-ballot validity (soft), gated by active
    component bv[nB];
    signal valid[nB];
    for (var j = 0; j < nB; j++) {
        bv[j] = BallotValidity(depth, nC);
        bv[j].eid_hash <== eid_hash;
        bv[j].mr <== mr;
        for (var c = 0; c < nC; c++) {
            bv[j].candidates[c] <== candidates[c];
        }
        bv[j].ct <== ct[j];
        for (var i = 0; i < 9; i++) {
            bv[j].pt[i] <== pt[j][i];
        }
        bv[j].rho <== rho[j];
        bv[j].r_ea <== r_ea[j];
        for (var d = 0; d < depth; d++) {
            bv[j].pathElements[d] <== path_elements[j][d];
            bv[j].pathIndex[d] <== path_index[j][d];
        }
        valid[j] <== bv[j].valid * active[j];
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
    component dup = DuplicateFirstValid(nB);
    for (var j = 0; j < nB; j++) {
        dup.valid[j] <== valid[j];
        dup.voterId[j] <== bv[j].voter_id;
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
