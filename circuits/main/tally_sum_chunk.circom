pragma circom 2.0.0;

// Final stage of the CHUNKED FilterAndTally pipeline:
//   * opens the K hiding partial-tally commitments (one per sorted run)
//     and constrains their SUM to equal the public tally — the only
//     tally-related value ever revealed; partial tallies and blinds
//     remain private witness;
//   * opens the two FINAL running-product commitments of the sorted-run
//     accumulator chains and constrains the accumulators to be EQUAL —
//     the grand-product/permutation equality, proven without revealing
//     any product value (see CHUNKED_TALLY_DESIGN.md, "Public values and
//     leakage").

include "circomlib/circuits/poseidon.circom";

template TallySum(K, nC) {
    // ---------------- public inputs ----------------
    signal input tc[K];             // partial-tally commitments
    signal input acc_p_cm;          // final sorted-side product commitment
    signal input acc_q_cm;          // final original-side product commitment
    signal input tally_counts[nC];  // the public tally

    // ---------------- private witness ----------------
    signal input t[K][nC];          // partial tallies
    signal input blind[K];
    signal input acc_p;             // final running products + blinds
    signal input acc_p_blind;
    signal input acc_q;
    signal input acc_q_blind;

    component h[K];
    for (var k = 0; k < K; k++) {
        h[k] = Poseidon(nC + 1);
        for (var c = 0; c < nC; c++) {
            h[k].inputs[c] <== t[k][c];
        }
        h[k].inputs[nC] <== blind[k];
        h[k].out === tc[k];
    }

    for (var c = 0; c < nC; c++) {
        var sum = 0;
        for (var k = 0; k < K; k++) {
            sum += t[k][c];
        }
        tally_counts[c] === sum;
    }

    // grand-product / permutation equality, hidden behind commitments
    component pcm = Poseidon(2);
    pcm.inputs[0] <== acc_p;
    pcm.inputs[1] <== acc_p_blind;
    pcm.out === acc_p_cm;
    component qcm = Poseidon(2);
    qcm.inputs[0] <== acc_q;
    qcm.inputs[1] <== acc_q_blind;
    qcm.out === acc_q_cm;
    acc_p === acc_q;
}
