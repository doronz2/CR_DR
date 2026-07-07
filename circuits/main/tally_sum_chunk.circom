pragma circom 2.0.0;

// Final stage of the CHUNKED FilterAndTally pipeline: opens the K hiding
// partial-tally commitments (one per sorted run) and constrains their SUM
// to equal the public tally — the only tally-related value ever revealed.
// Partial tallies and blinds remain private witness.

include "circomlib/circuits/poseidon.circom";

template TallySum(K, nC) {
    // ---------------- public inputs ----------------
    signal input tc[K];             // partial-tally commitments
    signal input tally_counts[nC];  // the public tally

    // ---------------- private witness ----------------
    signal input t[K][nC];          // partial tallies
    signal input blind[K];

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
}
