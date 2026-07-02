pragma circom 2.0.0;

// Accumulates counted ballots into per-candidate totals and constrains them
// to equal the public tally.

template TallyAccumulator(nB, nC) {
    signal input counted[nB];
    signal input candSel[nB][nC];
    signal input tallyCounts[nC];

    signal contrib[nB][nC];
    for (var c = 0; c < nC; c++) {
        var sum = 0;
        for (var j = 0; j < nB; j++) {
            contrib[j][c] <== counted[j] * candSel[j][c];
            sum += contrib[j][c];
        }
        tallyCounts[c] === sum;
    }
}
