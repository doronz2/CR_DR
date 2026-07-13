pragma circom 2.0.0;

// Like TallyAccumulator but the per-candidate totals are OUTPUT (revealed)
// rather than checked against a supplied public input — the Tier-3
// counterpart, so the tally is the MPC's revealed result.

template TallyAccumulatorOut(nB, nC) {
    signal input counted[nB];
    signal input candSel[nB][nC];
    signal output tallyCounts[nC];

    signal contrib[nB][nC];
    signal acc[nC][nB + 1];
    for (var c = 0; c < nC; c++) {
        acc[c][0] <== 0;
        for (var j = 0; j < nB; j++) {
            contrib[j][c] <== counted[j] * candSel[j][c];
            acc[c][j + 1] <== acc[c][j] + contrib[j][c];
        }
        tallyCounts[c] <== acc[c][nB];
    }
}
