pragma circom 2.0.0;

// TIER-3 variant of DuplicateTallySorted: identical sorted-record
// first-valid-counts logic, but the per-candidate totals are OUTPUT as
// public signals instead of being checked against a supplied public input.
//
// This is what makes the tally a decentralized RESULT rather than a value
// some party must know in advance: under MPC witness extension the sort,
// the duplicate counting, and the accumulation all run on secret shares,
// and only the final `tallyCounts` is revealed (as the circuit's public
// output). Nothing else — records, sorted order, counted flags — leaves
// the computation.

include "circomlib/circuits/comparators.circom";
include "./sort_records.circom";

template DuplicateTallySortedOut(nB, nC) {
    signal input valid[nB];
    signal input id[nB];            // valid-gated id, < 2^8
    signal input m[nB];             // candidate index, < nC
    signal output tallyCounts[nC];  // computed, revealed

    component srt = SortRecords(nB);
    for (var j = 0; j < nB; j++) {
        srt.rin[j][0] <== valid[j];
        srt.rin[j][1] <== id[j];
        srt.rin[j][2] <== j;
        srt.rin[j][3] <== m[j];
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
    signal acc[nC][nB + 1];
    for (var c = 0; c < nC; c++) {
        acc[c][0] <== 0;
        for (var j = 0; j < nB; j++) {
            mEq[j][c] = IsEqual();
            mEq[j][c].in[0] <== srt.rout[j][3];
            mEq[j][c].in[1] <== c;
            contrib[j][c] <== counted[j] * mEq[j][c].out;
            acc[c][j + 1] <== acc[c][j] + contrib[j][c];
        }
        tallyCounts[c] <== acc[c][nB];
    }
}
