pragma circom 2.0.0;

// Strategy A (required prototype): naive O(B^2) first-valid-counts.
// counted[j] = valid[j] AND no earlier VALID ballot with the same voter id.
// Invalid ballots never block later ballots — the CRITICAL invariant.
//
// Strategy B (optional, future scaling) — TODO/stub:
//   Sort valid ballots by (voter_id, board_index), prove the sort is a
//   permutation (e.g. via a grand-product / permutation argument), then a
//   single linear pass counts the first valid ballot per voter. Not needed
//   for the small/medium prototype sizes.

include "circomlib/circuits/comparators.circom";

template DuplicateFirstValid(nB) {
    signal input valid[nB];
    signal input voterId[nB];
    signal output counted[nB];

    component eq[nB][nB];
    signal priorSame[nB][nB];
    // noDup[j][k] = product over k' < k of (1 - valid[k']*same(k',j))
    signal noDup[nB][nB + 1];

    for (var j = 0; j < nB; j++) {
        noDup[j][0] <== 1;
        for (var k = 0; k < j; k++) {
            eq[j][k] = IsEqual();
            eq[j][k].in[0] <== voterId[k];
            eq[j][k].in[1] <== voterId[j];
            priorSame[j][k] <== valid[k] * eq[j][k].out;
            noDup[j][k + 1] <== noDup[j][k] * (1 - priorSame[j][k]);
        }
        counted[j] <== valid[j] * noDup[j][j];
    }
}
