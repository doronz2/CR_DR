pragma circom 2.0.0;

// Width-parameterized Batcher odd-even mergesort over records
// r_j = (valid, id, pos, m), for the LARGE monolithic Tier-3 circuit where
// a board of up to 2^posBits slots and up to 2^idBits identities needs a
// wider packed sort key than the 8/8-bit sort_records.circom used by the
// small/medium circuits.
//
//   key = (1-valid)*2^(idBits+posBits) + id*2^posBits + pos   (ascending)
//
// orders by (-valid, id, pos): valid first, then increasing id, then board
// position. Faithful because valid in {0,1}, id < 2^idBits, pos < 2^posBits
// (the caller range-checks id/pos; pos = board index j < nB <= 2^posBits).
// A deterministic network sorts EVERY input, so output = permutation +
// sorted, no challenge needed. Schedule identical to sort_records.circom /
// mock_backend::batcher_schedule.

include "circomlib/circuits/comparators.circom";

template CompareExchangeRecordWide(idBits, posBits) {
    signal input a[4];
    signal input b[4];
    signal output lo[4];
    signal output hi[4];

    var POS = 1 << posBits;
    var IDPOS = 1 << (idBits + posBits);
    signal keyA <== (1 - a[0]) * IDPOS + a[1] * POS + a[2];
    signal keyB <== (1 - b[0]) * IDPOS + b[1] * POS + b[2];

    component gt = GreaterThan(idBits + posBits + 1);
    gt.in[0] <== keyA;
    gt.in[1] <== keyB;

    signal d[4];
    for (var f = 0; f < 4; f++) {
        d[f] <== gt.out * (b[f] - a[f]);
        lo[f] <== a[f] + d[f];
        hi[f] <== b[f] - d[f];
    }
}

template SortRecordsWide(nB, idBits, posBits) {
    signal input rin[nB][4];
    signal output rout[nB][4];

    var cur[nB][4];
    for (var j = 0; j < nB; j++) {
        for (var f = 0; f < 4; f++) {
            cur[j][f] = rin[j][f];
        }
    }

    // count comparators (same loop as the network below)
    var CX = 0;
    var p = 1;
    while (p < nB) {
        var k = p;
        while (k >= 1) {
            var j = k % p;
            while (j + k < nB) {
                var top = k;
                if (nB - j - k < k) { top = nB - j - k; }
                for (var i = 0; i < top; i++) {
                    if ((i + j) \ (2 * p) == (i + j + k) \ (2 * p)) { CX++; }
                }
                j += 2 * k;
            }
            k = k \ 2;
        }
        p *= 2;
    }
    component cx[CX];

    var c = 0;
    p = 1;
    while (p < nB) {
        var k = p;
        while (k >= 1) {
            var j = k % p;
            while (j + k < nB) {
                var top = k;
                if (nB - j - k < k) { top = nB - j - k; }
                for (var i = 0; i < top; i++) {
                    if ((i + j) \ (2 * p) == (i + j + k) \ (2 * p)) {
                        cx[c] = CompareExchangeRecordWide(idBits, posBits);
                        for (var f = 0; f < 4; f++) {
                            cx[c].a[f] <== cur[i + j][f];
                            cx[c].b[f] <== cur[i + j + k][f];
                        }
                        for (var f = 0; f < 4; f++) {
                            cur[i + j][f] = cx[c].lo[f];
                            cur[i + j + k][f] = cx[c].hi[f];
                        }
                        c++;
                    }
                }
                j += 2 * k;
            }
            k = k \ 2;
        }
        p *= 2;
    }

    for (var j = 0; j < nB; j++) {
        for (var f = 0; f < 4; f++) {
            rout[j][f] <== cur[j][f];
        }
    }
}
