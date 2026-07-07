pragma circom 2.0.0;

// Strategy B permutation machinery: a Batcher odd-even mergesort NETWORK
// applied in-circuit to the private records r_j = (valid, id, pos, m).
//
// Soundness note: a deterministic sorting network sorts EVERY input, so its
// output is simultaneously (a) a permutation of the input records and
// (b) sorted by the comparator key — for all witnesses, with no challenge
// or prover-supplied permutation. This realizes "prove sorted_records is a
// permutation of original_records + check sortedness" without needing a
// Plonk-style linear permutation argument (not soundly available in this
// Groth16 stack: any in-circuit "random" challenge would be witness-
// dependent and prover-controlled).
//
// Cost: O(nB log^2 nB) comparators, each ~25 constraints.
//
// The comparator schedule MUST stay identical to
// `cr_dr::zk::mock_backend::batcher_schedule` (native mirror).

include "circomlib/circuits/comparators.circom";

// Compare-exchange of two records by the packed lexicographic key
//     key = (1-valid)*2^16 + id*2^8 + pos      (ascending)
// which orders by (-valid, id, pos): valid records first, then increasing
// id, then increasing board position. Faithful because the relation bounds
// valid in {0,1}, id < 2^8, pos < 2^8, so key < 2^17.
template CompareExchangeRecord() {
    signal input a[4];   // [valid, id, pos, m]
    signal input b[4];
    signal output lo[4];
    signal output hi[4];

    signal keyA <== (1 - a[0]) * 65536 + a[1] * 256 + a[2];
    signal keyB <== (1 - b[0]) * 65536 + b[1] * 256 + b[2];

    component gt = GreaterThan(17);
    gt.in[0] <== keyA;
    gt.in[1] <== keyB;

    signal d[4];
    for (var f = 0; f < 4; f++) {
        d[f] <== gt.out * (b[f] - a[f]);
        lo[f] <== a[f] + d[f];
        hi[f] <== b[f] - d[f];
    }
}

// Number of comparators in Batcher's odd-even mergesort on n elements.
// Same loop structure as the network below and as the native mirror.
function batcher_count(n) {
    var cnt = 0;
    var p = 1;
    while (p < n) {
        var k = p;
        while (k >= 1) {
            var j = k % p;
            while (j + k < n) {
                var top = k;
                if (n - j - k < k) {
                    top = n - j - k;
                }
                for (var i = 0; i < top; i++) {
                    if ((i + j) \ (2 * p) == (i + j + k) \ (2 * p)) {
                        cnt++;
                    }
                }
                j += 2 * k;
            }
            k = k \ 2;
        }
        p *= 2;
    }
    return cnt;
}

// Sort nB records ascending by (-valid, id, pos).
template SortRecords(nB) {
    signal input rin[nB][4];
    signal output rout[nB][4];

    var CX = batcher_count(nB);
    component cx[CX];

    // cur[j][f] tracks the latest signal expression at position j.
    var cur[nB][4];
    for (var j = 0; j < nB; j++) {
        for (var f = 0; f < 4; f++) {
            cur[j][f] = rin[j][f];
        }
    }

    var c = 0;
    var p = 1;
    while (p < nB) {
        var k = p;
        while (k >= 1) {
            var j = k % p;
            while (j + k < nB) {
                var top = k;
                if (nB - j - k < k) {
                    top = nB - j - k;
                }
                for (var i = 0; i < top; i++) {
                    if ((i + j) \ (2 * p) == (i + j + k) \ (2 * p)) {
                        cx[c] = CompareExchangeRecord();
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
