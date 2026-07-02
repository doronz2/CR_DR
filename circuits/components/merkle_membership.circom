pragma circom 2.0.0;

// Poseidon Merkle membership check with a SOFT result (ok = 0/1), so that
// non-membership makes a ballot invalid instead of making the whole
// FilterAndTally witness unsatisfiable.

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/comparators.circom";

template MerkleMembership(depth) {
    signal input leaf;
    signal input root;
    signal input pathElements[depth];
    // Direction bits, leaf level first: 0 = current node is the left child.
    signal input pathIndex[depth];
    signal output ok;

    signal cur[depth + 1];
    signal left[depth];
    signal right[depth];
    component h[depth];

    cur[0] <== leaf;
    for (var i = 0; i < depth; i++) {
        pathIndex[i] * (1 - pathIndex[i]) === 0;
        left[i] <== cur[i] + pathIndex[i] * (pathElements[i] - cur[i]);
        right[i] <== pathElements[i] + pathIndex[i] * (cur[i] - pathElements[i]);
        h[i] = Poseidon(2);
        h[i].inputs[0] <== left[i];
        h[i].inputs[1] <== right[i];
        cur[i + 1] <== h[i].out;
    }

    component eq = IsEqual();
    eq.in[0] <== cur[depth];
    eq.in[1] <== root;
    ok <== eq.out;
}
