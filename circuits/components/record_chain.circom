pragma circom 2.0.0;

// Blinded Poseidon chain commitment over private records
// r_j = (valid, id, pos, m):
//     acc_0 = blind,   acc_{j+1} = Poseidon(acc_j, valid_j, id_j, pos_j, m_j)
// Binding under Poseidon collision resistance; hiding via the private
// blind. Used for the phase-1 record commitments rc_k (original board
// order) and sc_k (sorted runs) of the chunked tally pipeline — both are
// published BEFORE the multiset challenge gamma is derived, which is what
// makes the grand-product permutation argument sound.

include "circomlib/circuits/poseidon.circom";

template RecordChain(C) {
    signal input blind;
    signal input records[C][4];   // [valid, id, pos, m]
    signal output out;

    component h[C];
    signal acc[C + 1];
    acc[0] <== blind;
    for (var j = 0; j < C; j++) {
        h[j] = Poseidon(5);
        h[j].inputs[0] <== acc[j];
        h[j].inputs[1] <== records[j][0];
        h[j].inputs[2] <== records[j][1];
        h[j].inputs[3] <== records[j][2];
        h[j].inputs[4] <== records[j][3];
        acc[j + 1] <== h[j].out;
    }
    out <== acc[C];
}

// Hiding commitment to a single record (chunk-boundary records):
//     cm = Poseidon(valid, id, pos, m, blind)
template RecordCommit() {
    signal input record[4];
    signal input blind;
    signal output out;

    component h = Poseidon(5);
    h.inputs[0] <== record[0];
    h.inputs[1] <== record[1];
    h.inputs[2] <== record[2];
    h.inputs[3] <== record[3];
    h.inputs[4] <== blind;
    out <== h.out;
}
