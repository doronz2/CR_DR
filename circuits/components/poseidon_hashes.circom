pragma circom 2.0.0;

// Poseidon hash gadgets for the CR-DR construction. Arities double as
// (weak) domain separation — see README.

include "circomlib/circuits/poseidon.circom";

// h = H_com(eid_hash, id, vk.x, vk.y, R, R_EA)
template HCom() {
    signal input eid_hash;
    signal input id;
    signal input vkx;
    signal input vky;
    signal input r;
    signal input r_ea;
    signal output out;

    component p = Poseidon(6);
    p.inputs[0] <== eid_hash;
    p.inputs[1] <== id;
    p.inputs[2] <== vkx;
    p.inputs[3] <== vky;
    p.inputs[4] <== r;
    p.inputs[5] <== r_ea;
    out <== p.out;
}

// leaf = H_reg(eid_hash, id, vk.x, vk.y, h)
template HReg() {
    signal input eid_hash;
    signal input id;
    signal input vkx;
    signal input vky;
    signal input h;
    signal output out;

    component p = Poseidon(5);
    p.inputs[0] <== eid_hash;
    p.inputs[1] <== id;
    p.inputs[2] <== vkx;
    p.inputs[3] <== vky;
    p.inputs[4] <== h;
    out <== p.out;
}

// msg = Poseidon(eid_hash, id, candidate, R)
template MessageHashForSignature() {
    signal input eid_hash;
    signal input id;
    signal input candidate;
    signal input r;
    signal output out;

    component p = Poseidon(4);
    p.inputs[0] <== eid_hash;
    p.inputs[1] <== id;
    p.inputs[2] <== candidate;
    p.inputs[3] <== r;
    out <== p.out;
}
