pragma circom 2.0.0;

// Per-ballot validity: ciphertext opening, election-id binding, candidate
// membership, Schnorr signature, hidden nonce relation and Merkle
// membership. Every check is SOFT; `valid` is their conjunction. The
// plaintext layout is
//   pt = [eid_hash, id, vk.x, vk.y, candidate, R, sig.Rx, sig.Ry, sig.S]

include "circomlib/circuits/comparators.circom";
include "./poseidon_hashes.circom";
include "./merkle_membership.circom";
include "./signature_verify.circom";
include "./encryption_decrypt.circom";

template BallotValidity(depth, nCand) {
    signal input eid_hash;
    signal input mr;
    signal input candidates[nCand];
    signal input ct;
    signal input pt[9];
    signal input rho;
    signal input r_ea;
    signal input pathElements[depth];
    signal input pathIndex[depth];

    signal output valid;
    signal output voter_id;
    signal output candSel[nCand];

    // (1) ciphertext opening / decryption
    component open = CiphertextOpen(9);
    open.ct <== ct;
    for (var i = 0; i < 9; i++) {
        open.pt[i] <== pt[i];
    }
    open.rho <== rho;

    // (2) plaintext eid matches the public one
    component eqEid = IsEqual();
    eqEid.in[0] <== pt[0];
    eqEid.in[1] <== eid_hash;

    // (3) candidate membership (one-hot selector; candidates are distinct)
    component selEq[nCand];
    var candSum = 0;
    for (var c = 0; c < nCand; c++) {
        selEq[c] = IsEqual();
        selEq[c].in[0] <== pt[4];
        selEq[c].in[1] <== candidates[c];
        candSel[c] <== selEq[c].out;
        candSum += selEq[c].out;
    }
    signal candOk;
    candOk <== candSum;

    // (4) signature over Poseidon(eid, id, candidate, R)
    component msgh = MessageHashForSignature();
    msgh.eid_hash <== pt[0];
    msgh.id <== pt[1];
    msgh.candidate <== pt[4];
    msgh.r <== pt[5];

    component sig = SchnorrVerify();
    sig.ax <== pt[2];
    sig.ay <== pt[3];
    sig.rx <== pt[6];
    sig.ry <== pt[7];
    sig.s <== pt[8];
    sig.msg <== msgh.out;

    // (5) h = H_com(eid, id, vk, R, R_EA)   (6) leaf = H_reg(eid, id, vk, h)
    component hcom = HCom();
    hcom.eid_hash <== pt[0];
    hcom.id <== pt[1];
    hcom.vkx <== pt[2];
    hcom.vky <== pt[3];
    hcom.r <== pt[5];
    hcom.r_ea <== r_ea;

    component hreg = HReg();
    hreg.eid_hash <== pt[0];
    hreg.id <== pt[1];
    hreg.vkx <== pt[2];
    hreg.vky <== pt[3];
    hreg.h <== hcom.out;

    // (7) Merkle membership of the recomputed leaf
    component mm = MerkleMembership(depth);
    mm.leaf <== hreg.out;
    mm.root <== mr;
    for (var d = 0; d < depth; d++) {
        mm.pathElements[d] <== pathElements[d];
        mm.pathIndex[d] <== pathIndex[d];
    }

    // (8) conjunction
    signal v1;
    signal v2;
    signal v3;
    v1 <== open.ok * eqEid.out;
    v2 <== v1 * candOk;
    v3 <== v2 * sig.ok;
    valid <== v3 * mm.ok;

    voter_id <== pt[1];
}
