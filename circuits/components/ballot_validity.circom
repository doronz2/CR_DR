pragma circom 2.0.0;

// Per-ballot validity against the INDEXED registration table. The plaintext
// layout is
//   pt = [eid_hash, id, vk.x, vk.y, candidate, R, sig.Rx, sig.Ry, sig.S]
//
// Check classes:
//
// * HARD, gated by active: the ballot-commitment opening
//   com === Poseidon(pt || rho). Under the CAST-ZK format every board
//   entry carries a publicly verified pi_cast, so the EA can always
//   decrypt the opening that satisfies this — the prover cannot withhold
//   an opening to soft-invalidate a ballot, and a voter cannot make the
//   tally unsatisfiable (all downstream checks are soft-safe for
//   arbitrary opening fields, incl. the Schnorr gadget).
//
// * SOFT (drive the 0/1 `valid` flag): election-id binding, candidate
//   membership, Schnorr signature (soft-safe), vk equality against the
//   registration row, and the hidden nonce relation
//   h = H_com(eid, id, vk, R, R_EA) against the row's h.
//
// * DETERMINISTIC in-range flag: the claimed id is decomposed with
//   Num2Bits_strict (canonical, < p — the prover has NO freedom in the
//   bits), in_range = (id < 2^8) AND (id < num_voters).
//
// * HARD, gated by (active AND in_range): the registration row fetch. The
//   witness supplies the row values (reg_vkx, reg_vky, reg_h) and sibling
//   hashes; the Merkle DIRECTION BITS ARE THE BITS OF id ITSELF and the
//   recomputed root must equal the public MR. The identity in a ballot
//   therefore determines its registration row: the prover cannot withhold
//   the path of an in-range identity or bind the ballot to another row to
//   flip a truly valid ballot to invalid (or vice versa).
//
// Out-of-range ids and malformed openings stay soft-invalid, so chaff and
// garbage never make the witness unsatisfiable.

include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/poseidon.circom";
include "./poseidon_hashes.circom";
include "./signature_verify.circom";

template BallotValidity(depth, nCand) {
    signal input eid_hash;          // public election id hash
    signal input mr;                // public registration Merkle root
    signal input num_voters;        // public, 8-bit (checked by main)
    signal input active;            // 0/1, derived from public num_ballots
    signal input candidates[nCand];
    signal input ct;
    signal input pt[9];
    signal input rho;
    signal input r_ea;
    signal input reg_vkx;           // registration row Reg[id]: vk.x
    signal input reg_vky;           //                           vk.y
    signal input reg_h;             //                           h
    signal input pathElements[depth];

    signal output valid;            // active-gated 0/1 validity
    signal output id_eff;           // valid * id (< 2^8)
    signal output m;                // candidate index (0 if no match)
    signal output candSel[nCand];

    // (1) ballot-commitment opening: HARD, gated by active
    component open = Poseidon(10);
    for (var i = 0; i < 9; i++) {
        open.inputs[i] <== pt[i];
    }
    open.inputs[9] <== rho;
    active * (open.out - ct) === 0;

    // (2) plaintext eid matches the public one (soft)
    component eqEid = IsEqual();
    eqEid.in[0] <== pt[0];
    eqEid.in[1] <== eid_hash;

    // (3) candidate membership (one-hot selector; candidates are distinct)
    component selEq[nCand];
    var candSum = 0;
    var mSum = 0;
    for (var c = 0; c < nCand; c++) {
        selEq[c] = IsEqual();
        selEq[c].in[0] <== pt[4];
        selEq[c].in[1] <== candidates[c];
        candSel[c] <== selEq[c].out;
        candSum += selEq[c].out;
        mSum += c * selEq[c].out;
    }
    signal candOk;
    candOk <== candSum;
    m <== mSum;

    // (4) signature over Poseidon(eid, id, candidate, R): SOFT-SAFE — the
    //     gadget stays satisfiable for arbitrary field inputs (off-curve
    //     vk / R, non-canonical S) and just drives ok to 0
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

    // (5) deterministic in-range flag from the STRICT id decomposition
    component idBits = Num2Bits_strict();
    idBits.in <== pt[1];
    var hiSum = 0;
    for (var d = 8; d < 254; d++) {
        hiSum += idBits.out[d];
    }
    component hiZero = IsZero();
    hiZero.in <== hiSum;
    var loSum = 0;
    for (var d = 0; d < 8; d++) {
        loSum += idBits.out[d] * (1 << d);
    }
    signal id_low;
    id_low <== loSum;
    component ltNv = LessThan(9);
    ltNv.in[0] <== id_low;
    ltNv.in[1] <== num_voters;
    signal in_range;
    in_range <== hiZero.out * ltNv.out;
    signal gate;
    gate <== active * in_range;

    // (6) HARD indexed registration-row fetch (gated): the leaf commits to
    //     (eid, id, row vk, row h) and the path direction bits are id's
    //     own bits, so row = Reg[id] and row.id = id by construction.
    component leafH = HReg();
    leafH.eid_hash <== eid_hash;    // PUBLIC eid, not pt[0]
    leafH.id <== pt[1];
    leafH.vkx <== reg_vkx;
    leafH.vky <== reg_vky;
    leafH.h <== reg_h;

    signal cur[depth + 1];
    signal left[depth];
    signal right[depth];
    component hh[depth];
    cur[0] <== leafH.out;
    for (var d = 0; d < depth; d++) {
        left[d] <== cur[d] + idBits.out[d] * (pathElements[d] - cur[d]);
        right[d] <== pathElements[d] + idBits.out[d] * (cur[d] - pathElements[d]);
        hh[d] = Poseidon(2);
        hh[d].inputs[0] <== left[d];
        hh[d].inputs[1] <== right[d];
        cur[d + 1] <== hh[d].out;
    }
    gate * (cur[depth] - mr) === 0;

    // (7) soft row consistency: ballot vk equals Reg[id].vk, and the hidden
    //     nonce relation h = H_com(eid, id, vk, R, R_EA) equals Reg[id].h
    component vkxEq = IsEqual();
    vkxEq.in[0] <== pt[2];
    vkxEq.in[1] <== reg_vkx;
    component vkyEq = IsEqual();
    vkyEq.in[0] <== pt[3];
    vkyEq.in[1] <== reg_vky;
    signal vk_match;
    vk_match <== vkxEq.out * vkyEq.out;

    component hcom = HCom();
    hcom.eid_hash <== pt[0];
    hcom.id <== pt[1];
    hcom.vkx <== pt[2];
    hcom.vky <== pt[3];
    hcom.r <== pt[5];
    hcom.r_ea <== r_ea;
    component hEq = IsEqual();
    hEq.in[0] <== hcom.out;
    hEq.in[1] <== reg_h;

    // (8) conjunction (opening is hard, not a flag)
    signal v2;
    signal v3;
    signal v4;
    signal v5;
    signal v6;
    v2 <== eqEid.out * candOk;
    v3 <== v2 * sig.ok;
    v4 <== v3 * in_range;
    v5 <== v4 * vk_match;
    v6 <== v5 * hEq.out;
    valid <== v6 * active;

    id_eff <== valid * id_low;
}
