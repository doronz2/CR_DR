pragma circom 2.0.0;

// pi_cast: the public cast proof of the CAST-ZK ballot format
//     B_j = (com_j, ct_open_j, pi_cast_j).
//
// Proves knowledge of (opening[9], r_com, rho_enc) such that
//
//     com    = H_ballot_com(opening, r_com)        (Poseidon, arity 10 —
//                                                   identical to the tally
//                                                   circuit's hard opening)
//     C1     = rho_enc * Base8
//     ss     = rho_enc * pk_EA
//     masked_i = m_i + Poseidon(ss.x, ss.y, i),    m = opening || r_com
//
// with rho_enc != 0 (a zero rho would make C1 the identity and ct_open
// undecryptable/trivially unmaskable). All constraints here are HARD: a
// failing pi_cast means the entry is rejected PUBLICLY before tallying.
// The tally circuit never re-proves any of this — it hard-checks only
// that the (EA-decrypted) opening opens com.

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/babyjub.circom";
include "circomlib/circuits/escalarmulany.circom";
include "circomlib/circuits/escalarmulfix.circom";

template CastProof() {
    // ---------------- public inputs ----------------
    signal input com;
    signal input pk_x;              // EA encryption public key
    signal input pk_y;
    signal input c1x;               // ct_open part 1
    signal input c1y;
    signal input masked[10];        // ct_open part 2

    // ---------------- private witness ----------------
    signal input opening[9];        // [eid_hash, id, vk.x, vk.y, candidate,
                                    //  R, sig.Rx, sig.Ry, sig.S]
    signal input r_com;
    signal input rho_enc;
    signal input rho_inv;           // forces rho_enc != 0

    rho_enc * rho_inv === 1;

    var BASE8[2] = [
        5299619240641551281634865583518297030282874472190772894086521144482721001553,
        16950150798460657717958625567821834550301663161624707787222815936182638968203
    ];

    // commitment opening (same hash as the tally circuit's hard check)
    component h = Poseidon(10);
    for (var i = 0; i < 9; i++) {
        h.inputs[i] <== opening[i];
    }
    h.inputs[9] <== r_com;
    h.out === com;

    // EA key must be a valid curve point
    component pkCheck = BabyCheck();
    pkCheck.x <== pk_x;
    pkCheck.y <== pk_y;

    // C1 = rho_enc * Base8
    component rhoBits = Num2Bits(251);
    rhoBits.in <== rho_enc;
    component mulB = EscalarMulFix(251, BASE8);
    for (var i = 0; i < 251; i++) {
        mulB.e[i] <== rhoBits.out[i];
    }
    mulB.out[0] === c1x;
    mulB.out[1] === c1y;

    // ss = rho_enc * pk_EA
    component mulP = EscalarMulAny(251);
    mulP.p[0] <== pk_x;
    mulP.p[1] <== pk_y;
    for (var i = 0; i < 251; i++) {
        mulP.e[i] <== rhoBits.out[i];
    }

    // masked_i = m_i + Poseidon(ss.x, ss.y, i)
    component padH[10];
    for (var i = 0; i < 10; i++) {
        padH[i] = Poseidon(3);
        padH[i].inputs[0] <== mulP.out[0];
        padH[i].inputs[1] <== mulP.out[1];
        padH[i].inputs[2] <== i;
        if (i < 9) {
            masked[i] === opening[i] + padH[i].out;
        } else {
            masked[i] === r_com + padH[i].out;
        }
    }
}
