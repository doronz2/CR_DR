pragma circom 2.0.0;

// Schnorr verification over BabyJubJub with a Poseidon challenge, matching
// crypto/signature.rs exactly:
//
//     c  = Poseidon(R.x, R.y, A.x, A.y, msg)   (254-bit integer scalar)
//     ok = [ S * Base8 == R + c * A ]
//
// HARD constraints (unsatisfiable if violated; the Rust witness builder
// substitutes safe dummy points for malformed ballots):
//   - A and R on the curve (BabyCheck)
//   - A not the identity (Edwards2Montgomery inside EscalarMulAny)
//   - S < 2^251 (Num2Bits)
// The verification result itself is SOFT (ok = 0/1) so invalid signatures
// simply invalidate the ballot.

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/babyjub.circom";
include "circomlib/circuits/escalarmulany.circom";
include "circomlib/circuits/escalarmulfix.circom";

template SchnorrVerify() {
    signal input ax;
    signal input ay;
    signal input rx;
    signal input ry;
    signal input s;
    signal input msg;
    signal output ok;

    var BASE8[2] = [
        5299619240641551281634865583518297030282874472190772894086521144482721001553,
        16950150798460657717958625567821834550301663161624707787222815936182638968203
    ];

    component checkA = BabyCheck();
    checkA.x <== ax;
    checkA.y <== ay;
    component checkR = BabyCheck();
    checkR.x <== rx;
    checkR.y <== ry;

    component ch = Poseidon(5);
    ch.inputs[0] <== rx;
    ch.inputs[1] <== ry;
    ch.inputs[2] <== ax;
    ch.inputs[3] <== ay;
    ch.inputs[4] <== msg;

    component cBits = Num2Bits_strict();
    cBits.in <== ch.out;

    component mulA = EscalarMulAny(254);
    mulA.p[0] <== ax;
    mulA.p[1] <== ay;
    for (var i = 0; i < 254; i++) {
        mulA.e[i] <== cBits.out[i];
    }

    component rhs = BabyAdd();
    rhs.x1 <== rx;
    rhs.y1 <== ry;
    rhs.x2 <== mulA.out[0];
    rhs.y2 <== mulA.out[1];

    component sBits = Num2Bits(251);
    sBits.in <== s;
    component mulB = EscalarMulFix(251, BASE8);
    for (var i = 0; i < 251; i++) {
        mulB.e[i] <== sBits.out[i];
    }

    component eqx = IsEqual();
    eqx.in[0] <== mulB.out[0];
    eqx.in[1] <== rhs.xout;
    component eqy = IsEqual();
    eqy.in[0] <== mulB.out[1];
    eqy.in[1] <== rhs.yout;
    ok <== eqx.out * eqy.out;
}
