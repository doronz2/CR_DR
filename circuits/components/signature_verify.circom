pragma circom 2.0.0;

// Schnorr verification over BabyJubJub with a Poseidon challenge, matching
// crypto/signature.rs exactly:
//
//     c  = Poseidon(R.x, R.y, A.x, A.y, msg)   (254-bit integer scalar)
//     ok = [ S * Base8 == R + c * A ]
//
// SOFT-SAFE for arbitrary field inputs: under the CAST-ZK format the tally
// circuit HARD-opens the ballot commitment, so the plaintext is forced by
// public data and a voter could commit to arbitrary garbage with a valid
// pi_cast. The tally witness must stay satisfiable for EVERY opening, so:
//   - A, R on the curve   -> SOFT flags (Edwards equation); off-curve
//     inputs are muxed to Base8 before any curve arithmetic;
//   - c*A is computed with a COMPLETE Edwards double-and-add (BabyAdd /
//     BabyDbl are complete on BabyJubJub for all curve points, including
//     the identity and small-order torsion — circomlib's Montgomery-ladder
//     EscalarMulAny is NOT safe for torsion inputs);
//   - S < 2^251           -> strict decomposition + soft top-zero flag
//     (the low 251 bits feed the fixed-base ladder, which is always safe).
// ok = pointEq AND onCurveA AND onCurveR AND sTopZero. For well-formed
// inputs the muxed values are the real ones, so acceptance is unchanged.

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/babyjub.circom";
include "circomlib/circuits/escalarmulfix.circom";

// Soft Edwards-membership check: 168700*x^2 + y^2 == 1 + 168696*x^2*y^2.
template SoftOnCurve() {
    signal input x;
    signal input y;
    signal output ok;

    signal x2;
    signal y2;
    signal x2y2;
    x2 <== x * x;
    y2 <== y * y;
    x2y2 <== x2 * y2;
    component eq = IsEqual();
    eq.in[0] <== 168700 * x2 + y2;
    eq.in[1] <== 1 + 168696 * x2y2;
    ok <== eq.out;
}

// out = sum_i e[i]*2^i * P via complete Edwards double-and-add. Safe for
// EVERY on-curve P (identity and torsion included); ~14 constraints/bit.
template CompleteEscalarMul(n) {
    signal input e[n];
    signal input px;
    signal input py;
    signal output outx;
    signal output outy;

    component dbl[n - 1];
    component add[n];
    signal addx[n];
    signal addy[n];
    signal accx[n + 1];
    signal accy[n + 1];
    accx[0] <== 0;
    accy[0] <== 1;

    signal powx[n];
    signal powy[n];
    powx[0] <== px;
    powy[0] <== py;

    for (var i = 0; i < n; i++) {
        // addend = e[i] ? pow_i : identity(0,1)
        addx[i] <== e[i] * powx[i];
        addy[i] <== e[i] * (powy[i] - 1) + 1;
        add[i] = BabyAdd();
        add[i].x1 <== accx[i];
        add[i].y1 <== accy[i];
        add[i].x2 <== addx[i];
        add[i].y2 <== addy[i];
        accx[i + 1] <== add[i].xout;
        accy[i + 1] <== add[i].yout;
        if (i < n - 1) {
            dbl[i] = BabyDbl();
            dbl[i].x <== powx[i];
            dbl[i].y <== powy[i];
            powx[i + 1] <== dbl[i].xout;
            powy[i + 1] <== dbl[i].yout;
        }
    }
    outx <== accx[n];
    outy <== accy[n];
}

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

    // ---- soft safety flags
    component ocA = SoftOnCurve();
    ocA.x <== ax;
    ocA.y <== ay;
    component ocR = SoftOnCurve();
    ocR.x <== rx;
    ocR.y <== ry;

    // ---- muxed inputs: Base8 substituted when off-curve
    signal axm;
    signal aym;
    signal rxm;
    signal rym;
    axm <== ocA.ok * (ax - BASE8[0]) + BASE8[0];
    aym <== ocA.ok * (ay - BASE8[1]) + BASE8[1];
    rxm <== ocR.ok * (rx - BASE8[0]) + BASE8[0];
    rym <== ocR.ok * (ry - BASE8[1]) + BASE8[1];

    // ---- challenge over the REAL inputs (semantics of the native verifier)
    component ch = Poseidon(5);
    ch.inputs[0] <== rx;
    ch.inputs[1] <== ry;
    ch.inputs[2] <== ax;
    ch.inputs[3] <== ay;
    ch.inputs[4] <== msg;

    component cBits = Num2Bits_strict();
    cBits.in <== ch.out;

    component mulA = CompleteEscalarMul(254);
    mulA.px <== axm;
    mulA.py <== aym;
    for (var i = 0; i < 254; i++) {
        mulA.e[i] <== cBits.out[i];
    }

    component rhs = BabyAdd();
    rhs.x1 <== rxm;
    rhs.y1 <== rym;
    rhs.x2 <== mulA.outx;
    rhs.y2 <== mulA.outy;

    // ---- S: strict decomposition, soft top-zero flag, low 251 bits used
    component sBits = Num2Bits_strict();
    sBits.in <== s;
    var topSum = 0;
    for (var i = 251; i < 254; i++) {
        topSum += sBits.out[i];
    }
    component sTopZero = IsZero();
    sTopZero.in <== topSum;

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

    signal v1;
    signal v2;
    signal v3;
    v1 <== eqx.out * eqy.out;
    v2 <== v1 * ocA.ok;
    v3 <== v2 * ocR.ok;
    ok <== v3 * sTopZero.out;
}
