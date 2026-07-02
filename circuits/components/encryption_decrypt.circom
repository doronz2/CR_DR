pragma circom 2.0.0;

// COMMITMENT-MODE PROTOTYPE (see the loud warning in README and
// src/crypto/encryption.rs): the "ciphertext" is a Poseidon commitment
//     ct = Poseidon(pt[0..nFields-1] || rho)
// and this component verifies the opening with a SOFT result, so that a
// ciphertext with no known opening yields an invalid ballot instead of an
// unsatisfiable witness.
//
// TODO(BabyJubJub-ElGamal hybrid): replace with a real decryption check —
//   witness sk_EA (bits), check   pk_ea == sk_EA * Base8   (EscalarMulFix,
//   once per proof), then per ballot:
//     ss    = sk_EA * C1                       (EscalarMulAny)
//     pt[i] = masked[i] - Poseidon(ss.x, ss.y, i)
//   with ciphertext fields (C1.x, C1.y, masked[0..8]). The native backend
//   for this already exists (crypto::encryption::elgamal_*).

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/comparators.circom";

template CiphertextOpen(nFields) {
    signal input ct;
    signal input pt[nFields];
    signal input rho;
    signal output ok;

    component p = Poseidon(nFields + 1);
    for (var i = 0; i < nFields; i++) {
        p.inputs[i] <== pt[i];
    }
    p.inputs[nFields] <== rho;

    component eq = IsEqual();
    eq.in[0] <== p.out;
    eq.in[1] <== ct;
    ok <== eq.out;
}
