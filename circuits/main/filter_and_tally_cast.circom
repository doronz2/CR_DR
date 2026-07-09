pragma circom 2.0.0;

// pi_cast instantiation (see cast_proof.circom). Per-ballot, fixed size.

include "./cast_proof.circom";

component main {
    public [com, pk_x, pk_y, c1x, c1y, masked]
} = CastProof();
