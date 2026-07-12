pragma circom 2.0.0;

// In-circuit Shamir reconstruction of the authority nonce R_EA from its
// threshold shares, for the TIER-3 (decentralized / coSNARK) prover.
//
// WHY THIS EXISTS. In Tier 1 the witness carries R_EA as a single field
// `r_ea`, which forces SOME party to reconstruct it in the clear
// (AuthoritySecretState::r_ea -> shamir::reconstruct). Tier 3 must never
// let any single party learn R_EA. So the circuit instead takes the
// per-authority Shamir SHARES as inputs and reconstructs R_EA INSIDE the
// computation:
//
//     R_EA = sum_i  lambda_i * share_i        (Lagrange at x = 0)
//
// where lambda_i depends only on the PUBLIC share indices (x = 1..t), so
// the coefficients are compile-time constants. Under an MPC witness
// extension (co-circom REP3/Shamir) each share_i enters as a secret-shared
// input contributed by authority i; the linear combination is evaluated on
// shares with no interaction, and R_EA exists only as an MPC-shared value
// — no party, including the prover, ever sees it.
//
// This component is IDENTICAL in effect to `crypto::shamir::reconstruct`
// over the first t shares (indices 1,2,...,t); the native mirror
// `mock_backend::lagrange_combine` recomputes the same coefficients.

// Reconstruct from the t = 2 shares at indices {1, 2}:
//   lambda_1 =  x2/(x2-x1) =  2/(2-1) =  2
//   lambda_2 =  x1/(x1-x2) =  1/(1-2) = -1
//   R_EA = 2*s_1 - s_2
template LagrangeCombineT2() {
    signal input shares[2];   // [share at index 1, share at index 2]
    signal output r_ea;
    r_ea <== 2 * shares[0] - shares[1];
}
