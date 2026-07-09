//! Private witness for the FilterAndTally relation, built by the tallier.
//!
//! ## Prover tiers
//!
//! * **Tier 1 (this code, benchmarked)** — a single logical prover performs
//!   an AUTHORIZED >= t reconstruction of each R_EA,i
//!   (`AuthoritySecretState::r_ea`), assembles the full witness and runs
//!   Groth16.
//! * **Tier 2** — the same algorithm executed inside a protected, audited
//!   environment; the interface is identical.
//! * **Tier 3 (future)** — threshold authorities jointly provide the
//!   witness without any single party learning everything. The only secret
//!   that crosses a trust boundary here is R_EA,i, and it is consumed
//!   through the share-based `r_ea()` interface, so a Tier-3 prover can
//!   replace that call with an MPC opening without changing the relation.
//!
//! ## CAST-ZK format
//!
//! Every board entry (com, ct_open) with a publicly verified pi_cast
//! decrypts (sk_EA) to the exact opening committed in `com`; the tally
//! circuit HARD-opens `com` with it. There is no dummy-substitution policy
//! anymore: the circuit's downstream checks (incl. the Schnorr gadget) are
//! soft-safe for ARBITRARY opening fields, so every decrypted opening is
//! usable as-is. An undecryptable entry (impossible when pi_cast was
//! verified) is a hard error.
//!
//! The registration side is INDEXED: the ballot's claimed id determines
//! the Merkle leaf index, so the row carries the public table row values
//! (reg_vk, reg_h) and the sibling path AT INDEX id.

use ark_ff::Zero;

use crate::crypto::hash::ct_commit;
use crate::crypto::signature::base8_circom_coords;
use crate::errors::{CrDrError, Result};
use crate::protocol::preprocessing::RegistrationState;
use crate::protocol::admission::AdmittedOpenings;
use crate::protocol::bulletin_board::AdmittedBoard;
use crate::types::{AuthoritySecretState, F, PLAINTEXT_FIELD_LEN, PublicParams};
use crate::zk::CircuitShape;

/// One per-ballot witness row (mirrors the circuit's private inputs).
#[derive(Debug, Clone)]
pub struct BallotWitnessRow {
    /// Public-side ciphertext commitment (bound via the BB chain).
    pub ct: F,
    pub pt_fields: [F; PLAINTEXT_FIELD_LEN],
    pub rho: F,
    pub r_ea: F,
    /// Indexed registration row Reg[id] = (id, vk, h): vk coordinates and h.
    /// Zeros when the claimed id is out of range (the circuit gates the row
    /// check off in that case).
    pub reg_vkx: F,
    pub reg_vky: F,
    pub reg_h: F,
    /// Sibling hashes for leaf index id (direction bits = bits of id).
    pub merkle_path: Vec<F>,
    /// Expected flags (recomputed, not trusted, by circuit and native
    /// relation checker; kept for tests).
    pub expect_valid: bool,
    pub expect_counted: bool,
}

#[derive(Debug, Clone)]
pub struct TallyWitness {
    pub rows: Vec<BallotWitnessRow>,
    /// Candidate values (opening of the candidate-set commitment).
    pub candidates: Vec<u64>,
}

/// Fixed dummy plaintext: all-zero metadata with Base8 as every point
/// coordinate pair, rho = 0. Never opens a real ciphertext, always safe for
/// the circuit's hard constraints.
pub fn dummy_pt_fields() -> [F; PLAINTEXT_FIELD_LEN] {
    let (b8x, b8y) = base8_circom_coords();
    [
        F::zero(),
        F::zero(),
        b8x,
        b8y,
        F::zero(),
        F::zero(),
        b8x,
        b8y,
        F::zero(),
    ]
}

/// A fully self-consistent padding row for circuit slots beyond
/// `num_ballots` (its ct opens correctly, but the row is inactive, so the
/// indexed row check is gated off and zeros are fine).
pub fn padding_row(depth: usize) -> BallotWitnessRow {
    let pt = dummy_pt_fields();
    BallotWitnessRow {
        ct: ct_commit(&pt, F::zero()),
        pt_fields: pt,
        rho: F::zero(),
        r_ea: F::zero(),
        reg_vkx: F::zero(),
        reg_vky: F::zero(),
        reg_h: F::zero(),
        merkle_path: vec![F::zero(); depth],
        expect_valid: false,
        expect_counted: false,
    }
}

/// Build the witness for the posted ballots. Mirrors the native
/// FilterAndTally decision procedure exactly.
pub fn build_tally_witness(
    pp: &PublicParams,
    authority_secret: &AuthoritySecretState,
    registration_state: &RegistrationState,
    admitted: &AdmittedBoard,
    openings: &AdmittedOpenings,
) -> Result<TallyWitness> {
    let depth = pp.merkle_depth;
    let num_voters = registration_state.num_voters() as u64;
    let (_tally, evals) = crate::protocol::filter_and_tally::filter_and_tally(
        pp,
        authority_secret,
        registration_state,
        admitted,
        openings,
    )?;

    let mut rows = Vec::with_capacity(admitted.len());
    for (j, eval) in evals.iter().enumerate() {
        // The admitted commitment's opening (both admission paths
        // guarantee it opens; checked defensively inside).
        let (pt_fields, rho) =
            crate::protocol::filter_and_tally::opening_checked(admitted, openings, j)?;

        // Indexed registration side: the claimed id (whatever it is)
        // determines the row. For in-range ids the row values and sibling
        // path MUST be the true ones (hard constraints); out-of-range ids
        // get zeros (constraints gated off).
        let reg = registration_side(authority_secret, registration_state, &pt_fields, num_voters, depth);

        rows.push(BallotWitnessRow {
            ct: admitted.coms[j],
            pt_fields,
            rho,
            r_ea: reg.r_ea,
            reg_vkx: reg.vkx,
            reg_vky: reg.vky,
            reg_h: reg.h,
            merkle_path: reg.path,
            expect_valid: matches!(
                eval.status,
                crate::types::InternalBallotStatus::Counted
                    | crate::types::InternalBallotStatus::DuplicateValidBallot
            ),
            expect_counted: matches!(eval.status, crate::types::InternalBallotStatus::Counted),
        });
    }

    Ok(TallyWitness { rows, candidates: pp.candidates.clone() })
}

struct RegSide {
    r_ea: F,
    vkx: F,
    vky: F,
    h: F,
    path: Vec<F>,
}

/// The id-determined registration witness. In-range id => the true row
/// Reg[id], its sibling path, and the authorized-reconstructed R_EA,id
/// (supplied even when the ballot is invalid for other reasons — the row
/// fetch is hard, the vk/nonce comparisons are soft). Out-of-range => zeros.
fn registration_side(
    authority_secret: &AuthoritySecretState,
    registration_state: &RegistrationState,
    pt_fields: &[F; PLAINTEXT_FIELD_LEN],
    num_voters: u64,
    depth: usize,
) -> RegSide {
    let zeros = RegSide {
        r_ea: F::zero(),
        vkx: F::zero(),
        vky: F::zero(),
        h: F::zero(),
        path: vec![F::zero(); depth],
    };
    let Some(id) = crate::types::f_to_u64(&pt_fields[1]) else {
        return zeros;
    };
    if id >= num_voters {
        return zeros;
    }
    let Some(record) = registration_state.record(id) else {
        return zeros; // unreachable for a well-formed dense table
    };
    let path = registration_state
        .paths
        .get(&id)
        .map(|p| p.elements.clone())
        .unwrap_or_else(|| vec![F::zero(); depth]);
    // Authorized >= t quorum reconstruction; a registered row always has one.
    let r_ea = authority_secret.r_ea(id).unwrap_or_else(|_| F::zero());
    RegSide { r_ea, vkx: record.vk.x, vky: record.vk.y, h: record.h, path }
}

/// Pad witness rows out to the circuit's compile-time ballot count.
pub fn padded_rows(witness: &TallyWitness, shape: &CircuitShape) -> Result<Vec<BallotWitnessRow>> {
    if witness.rows.len() > shape.num_ballots {
        return Err(CrDrError::ZkToolchain(format!(
            "{} ballots exceed circuit capacity {}",
            witness.rows.len(),
            shape.num_ballots
        )));
    }
    let mut rows = witness.rows.clone();
    while rows.len() < shape.num_ballots {
        rows.push(padding_row(shape.merkle_depth));
    }
    Ok(rows)
}
