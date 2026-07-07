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
//! ## Row layout
//!
//! The witness rows mirror the circuit's per-ballot private inputs. The
//! registration side is INDEXED: the ballot's claimed id determines the
//! Merkle leaf index, so the row carries the public table row values
//! (reg_vk, reg_h) and the sibling path AT INDEX id — the direction bits
//! are the bits of id itself and are not part of the witness.
//!
//! For ballots that cannot even be represented safely inside the circuit
//! (unopenable ciphertexts, off-curve/identity points, non-canonical
//! scalars), the builder substitutes a fixed "dummy" plaintext whose point
//! coordinates are valid curve points. The circuit's hard constraints then
//! remain satisfiable while the ballot's soft validity flag evaluates to 0 —
//! the same verdict the native FilterAndTally reached.

use ark_ff::Zero;

use crate::crypto::encryption::commit_open;
use crate::crypto::hash::ct_commit;
use crate::crypto::signature::{base8_circom_coords, decode_point, f_is_canonical_scalar};
use crate::errors::{CrDrError, Result};
use crate::protocol::preprocessing::RegistrationState;
use crate::types::{
    AuthoritySecretState, Ballot, BallotPlaintext, F, PLAINTEXT_FIELD_LEN, PublicParams,
};
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

/// True iff the plaintext's curve points / scalars can be fed to the
/// circuit's hard constraints (BabyCheck, Num2Bits, Edwards2Montgomery).
fn circuit_safe(pt: &BallotPlaintext) -> bool {
    let vk_ok = matches!(decode_point(pt.vk.x, pt.vk.y), Some(p) if !p.is_zero());
    let r_ok = decode_point(pt.sigma.rx, pt.sigma.ry).is_some();
    vk_ok && r_ok && f_is_canonical_scalar(&pt.sigma.s)
}

/// Build the witness for the posted ballots. Mirrors the native
/// FilterAndTally decision procedure exactly.
pub fn build_tally_witness(
    pp: &PublicParams,
    authority_secret: &AuthoritySecretState,
    registration_state: &RegistrationState,
    ballots: &[Ballot],
) -> Result<TallyWitness> {
    let depth = pp.merkle_depth;
    let num_voters = registration_state.num_voters() as u64;
    let (_tally, evals) = crate::protocol::filter_and_tally::filter_and_tally(
        pp,
        authority_secret,
        registration_state,
        ballots,
    )?;

    let mut rows = Vec::with_capacity(ballots.len());
    for (ballot, eval) in ballots.iter().zip(&evals) {
        if ballot.ciphertext.fields.len() != 1 {
            return Err(CrDrError::Crypto("commitment-mode ciphertext expected".into()));
        }
        let ct = ballot.ciphertext.fields[0];

        // Recover plaintext fields when the ballot opens and is circuit-safe;
        // otherwise substitute the dummy row (opening check will fail softly).
        let opened = commit_open(&ballot.ciphertext, &ballot.ea_payload)
            .ok()
            .and_then(|o| {
                let mut f = [F::zero(); PLAINTEXT_FIELD_LEN];
                f.copy_from_slice(&o.plaintext_fields);
                Some((f, o.rho))
            });

        let (pt_fields, rho) = match opened {
            Some((f, rho)) => {
                match BallotPlaintext::from_fields(&f) {
                    Ok(pt) if circuit_safe(&pt) => (f, rho),
                    // id/candidate out of u64 range still fine for the
                    // circuit as long as points are safe; from_fields
                    // rejects those, so re-check point safety directly.
                    _ => {
                        if fields_points_safe(&f) {
                            (f, rho)
                        } else {
                            (dummy_pt_fields(), F::zero())
                        }
                    }
                }
            }
            None => (dummy_pt_fields(), F::zero()),
        };

        // Indexed registration side: the claimed id (real or dummy)
        // determines the row. For in-range ids the row values and sibling
        // path MUST be the true ones (hard constraints); out-of-range ids
        // get zeros (constraints gated off).
        let reg = registration_side(authority_secret, registration_state, &pt_fields, num_voters, depth);

        rows.push(BallotWitnessRow {
            ct,
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

/// Point-safety check on raw fields (positions 2,3 = vk; 6,7 = sig R; 8 = s).
fn fields_points_safe(f: &[F; PLAINTEXT_FIELD_LEN]) -> bool {
    let vk_ok = matches!(decode_point(f[2], f[3]), Some(p) if !p.is_zero());
    let r_ok = decode_point(f[6], f[7]).is_some();
    vk_ok && r_ok && f_is_canonical_scalar(&f[8])
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
