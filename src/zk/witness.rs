//! Private witness for the FilterAndTally relation, built by the tallier
//! (who holds the EA secret state).
//!
//! The witness rows mirror the circuit's per-ballot private inputs. For
//! ballots that cannot even be represented safely inside the circuit
//! (unopenable ciphertexts, off-curve/identity points, non-canonical
//! scalars), the builder substitutes a fixed "dummy" plaintext whose point
//! coordinates are valid curve points. The circuit's hard constraints
//! (Poseidon computations, on-curve checks, bit decompositions) then remain
//! satisfiable while the ballot's soft validity flag evaluates to 0 — the
//! same verdict the native FilterAndTally reached.

use ark_ff::Zero;

use crate::crypto::encryption::commit_open;
use crate::crypto::hash::ct_commit;
use crate::crypto::merkle::MerklePath;
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
    pub merkle_path: Vec<F>,
    pub merkle_index: Vec<bool>,
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
/// `num_ballots` (its ct opens correctly, but the row is inactive).
pub fn padding_row(depth: usize) -> BallotWitnessRow {
    let pt = dummy_pt_fields();
    BallotWitnessRow {
        ct: ct_commit(&pt, F::zero()),
        pt_fields: pt,
        rho: F::zero(),
        r_ea: F::zero(),
        merkle_path: vec![F::zero(); depth],
        merkle_index: vec![false; depth],
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

        // Registration-side witness: real R_EA and Merkle path when the
        // claimed (id, vk) matches a registered record, else zeros.
        let (r_ea, path) = witness_registration_side(
            authority_secret,
            registration_state,
            &pt_fields,
            depth,
        );

        rows.push(BallotWitnessRow {
            ct,
            pt_fields,
            rho,
            r_ea,
            merkle_path: path.elements,
            merkle_index: path.indices,
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

fn witness_registration_side(
    authority_secret: &AuthoritySecretState,
    registration_state: &RegistrationState,
    pt_fields: &[F; PLAINTEXT_FIELD_LEN],
    depth: usize,
) -> (F, MerklePath) {
    let empty = MerklePath { elements: vec![F::zero(); depth], indices: vec![false; depth] };
    let Some(id) = crate::types::f_to_u64(&pt_fields[1]) else {
        return (F::zero(), empty);
    };
    let Some(record) = registration_state.record(id) else {
        return (F::zero(), empty);
    };
    if record.vk.x != pt_fields[2] || record.vk.y != pt_fields[3] {
        return (F::zero(), empty);
    }
    let Some(secret) = authority_secret.voter_secrets.get(&id) else {
        return (F::zero(), empty);
    };
    let path = registration_state.paths.get(&id).cloned().unwrap_or(empty);
    (secret.r_ea, path)
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
