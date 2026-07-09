//! pi_cast: the public cast proof of the CAST-ZK ballot format
//!     B_j = (com_j, ct_open_j, pi_cast_j).
//!
//! pi_cast proves that com_j and ct_open_j open to the SAME
//! (opening_j, r_com_j) under pk_EA — see circuits/main/cast_proof.circom.
//! It is verified PUBLICLY (by the board operator / any observer) BEFORE
//! tallying; the tally circuit never re-proves encryption or decryption.
//! Under this precondition the EA's decryption of ct_open always yields
//! the opening committed in com, which the tally circuit HARD-checks.

use serde_json::{json, Value};

use crate::crypto::encryption::{cast_encrypt, CastSecret, EaPublicKey, CAST_CT_LEN};
use crate::crypto::hash::ct_commit;
use crate::errors::{CrDrError, Result};
use crate::types::{f_to_dec, F, PLAINTEXT_FIELD_LEN, PublicBallot};
use crate::zk::groth16_backend::{RapidsnarkBackend, SnarkjsBackend};

/// Circuit name of the compiled pi_cast instantiation.
pub const CAST_CIRCUIT: &str = "filter_and_tally_cast";

/// Native mirror of the CastProof circuit: true iff the secret opens BOTH
/// the commitment and the encryption of the public entry under pk_EA.
pub fn cast_relation_check_native(
    pk: &EaPublicKey,
    entry: &PublicBallot,
    secret: &CastSecret,
) -> bool {
    if secret.opening.plaintext_fields.len() != PLAINTEXT_FIELD_LEN {
        return false;
    }
    let mut pt = [F::from(0u64); PLAINTEXT_FIELD_LEN];
    pt.copy_from_slice(&secret.opening.plaintext_fields);
    if ct_commit(&pt, secret.opening.rho) != entry.com {
        return false;
    }
    let mut fields = [F::from(0u64); CAST_CT_LEN];
    fields[..PLAINTEXT_FIELD_LEN].copy_from_slice(&pt);
    fields[PLAINTEXT_FIELD_LEN] = secret.opening.rho;
    match cast_encrypt(pk, &fields, secret.rho_enc) {
        Ok(ct) => ct == entry.ct_open,
        Err(_) => false,
    }
}

/// circom input.json for a pi_cast proof.
pub fn cast_input(pk: &EaPublicKey, entry: &PublicBallot, secret: &CastSecret) -> Result<Value> {
    use ark_ff::Field;
    let rho_inv = secret
        .rho_enc
        .inverse()
        .ok_or_else(|| CrDrError::Crypto("rho_enc must be nonzero".into()))?;
    Ok(json!({
        "com": f_to_dec(&entry.com),
        "pk_x": f_to_dec(&pk.x),
        "pk_y": f_to_dec(&pk.y),
        "c1x": f_to_dec(&entry.ct_open.c1x),
        "c1y": f_to_dec(&entry.ct_open.c1y),
        "masked": entry.ct_open.masked.iter().map(f_to_dec).collect::<Vec<_>>(),
        "opening": secret.opening.plaintext_fields.iter().map(f_to_dec).collect::<Vec<_>>(),
        "r_com": f_to_dec(&secret.opening.rho),
        "rho_enc": f_to_dec(&secret.rho_enc),
        "rho_inv": f_to_dec(&rho_inv),
    }))
}

/// The exact snarkjs public.json a pi_cast proof for `entry` must carry
/// (declaration order: com, pk_x, pk_y, c1x, c1y, masked[10]).
pub fn cast_publics(pk: &EaPublicKey, entry: &PublicBallot) -> Vec<String> {
    let mut v = vec![
        f_to_dec(&entry.com),
        f_to_dec(&pk.x),
        f_to_dec(&pk.y),
        f_to_dec(&entry.ct_open.c1x),
        f_to_dec(&entry.ct_open.c1y),
    ];
    v.extend(entry.ct_open.masked.iter().map(f_to_dec));
    v
}

/// A pi_cast proof as attached to a board entry.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CastProof {
    pub proof: Value,
    pub public: Value,
}

/// Generate pi_cast for a ballot (rapidsnark when available, else snarkjs).
pub fn prove_cast(
    root: impl Into<std::path::PathBuf>,
    pk: &EaPublicKey,
    entry: &PublicBallot,
    secret: &CastSecret,
) -> Result<CastProof> {
    let be = SnarkjsBackend { root: root.into(), circuit: CAST_CIRCUIT.into() };
    let input = cast_input(pk, entry, secret)?;
    let (proof, public) = match RapidsnarkBackend::discover(be.clone()) {
        Some(rapid) => rapid.prove(&input)?,
        None => be.prove(&input)?,
    };
    Ok(CastProof { proof, public })
}

/// PUBLIC verification of a board entry's pi_cast, run BEFORE tallying:
///  1. the proof's public inputs are exactly (com, pk_EA, ct_open);
///  2. the Groth16 proof verifies;
///  3. C1 is a valid non-identity subgroup point (decryptability).
/// Entries failing any check must be rejected and never tallied.
pub fn verify_cast_entry(
    root: impl Into<std::path::PathBuf>,
    pk: &EaPublicKey,
    entry: &PublicBallot,
    cast: &CastProof,
) -> Result<bool> {
    let be = SnarkjsBackend { root: root.into(), circuit: CAST_CIRCUIT.into() };
    let expected = cast_publics(pk, entry);
    let bound = cast
        .public
        .as_array()
        .map(|a| {
            a.len() == expected.len()
                && a.iter().zip(&expected).all(|(v, e)| v.as_str() == Some(e.as_str()))
        })
        .unwrap_or(false);
    if !bound {
        return Ok(false);
    }
    use ark_ff::Zero;
    let c1_ok = matches!(
        crate::crypto::signature::decode_point(entry.ct_open.c1x, entry.ct_open.c1y),
        Some(p) if !p.is_zero()
    );
    if !c1_ok || entry.ct_open.masked.len() != CAST_CT_LEN {
        return Ok(false);
    }
    be.verify(&cast.proof, &cast.public)
}
