//! Ballot encryption: the CAST-ZK format.
//!
//! A public board entry is B_j = (com_j, ct_open_j, pi_cast_j):
//!
//! ```text
//! com_j     = H_ballot_com(opening_j, r_com_j)          (Poseidon, arity 10)
//! ct_open_j = Enc_pkEA(opening_j, r_com_j; rho_enc_j)   (BabyJubJub-ElGamal
//!                                                        + Poseidon-pad hybrid)
//! pi_cast_j = ZK proof that com_j and ct_open_j open to the SAME
//!             (opening_j, r_com_j)  — circuits/main/cast_proof.circom
//! ```
//!
//! pi_cast is verified PUBLICLY before tallying (zk::cast). The tally
//! circuit never proves encryption/decryption: the EA decrypts ct_open
//! natively (sk_EA) and the tally circuit HARD-checks that the decrypted
//! opening opens com. Hybrid scheme:
//!
//! ```text
//! C1 = rho_enc * Base8,  ss = rho_enc * pk_EA,
//! masked_i = m_i + Poseidon(ss.x, ss.y, i),   m = opening || r_com.
//! ```
//!
//! Production encryption still requires a full formal treatment (key
//! validation ceremonies, CCA transforms, etc.).

use ark_ec::CurveGroup;
use ark_ff::{BigInteger, PrimeField, UniformRand, Zero};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::crypto::poseidon_native::poseidon;
use crate::crypto::signature::{base8, JubProjective, JubScalar};
use crate::errors::{CrDrError, Result};
use crate::types::{f_to_bytes_be, fserde, fserde_vec, F, PLAINTEXT_FIELD_LEN};

/// Number of encrypted fields in ct_open: the 9 opening fields + r_com.
pub const CAST_CT_LEN: usize = PLAINTEXT_FIELD_LEN + 1;

/// EA encryption secret key (BabyJubJub scalar).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EaSecretKey(
    #[serde(with = "crate::crypto::signature::jubserde")] pub JubScalar,
);

/// EA encryption public key (BabyJubJub point).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct EaPublicKey {
    #[serde(with = "fserde")]
    pub x: F,
    #[serde(with = "fserde")]
    pub y: F,
}

pub fn ea_keygen<R: RngCore + CryptoRng>(rng: &mut R) -> (EaSecretKey, EaPublicKey) {
    let sk = loop {
        let s = JubScalar::rand(rng);
        if !s.is_zero() {
            break s;
        }
    };
    let pk = (JubProjective::from(base8()) * sk).into_affine();
    let (x, y) = crate::crypto::signature::to_circom_point(&pk);
    (EaSecretKey(sk), EaPublicKey { x, y })
}

/// The public encrypted opening ct_open_j = (C1, masked[10]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CastCiphertext {
    #[serde(with = "fserde")]
    pub c1x: F,
    #[serde(with = "fserde")]
    pub c1y: F,
    #[serde(with = "fserde_vec")]
    pub masked: Vec<F>,
}

impl CastCiphertext {
    /// Exact public byte encoding (32-byte BE per field, concatenated).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity((2 + self.masked.len()) * 32);
        out.extend_from_slice(&f_to_bytes_be(&self.c1x));
        out.extend_from_slice(&f_to_bytes_be(&self.c1y));
        for f in &self.masked {
            out.extend_from_slice(&f_to_bytes_be(f));
        }
        out
    }
}

/// Opening of a ballot commitment: the 9 plaintext fields + r_com (named
/// `rho` for continuity with the tally circuit's signal name).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncOpening {
    #[serde(with = "fserde_vec")]
    pub plaintext_fields: Vec<F>,
    #[serde(with = "fserde")]
    pub rho: F,
}

/// The voter-private cast secret: everything needed to produce pi_cast and
/// to open the ballot in a dispute.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CastSecret {
    pub opening: EncOpening,
    /// ElGamal ephemeral randomness (a canonical BabyJubJub scalar < 2^251,
    /// stored as a field element for the circuit witness).
    #[serde(with = "fserde")]
    pub rho_enc: F,
}

fn pad(ssx: F, ssy: F, i: usize) -> F {
    poseidon(&[ssx, ssy, F::from(i as u64)])
}

/// Sample nonzero ElGamal randomness (canonical scalar, as a field element).
pub fn sample_rho_enc<R: RngCore + CryptoRng>(rng: &mut R) -> F {
    loop {
        let r = JubScalar::rand(rng);
        if !r.is_zero() {
            return F::from_le_bytes_mod_order(&r.into_bigint().to_bytes_le());
        }
    }
}

fn rho_to_scalar(rho_enc: F) -> Result<JubScalar> {
    if !crate::crypto::signature::f_is_canonical_scalar(&rho_enc) || rho_enc.is_zero() {
        return Err(CrDrError::Crypto("rho_enc must be a nonzero canonical scalar".into()));
    }
    Ok(crate::crypto::signature::jub_scalar_from_field(&rho_enc))
}

/// Hybrid-encrypt the 10 cast fields (opening || r_com) under pk_EA with
/// the given ephemeral randomness. Deterministic given rho_enc, exactly
/// matching the CastProof circuit.
pub fn cast_encrypt(pk: &EaPublicKey, fields: &[F; CAST_CT_LEN], rho_enc: F) -> Result<CastCiphertext> {
    let pk_point = crate::crypto::signature::decode_point(pk.x, pk.y)
        .ok_or_else(|| CrDrError::Crypto("invalid EA public key".into()))?;
    let r = rho_to_scalar(rho_enc)?;
    let c1 = (JubProjective::from(base8()) * r).into_affine();
    let ss = (JubProjective::from(pk_point) * r).into_affine();
    let (c1x, c1y) = crate::crypto::signature::to_circom_point(&c1);
    let (ssx, ssy) = crate::crypto::signature::to_circom_point(&ss);
    let masked = fields
        .iter()
        .enumerate()
        .map(|(i, m)| *m + pad(ssx, ssy, i))
        .collect();
    Ok(CastCiphertext { c1x, c1y, masked })
}

/// EA-side decryption of ct_open. Fails on malformed C1 (impossible for
/// entries whose pi_cast verified) or wrong field count.
pub fn cast_decrypt(sk: &EaSecretKey, ct: &CastCiphertext) -> Result<[F; CAST_CT_LEN]> {
    if ct.masked.len() != CAST_CT_LEN {
        return Err(CrDrError::Crypto("ct_open must carry 10 masked fields".into()));
    }
    let c1 = crate::crypto::signature::decode_point(ct.c1x, ct.c1y)
        .ok_or_else(|| CrDrError::Crypto("invalid C1".into()))?;
    if c1.is_zero() {
        return Err(CrDrError::Crypto("identity C1".into()));
    }
    let ss = (JubProjective::from(c1) * sk.0).into_affine();
    let (ssx, ssy) = crate::crypto::signature::to_circom_point(&ss);
    let mut out = [F::zero(); CAST_CT_LEN];
    for i in 0..CAST_CT_LEN {
        out[i] = ct.masked[i] - pad(ssx, ssy, i);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn cast_hybrid_roundtrip() {
        let mut rng = ChaCha20Rng::seed_from_u64(5);
        let (sk, pk) = ea_keygen(&mut rng);
        let mut fields = [F::zero(); CAST_CT_LEN];
        for (i, f) in fields.iter_mut().enumerate() {
            *f = F::from((i * 17 + 3) as u64);
        }
        let rho = sample_rho_enc(&mut rng);
        let ct = cast_encrypt(&pk, &fields, rho).unwrap();
        assert_eq!(cast_decrypt(&sk, &ct).unwrap(), fields);
    }

    #[test]
    fn cast_hybrid_wrong_key_garbles() {
        let mut rng = ChaCha20Rng::seed_from_u64(6);
        let (_sk, pk) = ea_keygen(&mut rng);
        let (sk2, _pk2) = ea_keygen(&mut rng);
        let fields = [F::from(5u64); CAST_CT_LEN];
        let rho = sample_rho_enc(&mut rng);
        let ct = cast_encrypt(&pk, &fields, rho).unwrap();
        assert_ne!(cast_decrypt(&sk2, &ct).unwrap(), fields);
    }

    #[test]
    fn cast_rejects_zero_rho() {
        let mut rng = ChaCha20Rng::seed_from_u64(7);
        let (_sk, pk) = ea_keygen(&mut rng);
        let fields = [F::from(5u64); CAST_CT_LEN];
        assert!(cast_encrypt(&pk, &fields, F::zero()).is_err());
    }
}
