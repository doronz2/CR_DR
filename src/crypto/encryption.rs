//! Ballot "encryption" backends.
//!
//! ============================================================
//! LOUD WARNING — COMMITMENT-MODE PROTOTYPE, NOT FULL ENCRYPTION
//! ============================================================
//!
//! The default backend used end-to-end (and matched by the circuit's
//! `encryption_decrypt.circom`) is COMMITMENT MODE:
//! `ciphertext = Poseidon(plaintext_fields || rho)`.
//!
//! The ballot carries an `ea_payload` (the serialized opening) that models a
//! private channel to the EA. This is a circuit-friendly commitment/opening
//! relation, NOT public-key encryption: anyone holding the payload can open
//! it. It is acceptable only as a first relation-checking prototype so the
//! FilterAndTally circuit works end-to-end.
//!
//! A native BabyJubJub ElGamal + Poseidon-pad hybrid backend is also
//! implemented below as the intended production-shaped replacement; the
//! circuit component for it is left as a documented TODO in
//! `circuits/components/encryption_decrypt.circom`. Production encryption
//! requires a full formal treatment (key validation, CCA transforms, etc.).

use ark_ec::CurveGroup;
use ark_ff::{UniformRand, Zero};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::crypto::hash::ct_commit;
use crate::crypto::poseidon_native::poseidon;
use crate::crypto::signature::{base8, JubAffine, JubProjective, JubScalar};
use crate::errors::{CrDrError, Result};
use crate::types::{f_to_bytes_be, fserde, fserde_vec, F, PLAINTEXT_FIELD_LEN};

/// EA encryption secret key (BabyJubJub scalar).
#[derive(Debug, Clone)]
pub struct EaSecretKey(pub JubScalar);

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

/// Public ciphertext as posted on the bulletin board. In commitment mode this
/// is a single field element; in ElGamal-hybrid mode it is
/// [C1.x, C1.y, masked_0..masked_8].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ciphertext {
    #[serde(with = "fserde_vec")]
    pub fields: Vec<F>,
}

impl Ciphertext {
    /// Exact public byte encoding (32-byte BE per field, concatenated).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.fields.len() * 32);
        for f in &self.fields {
            out.extend_from_slice(&f_to_bytes_be(f));
        }
        out
    }
}

/// Opening of a commitment-mode ciphertext (plaintext fields + rho).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncOpening {
    #[serde(with = "fserde_vec")]
    pub plaintext_fields: Vec<F>,
    #[serde(with = "fserde")]
    pub rho: F,
}

// ---------------------------------------------------------------------------
// Commitment-mode backend (default; matched by the circuit)
// ---------------------------------------------------------------------------

/// Encrypt (commit) plaintext fields. Returns the public ciphertext and the
/// opening. The caller packages the opening into the ballot's `ea_payload`.
pub fn commit_encrypt<R: RngCore + CryptoRng>(
    plaintext_fields: &[F; PLAINTEXT_FIELD_LEN],
    rng: &mut R,
) -> (Ciphertext, EncOpening) {
    let rho = F::rand(rng);
    let ct = ct_commit(plaintext_fields, rho);
    (
        Ciphertext { fields: vec![ct] },
        EncOpening { plaintext_fields: plaintext_fields.to_vec(), rho },
    )
}

/// Serialize an opening into an EA payload.
pub fn opening_to_payload(opening: &EncOpening) -> Vec<u8> {
    serde_json::to_vec(opening).expect("opening serialization")
}

/// EA-side opening of a commitment-mode ballot: parse the payload and check
/// it opens the public ciphertext. Any failure = InvalidDecryption upstream.
pub fn commit_open(ciphertext: &Ciphertext, ea_payload: &[u8]) -> Result<EncOpening> {
    if ciphertext.fields.len() != 1 {
        return Err(CrDrError::Crypto("commitment-mode ciphertext must be 1 field".into()));
    }
    let opening: EncOpening = serde_json::from_slice(ea_payload)
        .map_err(|e| CrDrError::Crypto(format!("payload parse failed: {e}")))?;
    if opening.plaintext_fields.len() != PLAINTEXT_FIELD_LEN {
        return Err(CrDrError::Crypto("wrong plaintext field count".into()));
    }
    let mut fields = [F::zero(); PLAINTEXT_FIELD_LEN];
    fields.copy_from_slice(&opening.plaintext_fields);
    if ct_commit(&fields, opening.rho) != ciphertext.fields[0] {
        return Err(CrDrError::Crypto("opening does not match ciphertext".into()));
    }
    Ok(opening)
}

// ---------------------------------------------------------------------------
// BabyJubJub ElGamal + Poseidon-pad hybrid (native demonstration backend)
// ---------------------------------------------------------------------------
// ciphertext = (C1, masked[9]) with C1 = r*B8, ss = r*PK,
// masked_i = pt_i + Poseidon(ss.x, ss.y, i).
// The circuit-side decryption check (ss = sk_EA * C1) is a documented TODO.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElGamalCiphertext {
    pub c1: (F, F),
    pub masked: [F; PLAINTEXT_FIELD_LEN],
}

fn pad(ss: &JubAffine, i: usize) -> F {
    let (x, y) = crate::crypto::signature::to_circom_point(ss);
    poseidon(&[x, y, F::from(i as u64)])
}

pub fn elgamal_encrypt<R: RngCore + CryptoRng>(
    pk: &EaPublicKey,
    plaintext_fields: &[F; PLAINTEXT_FIELD_LEN],
    rng: &mut R,
) -> Result<ElGamalCiphertext> {
    let pk_point = crate::crypto::signature::decode_point(pk.x, pk.y)
        .ok_or_else(|| CrDrError::Crypto("invalid EA public key".into()))?;
    let r = loop {
        let r = JubScalar::rand(rng);
        if !r.is_zero() {
            break r;
        }
    };
    let c1 = (JubProjective::from(base8()) * r).into_affine();
    let ss = (JubProjective::from(pk_point) * r).into_affine();
    let mut masked = [F::zero(); PLAINTEXT_FIELD_LEN];
    for (i, pt) in plaintext_fields.iter().enumerate() {
        masked[i] = *pt + pad(&ss, i);
    }
    Ok(ElGamalCiphertext { c1: crate::crypto::signature::to_circom_point(&c1), masked })
}

pub fn elgamal_decrypt(
    sk: &EaSecretKey,
    ct: &ElGamalCiphertext,
) -> Result<[F; PLAINTEXT_FIELD_LEN]> {
    let c1 = crate::crypto::signature::decode_point(ct.c1.0, ct.c1.1)
        .ok_or_else(|| CrDrError::Crypto("invalid C1".into()))?;
    if c1.is_zero() {
        return Err(CrDrError::Crypto("identity C1".into()));
    }
    let ss = (JubProjective::from(c1) * sk.0).into_affine();
    let mut out = [F::zero(); PLAINTEXT_FIELD_LEN];
    for i in 0..PLAINTEXT_FIELD_LEN {
        out[i] = ct.masked[i] - pad(&ss, i);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn commitment_mode_roundtrip() {
        let mut rng = ChaCha20Rng::seed_from_u64(3);
        let fields = [F::from(9u64); PLAINTEXT_FIELD_LEN];
        let (ct, opening) = commit_encrypt(&fields, &mut rng);
        let payload = opening_to_payload(&opening);
        let opened = commit_open(&ct, &payload).unwrap();
        assert_eq!(opened.plaintext_fields, fields.to_vec());
    }

    #[test]
    fn commitment_mode_rejects_tampered_payload() {
        let mut rng = ChaCha20Rng::seed_from_u64(4);
        let fields = [F::from(9u64); PLAINTEXT_FIELD_LEN];
        let (ct, opening) = commit_encrypt(&fields, &mut rng);
        let mut tampered = opening.clone();
        tampered.plaintext_fields[4] = F::from(1234u64);
        let payload = opening_to_payload(&tampered);
        assert!(commit_open(&ct, &payload).is_err());
    }

    #[test]
    fn elgamal_roundtrip() {
        let mut rng = ChaCha20Rng::seed_from_u64(5);
        let (sk, pk) = ea_keygen(&mut rng);
        let mut fields = [F::zero(); PLAINTEXT_FIELD_LEN];
        for (i, f) in fields.iter_mut().enumerate() {
            *f = F::from((i * 17 + 3) as u64);
        }
        let ct = elgamal_encrypt(&pk, &fields, &mut rng).unwrap();
        let dec = elgamal_decrypt(&sk, &ct).unwrap();
        assert_eq!(dec, fields);
    }

    #[test]
    fn elgamal_wrong_key_garbles() {
        let mut rng = ChaCha20Rng::seed_from_u64(6);
        let (_sk, pk) = ea_keygen(&mut rng);
        let (sk2, _pk2) = ea_keygen(&mut rng);
        let fields = [F::from(5u64); PLAINTEXT_FIELD_LEN];
        let ct = elgamal_encrypt(&pk, &fields, &mut rng).unwrap();
        let dec = elgamal_decrypt(&sk2, &ct).unwrap();
        assert_ne!(dec, fields);
    }
}
