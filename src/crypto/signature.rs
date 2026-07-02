//! ZK-friendly signature scheme: Schnorr over BabyJubJub with a Poseidon
//! challenge hash.
//!
//! This is EdDSA-shaped (same curve and hash as circomlib's EdDSA/Poseidon
//! components) but uses the plain Schnorr equation
//! `S * B8 == R + c * A` with `c = Poseidon(R.x, R.y, A.x, A.y, msg)`,
//! so that exactly the same verification is implemented natively here and in
//! `circuits/components/signature_verify.circom` (using circomlib's
//! BabyJubJub scalar-multiplication gadgets and the same Base8 point).
//!
//! The base point is circomlib's `Base8` (8 * generator), which generates the
//! prime-order subgroup of order l.

use ark_ec::CurveGroup;
use ark_ff::{PrimeField, UniformRand, Zero};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::crypto::poseidon_native::poseidon;
use crate::types::{fserde, F};

pub type JubScalar = ark_ed_on_bn254::Fr;
pub type JubAffine = ark_ed_on_bn254::EdwardsAffine;
pub type JubProjective = ark_ed_on_bn254::EdwardsProjective;

/// circomlib Base8 (x coordinate).
pub const BASE8_X: &str =
    "5299619240641551281634865583518297030282874472190772894086521144482721001553";
/// circomlib Base8 (y coordinate).
pub const BASE8_Y: &str =
    "16950150798460657717958625567821834550301663161624707787222815936182638968203";

// ---------------------------------------------------------------------------
// circomlib <-> arkworks coordinate mapping.
//
// circomlib uses Baby Jubjub in the twisted Edwards form
//     168700 x^2 + y^2 = 1 + 168696 x^2 y^2,
// while ark-ed-on-bn254 uses the isomorphic scaled form with a = 1:
//     x'^2 + y^2 = 1 + (168696/168700) x'^2 y^2,      x' = sqrt(168700) * x.
//
// ALL coordinates stored in protocol types (VerificationKey, Signature,
// EaPublicKey, ciphertexts) and hashed by Poseidon are in CIRCOMLIB form so
// they match the circuit; arithmetic is done on mapped ark points.
// ---------------------------------------------------------------------------

use std::sync::OnceLock;

fn scaling() -> &'static (F, F) {
    static S: OnceLock<(F, F)> = OnceLock::new();
    S.get_or_init(|| {
        use ark_ff::Field;
        let s = F::from(168700u64).sqrt().expect("168700 is a QR mod p");
        (s, s.inverse().expect("nonzero"))
    })
}

/// arkworks point -> circomlib (x, y) coordinates.
pub fn to_circom_point(p: &JubAffine) -> (F, F) {
    let (_, s_inv) = scaling();
    (p.x * s_inv, p.y)
}

/// circomlib (x, y) coordinates -> arkworks point (unchecked).
pub fn from_circom_point(x: F, y: F) -> JubAffine {
    let (s, _) = scaling();
    JubAffine::new_unchecked(x * *s, y)
}

/// circomlib Base8 coordinates as field elements.
pub fn base8_circom_coords() -> (F, F) {
    (
        crate::types::f_from_dec(BASE8_X).expect("base8 x"),
        crate::types::f_from_dec(BASE8_Y).expect("base8 y"),
    )
}

/// circomlib Base8 point (prime-order subgroup generator), in ark form.
pub fn base8() -> JubAffine {
    let (x, y) = base8_circom_coords();
    let p = from_circom_point(x, y);
    debug_assert!(p.is_on_curve() && p.is_in_correct_subgroup_assuming_on_curve());
    p
}

#[derive(Debug, Clone)]
pub struct SecretKey(pub JubScalar);

/// Verification key: BabyJubJub point (affine coordinates in F).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationKey {
    #[serde(with = "fserde")]
    pub x: F,
    #[serde(with = "fserde")]
    pub y: F,
}

/// Signature (R.x, R.y, S). S is a scalar mod l, embedded in F (l < p).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signature {
    #[serde(with = "fserde")]
    pub rx: F,
    #[serde(with = "fserde")]
    pub ry: F,
    #[serde(with = "fserde")]
    pub s: F,
}

/// Interpret a base-field element as a BabyJubJub scalar (mod l). This
/// matches the circuit, where the 254-bit challenge is fed to
/// EscalarMulAny and the group order reduces it implicitly.
pub fn jub_scalar_from_field(f: &F) -> JubScalar {
    use ark_ff::BigInteger;
    JubScalar::from_le_bytes_mod_order(&f.into_bigint().to_bytes_le())
}

/// Embed a BabyJubJub scalar into the base field (injective since l < p).
pub fn field_from_jub_scalar(s: &JubScalar) -> F {
    use ark_ff::BigInteger;
    F::from_le_bytes_mod_order(&s.into_bigint().to_bytes_le())
}

/// True iff the integer value of `f` is a canonical scalar (< l).
pub fn f_is_canonical_scalar(f: &F) -> bool {
    use ark_ff::BigInteger;
    let fi = num_bigint::BigUint::from_bytes_be(&f.into_bigint().to_bytes_be());
    let l = num_bigint::BigUint::from_bytes_be(
        &JubScalar::MODULUS.to_bytes_be(),
    );
    fi < l
}

/// Try to decode an on-curve, in-subgroup point from circomlib-form (x, y).
/// Returns None if the coordinates are not a valid subgroup point.
pub fn decode_point(x: F, y: F) -> Option<JubAffine> {
    let p = from_circom_point(x, y);
    if p.is_on_curve() && p.is_in_correct_subgroup_assuming_on_curve() {
        Some(p)
    } else {
        None
    }
}

pub fn keygen<R: RngCore + CryptoRng>(rng: &mut R) -> (SecretKey, VerificationKey) {
    let sk = loop {
        let s = JubScalar::rand(rng);
        if !s.is_zero() {
            break s;
        }
    };
    let a = (JubProjective::from(base8()) * sk).into_affine();
    let (x, y) = to_circom_point(&a);
    (SecretKey(sk), VerificationKey { x, y })
}

/// Poseidon challenge c = Poseidon(R.x, R.y, A.x, A.y, msg) — arity 5.
pub fn challenge(rx: F, ry: F, vk: &VerificationKey, msg: F) -> F {
    poseidon(&[rx, ry, vk.x, vk.y, msg])
}

pub fn sign<R: RngCore + CryptoRng>(sk: &SecretKey, msg: F, rng: &mut R) -> Signature {
    let base = JubProjective::from(base8());
    let a = (base * sk.0).into_affine();
    let (ax, ay) = to_circom_point(&a);
    let vk = VerificationKey { x: ax, y: ay };
    let r = loop {
        let r = JubScalar::rand(rng);
        if !r.is_zero() {
            break r;
        }
    };
    let rp = (base * r).into_affine();
    let (rx, ry) = to_circom_point(&rp);
    let c = jub_scalar_from_field(&challenge(rx, ry, &vk, msg));
    let s = r + c * sk.0;
    Signature { rx, ry, s: field_from_jub_scalar(&s) }
}

/// Verify S * B8 == R + c * A. Returns false (never panics) on malformed
/// inputs: off-curve points, non-canonical S, identity points.
pub fn verify(vk: &VerificationKey, msg: F, sig: &Signature) -> bool {
    let a = match decode_point(vk.x, vk.y) {
        Some(p) if !p.is_zero() => p,
        _ => return false,
    };
    let rp = match decode_point(sig.rx, sig.ry) {
        Some(p) => p,
        None => return false,
    };
    if !f_is_canonical_scalar(&sig.s) {
        return false;
    }
    let s = jub_scalar_from_field(&sig.s);
    let c = jub_scalar_from_field(&challenge(sig.rx, sig.ry, vk, msg));
    let lhs = JubProjective::from(base8()) * s;
    let rhs = JubProjective::from(rp) + JubProjective::from(a) * c;
    lhs.into_affine() == rhs.into_affine()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::ChaCha20Rng;
    use rand::SeedableRng;

    #[test]
    fn base8_is_valid_subgroup_point() {
        let p = base8();
        assert!(p.is_on_curve());
        assert!(p.is_in_correct_subgroup_assuming_on_curve());
    }

    #[test]
    fn sign_verify_roundtrip() {
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        let (sk, vk) = keygen(&mut rng);
        let msg = F::from(42u64);
        let sig = sign(&sk, msg, &mut rng);
        assert!(verify(&vk, msg, &sig));
        assert!(!verify(&vk, F::from(43u64), &sig));
        let bad = Signature { s: sig.s + F::from(1u64), ..sig };
        assert!(!verify(&vk, msg, &bad));
    }

    #[test]
    fn wrong_key_rejects() {
        let mut rng = ChaCha20Rng::seed_from_u64(2);
        let (sk, _vk) = keygen(&mut rng);
        let (_sk2, vk2) = keygen(&mut rng);
        let msg = F::from(7u64);
        let sig = sign(&sk, msg, &mut rng);
        assert!(!verify(&vk2, msg, &sig));
    }
}
