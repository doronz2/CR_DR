//! Core types for the CR-DR reference implementation.
//!
//! All values that enter the ZK circuit are encoded as BN254 scalar field
//! elements (`F`). Native protocol logic uses the same encoding so that the
//! native FilterAndTally, the native relation checker, and the Circom circuit
//! agree bit-for-bit.

use std::collections::HashMap;

use ark_ff::PrimeField;
use serde::{Deserialize, Serialize};

use crate::crypto::signature::{SecretKey, Signature, VerificationKey};
use crate::errors::{CrDrError, Result};

/// BN254 scalar field element (the field Circom/Groth16 operate over).
pub type F = ark_bn254::Fr;

pub type ElectionId = String;
pub type VoterId = u64;
pub type Candidate = u64;
/// Nonces are field elements (voter nonce R_i and authority nonce R_EA,i).
pub type Nonce = F;

/// Number of field elements in a ballot plaintext:
/// [eid_hash, id, vk.x, vk.y, candidate, R, sig.rx, sig.ry, sig.s]
pub const PLAINTEXT_FIELD_LEN: usize = 9;
pub const VK_FIELD_LEN: usize = 2;
pub const SIG_FIELD_LEN: usize = 3;

/// Serde helpers: field elements as decimal strings (circom-compatible).
pub mod fserde {
    use super::F;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(f: &F, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&crate::types::f_to_dec(f))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> std::result::Result<F, D::Error> {
        let s = String::deserialize(d)?;
        crate::types::f_from_dec(&s).map_err(serde::de::Error::custom)
    }
}

/// Serde helpers for `Vec<F>`.
pub mod fserde_vec {
    use super::F;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[F], s: S) -> std::result::Result<S::Ok, S::Error> {
        s.collect_seq(v.iter().map(|f| crate::types::f_to_dec(f)))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> std::result::Result<Vec<F>, D::Error> {
        let v = Vec::<String>::deserialize(d)?;
        v.iter()
            .map(|s| crate::types::f_from_dec(s).map_err(serde::de::Error::custom))
            .collect()
    }
}

/// Field element -> decimal string (circom input encoding).
pub fn f_to_dec(f: &F) -> String {
    let bytes = f.into_bigint().to_bytes_be();
    num_bigint::BigUint::from_bytes_be(&bytes).to_str_radix(10)
}

/// Decimal string -> field element (reduced mod p).
pub fn f_from_dec(s: &str) -> Result<F> {
    let n = num_bigint::BigUint::parse_bytes(s.as_bytes(), 10)
        .ok_or_else(|| CrDrError::Serialization(format!("bad decimal field element: {s}")))?;
    Ok(F::from_le_bytes_mod_order(&n.to_bytes_le()))
}

/// Field element -> fixed 32-byte big-endian encoding.
pub fn f_to_bytes_be(f: &F) -> [u8; 32] {
    let mut out = [0u8; 32];
    let b = f.into_bigint().to_bytes_be();
    out[32 - b.len()..].copy_from_slice(&b);
    out
}

use ark_ff::BigInteger;

/// Duplicate-ballot handling policy. Only first-valid-ballot-counts is
/// implemented; the id is bound into the public ZK statement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DuplicateRule {
    FirstValidCounts,
}

impl DuplicateRule {
    pub fn id(&self) -> u64 {
        match self {
            DuplicateRule::FirstValidCounts => 1,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThresholdParams {
    /// Reconstruction threshold: any t shares reconstruct, t-1 reveal nothing.
    pub t: usize,
    /// Total number of authorities.
    pub k: usize,
}

impl ThresholdParams {
    /// The degenerate single-authority case (t = k = 1): one authority whose
    /// single "share" IS the nonce. Used when no threshold params are
    /// configured, so the share-based state layout is uniform.
    pub const fn single() -> Self {
        ThresholdParams { t: 1, k: 1 }
    }
}

/// Public election parameters. Everything here is public.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicParams {
    pub eid: ElectionId,
    /// Poseidon-friendly hash of the election id (enters the circuit).
    #[serde(with = "fserde")]
    pub eid_hash: F,
    pub candidates: Vec<Candidate>,
    /// EA encryption public key (BabyJubJub point, used by the ElGamal
    /// backend; in commitment-mode it is only bound into the statement).
    pub pk_ea: crate::crypto::encryption::EaPublicKey,
    /// EA receipt-signing verification key (for submission receipts).
    pub ea_receipt_vk: VerificationKey,
    pub duplicate_rule: DuplicateRule,
    pub max_ballots: usize,
    pub max_voters: usize,
    pub merkle_depth: usize,
    pub threshold_params: Option<ThresholdParams>,
}

/// Everything the voter holds after preprocessing.
/// NOTE: the voter never holds R_EA,i (and this type cannot carry it).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoterState {
    pub id: VoterId,
    pub sk: SecretKey,
    pub vk: VerificationKey,
    #[serde(with = "fserde")]
    pub r: Nonce,
}

/// Public registration record posted for each voter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicRegistrationRecord {
    pub id: VoterId,
    pub vk: VerificationKey,
    /// h_i = H_com(eid_hash, i, vk_i, R_i, R_EA,i)
    #[serde(with = "fserde")]
    pub h: F,
    /// leaf_i = H_reg(eid_hash, i, vk_i, h_i)
    #[serde(with = "fserde")]
    pub leaf: F,
}

/// Authority-side per-voter record. Contains ONLY threshold material for
/// R_EA,i — Shamir shares, one per authority. It contains neither the voter
/// nonce R_i (which only the voter samples and holds) nor the plain R_EA,i
/// (which exists only transiently inside the idealized preprocessing
/// functionality and inside authorized >= t reconstructions). Any coalition
/// of fewer than t authorities holds < t shares, which are distributed
/// independently of R_EA,i.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorityVoterSecret {
    pub id: VoterId,
    pub vk: VerificationKey,
    /// Shamir shares of R_EA,i; shares[j] belongs to authority j+1.
    pub r_ea_shares: Vec<crate::crypto::shamir::Share>,
}

/// The single LOGICAL election authority, implemented by k threshold
/// authorities. Serializable only so the CLI can persist it in the
/// authority's private directory — never publish it.
///
/// In a deployment each authority would hold only its own row of every
/// share vector; this struct models their joint (authorized) interface.
#[derive(Debug, Serialize, Deserialize)]
pub struct AuthoritySecretState {
    /// EA decryption key (ElGamal backend).
    pub sk_ea: crate::crypto::encryption::EaSecretKey,
    /// EA receipt-signing key.
    pub receipt_sk: SecretKey,
    /// Threshold parameters the nonce shares were generated under.
    pub threshold: ThresholdParams,
    pub voter_secrets: HashMap<VoterId, AuthorityVoterSecret>,
}

impl AuthoritySecretState {
    /// AUTHORIZED reconstruction of R_EA,i by the logical EA — models a
    /// >= t quorum of authorities agreeing to open the nonce (for tallying,
    /// witness construction, or a private-judge dispute). Tier-1/Tier-2
    /// provers call this to obtain the plain nonce; a Tier-3 threshold
    /// prover would replace this call with an MPC evaluation over the same
    /// shares, which is why no other code path ever stores the plain value.
    pub fn r_ea(&self, id: VoterId) -> Result<F> {
        let secret =
            self.voter_secrets.get(&id).ok_or(CrDrError::UnknownVoter(id))?;
        if secret.r_ea_shares.len() < self.threshold.t {
            return Err(CrDrError::Threshold(format!(
                "voter {id}: {} shares stored, need >= t = {}",
                secret.r_ea_shares.len(),
                self.threshold.t
            )));
        }
        crate::crypto::shamir::reconstruct(&secret.r_ea_shares)
    }
}

/// Decoded ballot plaintext.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BallotPlaintext {
    pub eid_hash: F,
    pub id: VoterId,
    pub vk: VerificationKey,
    pub candidate: Candidate,
    pub r: Nonce,
    pub sigma: Signature,
}

impl BallotPlaintext {
    /// Canonical field encoding used by hashing, encryption and the circuit.
    pub fn to_fields(&self) -> [F; PLAINTEXT_FIELD_LEN] {
        [
            self.eid_hash,
            F::from(self.id),
            self.vk.x,
            self.vk.y,
            F::from(self.candidate),
            self.r,
            self.sigma.rx,
            self.sigma.ry,
            self.sigma.s,
        ]
    }

    /// Parse a field encoding. Fails (InvalidFormat at the protocol layer) if
    /// id/candidate are not u64-range integers.
    pub fn from_fields(fields: &[F]) -> Result<Self> {
        if fields.len() != PLAINTEXT_FIELD_LEN {
            return Err(CrDrError::Serialization(format!(
                "plaintext must have {PLAINTEXT_FIELD_LEN} fields, got {}",
                fields.len()
            )));
        }
        let id = f_to_u64(&fields[1])
            .ok_or_else(|| CrDrError::Serialization("voter id out of u64 range".into()))?;
        let candidate = f_to_u64(&fields[4])
            .ok_or_else(|| CrDrError::Serialization("candidate out of u64 range".into()))?;
        Ok(BallotPlaintext {
            eid_hash: fields[0],
            id,
            vk: VerificationKey { x: fields[2], y: fields[3] },
            candidate,
            r: fields[5],
            sigma: Signature { rx: fields[6], ry: fields[7], s: fields[8] },
        })
    }
}

/// Try to interpret a field element as a small u64 integer.
pub fn f_to_u64(f: &F) -> Option<u64> {
    let limbs = f.into_bigint().0;
    if limbs[1] == 0 && limbs[2] == 0 && limbs[3] == 0 {
        Some(limbs[0])
    } else {
        None
    }
}

/// A ballot as cast by the voter and carried by the anonymous channel.
///
/// `ea_payload` models the ciphertext body that only the EA can open. In the
/// commitment-mode prototype backend this is a serialized opening — the full
/// plaintext, nonce and signature — so it must NEVER be published; only the
/// EA (and, for a dispute, the private judge) may see it. See the loud
/// warning in README and `crypto::encryption`.
///
/// Only the projection [`Ballot::public`] goes on the bulletin board. The
/// exact public byte encoding is always derived from the ciphertext via
/// [`Ballot::bytes`], never stored, so it cannot disagree with what is
/// tallied.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ballot {
    pub ciphertext: crate::crypto::encryption::Ciphertext,
    pub ea_payload: Vec<u8>,
}

impl Ballot {
    /// The public part of the ballot: exactly what is posted on the board.
    pub fn public(&self) -> PublicBallot {
        PublicBallot { ciphertext: self.ciphertext.clone() }
    }

    /// Exact public byte encoding (derived from the ciphertext).
    pub fn bytes(&self) -> Vec<u8> {
        self.ciphertext.to_bytes()
    }
}

/// The public part of a ballot: only the ciphertext. This is the ONLY
/// per-ballot data that appears on the public bulletin board.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicBallot {
    pub ciphertext: crate::crypto::encryption::Ciphertext,
}

impl PublicBallot {
    /// Exact public byte encoding (derived from the ciphertext).
    pub fn bytes(&self) -> Vec<u8> {
        self.ciphertext.to_bytes()
    }
}

/// EA-PRIVATE store of the ballot payloads, aligned with bulletin-board
/// order: `payloads[i]` belongs to board entry `i`. In commitment mode a
/// payload is the full plaintext opening — publishing it would reveal votes,
/// voter ids, nonces and signatures.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuthorityBallotPayloads {
    pub payloads: Vec<Vec<u8>>,
}

/// Public tally output. This is the ONLY tally-related public output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TallyResult {
    /// counts[i] = number of counted ballots for candidates[i].
    pub counts: Vec<u64>,
    pub counted_ballots: u64,
}

/// Internal per-ballot status. TEST/DEBUG ONLY — never part of public output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InternalBallotStatus {
    Counted,
    InvalidDecryption,
    InvalidFormat,
    InvalidCandidate,
    InvalidSignature,
    InvalidRegistration,
    DuplicateValidBallot,
}

/// Internal per-ballot evaluation. TEST/DEBUG ONLY — never part of public
/// output. Deliberately does not implement Serialize.
#[derive(Debug, Clone)]
pub struct InternalBallotEvaluation {
    pub ballot_index: usize,
    pub status: InternalBallotStatus,
    pub voter_id: Option<VoterId>,
    pub candidate: Option<Candidate>,
}

/// Election configuration for setup.
#[derive(Debug, Clone)]
pub struct ElectionConfig {
    pub eid: ElectionId,
    pub candidates: Vec<Candidate>,
    pub max_voters: usize,
    pub max_ballots: usize,
    pub merkle_depth: usize,
    pub duplicate_rule: DuplicateRule,
    pub threshold_params: Option<ThresholdParams>,
}
