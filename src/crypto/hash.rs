//! Protocol hash functions. Every hash that appears inside the circuit is
//! Poseidon with a fixed arity; the arity itself provides (weak) domain
//! separation between H_com, H_reg, the signature message hash and the
//! ciphertext commitment. A production design should add explicit domain
//! tags.

use ark_ff::PrimeField;
use sha2::{Digest, Sha256};

use crate::crypto::poseidon_native::poseidon;
use crate::crypto::signature::VerificationKey;
use crate::types::{Candidate, F, Nonce, VoterId};

/// Map an election id string into the field: SHA-256 with a domain prefix,
/// reduced mod p. (This hash is computed outside the circuit; the circuit
/// only ever sees the resulting field element.)
pub fn eid_to_field(eid: &str) -> F {
    let mut h = Sha256::new();
    h.update(b"CRDR-EID-V1");
    h.update(eid.as_bytes());
    F::from_be_bytes_mod_order(&h.finalize())
}

/// h_i = H_com(eid_hash, i, vk_i, R_i, R_EA,i)  — Poseidon arity 6.
pub fn h_com(eid_hash: F, id: VoterId, vk: &VerificationKey, r: Nonce, r_ea: Nonce) -> F {
    poseidon(&[eid_hash, F::from(id), vk.x, vk.y, r, r_ea])
}

/// leaf_i = H_reg(eid_hash, i, vk_i, h_i)  — Poseidon arity 5.
pub fn h_reg(eid_hash: F, id: VoterId, vk: &VerificationKey, h: F) -> F {
    poseidon(&[eid_hash, F::from(id), vk.x, vk.y, h])
}

/// Signature message hash: Poseidon(eid_hash, id, candidate, R) — arity 4.
pub fn sig_msg_hash(eid_hash: F, id: VoterId, candidate: Candidate, r: Nonce) -> F {
    poseidon(&[eid_hash, F::from(id), F::from(candidate), r])
}

/// Commitment-mode ciphertext: Poseidon(plaintext_fields || rho) — arity 10.
pub fn ct_commit(plaintext_fields: &[F; crate::types::PLAINTEXT_FIELD_LEN], rho: F) -> F {
    let mut inp = plaintext_fields.to_vec();
    inp.push(rho);
    poseidon(&inp)
}

/// Merkle inner node hash — Poseidon arity 2.
pub fn merkle_hash(left: F, right: F) -> F {
    poseidon(&[left, right])
}

/// Bulletin-board commitment: a Poseidon chain over all ciphertext fields of
/// the listed ballots, in BB order. acc_0 = 0; acc <- Poseidon(acc, field).
pub fn bb_commitment(ciphertext_fields: &[Vec<F>]) -> F {
    let mut acc = F::from(0u64);
    for ct in ciphertext_fields {
        for f in ct {
            acc = poseidon(&[acc, *f]);
        }
    }
    acc
}

/// Commitment to the candidate list — Poseidon over the candidate values.
pub fn candidate_set_commitment(candidates: &[Candidate]) -> F {
    let inp: Vec<F> = candidates.iter().map(|c| F::from(*c)).collect();
    poseidon(&inp)
}

/// Commitment to the EA public key (bound into the public statement).
pub fn pk_ea_commitment(pk: &crate::crypto::encryption::EaPublicKey) -> F {
    poseidon(&[pk.x, pk.y])
}

/// Hash of a ballot's public bytes, for submission receipts — Poseidon chain
/// over the ciphertext fields of a single ballot.
pub fn ballot_hash(ciphertext_fields: &[F]) -> F {
    let mut acc = F::from(0u64);
    for f in ciphertext_fields {
        acc = poseidon(&[acc, *f]);
    }
    acc
}
