//! Chaff ballots: syntactically well-formed ballots for unregistered
//! identities. They are rejected by FilterAndTally exactly like
//! fake-compliance ballots (both end in InvalidRegistration), share the same
//! public object shape (one ciphertext commitment + EA payload), and carry no
//! marker distinguishing them from real or fake ballots.

use ark_ff::UniformRand;
use rand::{CryptoRng, Rng, RngCore};

use crate::crypto::encryption::{commit_encrypt, opening_to_payload};
use crate::crypto::hash::sig_msg_hash;
use crate::crypto::signature::{keygen, sign};
use crate::errors::Result;
use crate::types::{Ballot, BallotPlaintext, F, PublicParams};

/// Generate one chaff ballot: a fresh identity (keypair + nonce) that is not
/// in the registration tree, voting for a random valid candidate, correctly
/// signed. It passes every syntactic check and fails only the hidden
/// registration relation.
pub fn chaff_ballot<R: RngCore + CryptoRng>(pp: &PublicParams, rng: &mut R) -> Result<Ballot> {
    // A plausible voter id in-range; the fresh vk (and nonce) cannot match
    // any committed registration record.
    let id = rng.gen_range(0..pp.max_voters as u64);
    let (sk, vk) = keygen(rng);
    let r = F::rand(rng);
    let candidate = pp.candidates[rng.gen_range(0..pp.candidates.len())];

    let msg = sig_msg_hash(pp.eid_hash, id, candidate, r);
    let sigma = sign(&sk, msg, rng);

    let plaintext =
        BallotPlaintext { eid_hash: pp.eid_hash, id, vk, candidate, r, sigma };
    let (ciphertext, opening) = commit_encrypt(&plaintext.to_fields(), rng);
    let bytes = ciphertext.to_bytes();
    Ok(Ballot { ciphertext, ea_payload: opening_to_payload(&opening), bytes })
}
