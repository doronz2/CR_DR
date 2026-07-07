//! Real-vote casting.

use rand::{CryptoRng, RngCore};

use crate::crypto::encryption::{commit_encrypt, opening_to_payload};
use crate::crypto::hash::sig_msg_hash;
use crate::crypto::signature::sign;
use crate::errors::{CrDrError, Result};
use crate::protocol::preprocessing::RegistrationState;
use crate::types::{Ballot, BallotPlaintext, Candidate, PublicParams, VoterState};

/// Build a real ballot for `candidate`.
///
/// sigma = Sign_sk_i(eid_hash, i, candidate, R_i); the plaintext
/// (eid_hash, i, vk_i, candidate, R_i, sigma) is encrypted (commitment-mode
/// backend) and the exact public bytes are fixed at this point.
pub fn cast_vote<R: RngCore + CryptoRng>(
    pp: &PublicParams,
    registration_state: &RegistrationState,
    voter_state: &VoterState,
    candidate: Candidate,
    rng: &mut R,
) -> Result<Ballot> {
    if !pp.candidates.contains(&candidate) {
        return Err(CrDrError::InvalidCandidate(candidate));
    }
    // Sanity: the voter is registered (not required to build a ballot, but a
    // real voter would check their public record exists).
    if registration_state.record(voter_state.id).is_none() {
        return Err(CrDrError::UnknownVoter(voter_state.id));
    }

    let msg = sig_msg_hash(pp.eid_hash, voter_state.id, candidate, voter_state.r);
    let sigma = sign(&voter_state.sk, msg, rng);

    let plaintext = BallotPlaintext {
        eid_hash: pp.eid_hash,
        id: voter_state.id,
        vk: voter_state.vk,
        candidate,
        r: voter_state.r,
        sigma,
    };
    let (ciphertext, opening) = commit_encrypt(&plaintext.to_fields(), rng);
    Ok(Ballot { ciphertext, ea_payload: opening_to_payload(&opening) })
}
