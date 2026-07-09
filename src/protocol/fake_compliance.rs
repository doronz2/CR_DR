//! Fake compliance: what a coerced voter hands to (or performs for) the
//! coercer.
//!
//! The voter reveals their REAL signing key sk_i together with a FAKE nonce
//! R~ != R_i, and signs the coercer's requested candidate under R~. The
//! coercer can verify the signature (it is genuinely valid under vk_i), but
//! cannot test whether R~ is the registered nonce, because doing so requires
//! the authority nonce R_EA,i which the voter never had.

use ark_ff::UniformRand;
use rand::{CryptoRng, RngCore};

use crate::crypto::hash::sig_msg_hash;
use crate::crypto::signature::{sign, SecretKey, Signature, VerificationKey};
use crate::errors::{CrDrError, Result};
use crate::types::{Ballot, BallotPlaintext, Candidate, F, Nonce, PublicParams, VoterState};

/// Everything the coerced voter surrenders to the coercer. Note it contains
/// the REAL signing key — coercion resistance does not rest on hiding sk_i.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FakeComplianceTranscript {
    pub voter_id: u64,
    pub sk: SecretKey,
    pub vk: VerificationKey,
    #[serde(with = "crate::types::fserde")]
    pub r_fake: Nonce,
    pub requested_candidate: Candidate,
    pub sigma_fake: Signature,
}

/// Produce the fake-compliance transcript for the coercer's requested
/// candidate. Samples R~ != R_i and signs (eid, i, m*, R~) with the real key.
pub fn fake_compliance<R: RngCore + CryptoRng>(
    pp: &PublicParams,
    voter_state: &VoterState,
    requested_candidate: Candidate,
    rng: &mut R,
) -> Result<FakeComplianceTranscript> {
    if !pp.candidates.contains(&requested_candidate) {
        return Err(CrDrError::InvalidCandidate(requested_candidate));
    }
    let r_fake = loop {
        let r = F::rand(rng);
        if r != voter_state.r {
            break r;
        }
    };
    let msg = sig_msg_hash(pp.eid_hash, voter_state.id, requested_candidate, r_fake);
    let sigma_fake = sign(&voter_state.sk, msg, rng);
    Ok(FakeComplianceTranscript {
        voter_id: voter_state.id,
        sk: voter_state.sk.clone(),
        vk: voter_state.vk,
        r_fake,
        requested_candidate,
        sigma_fake,
    })
}

/// Build the ballot the coercer submits (or watches being submitted) from a
/// fake-compliance transcript. Publicly indistinguishable from a real ballot.
pub fn build_fake_ballot<R: RngCore + CryptoRng>(
    _pp: &PublicParams,
    transcript: &FakeComplianceTranscript,
    rng: &mut R,
) -> Result<Ballot> {
    let plaintext = BallotPlaintext {
        eid_hash: _pp.eid_hash,
        id: transcript.voter_id,
        vk: transcript.vk,
        candidate: transcript.requested_candidate,
        r: transcript.r_fake,
        sigma: transcript.sigma_fake,
    };
    crate::protocol::vote::seal_ballot(_pp, &plaintext, rng)
}
