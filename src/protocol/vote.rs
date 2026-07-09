//! Real-vote casting in the CAST-ZK format.

use ark_ff::UniformRand;
use rand::{CryptoRng, RngCore};

use crate::crypto::encryption::{cast_encrypt, sample_rho_enc, CastSecret, EncOpening, CAST_CT_LEN};
use crate::crypto::hash::{ct_commit, sig_msg_hash};
use crate::crypto::signature::sign;
use crate::errors::{CrDrError, Result};
use crate::protocol::preprocessing::RegistrationState;
use crate::types::{Ballot, BallotPlaintext, Candidate, F, PublicParams, VoterState};

/// Seal a plaintext into the CAST-ZK ballot format:
///     com     = H_ballot_com(opening, r_com)
///     ct_open = Enc_pkEA(opening, r_com; rho_enc)
/// The returned Ballot carries the CastSecret (for pi_cast generation via
/// zk::cast and for disputes); only Ballot::public() goes on the board.
pub fn seal_ballot<R: RngCore + CryptoRng>(
    pp: &PublicParams,
    plaintext: &BallotPlaintext,
    rng: &mut R,
) -> Result<Ballot> {
    let fields = plaintext.to_fields();
    let r_com = F::rand(rng);
    let com = ct_commit(&fields, r_com);
    let rho_enc = sample_rho_enc(rng);
    let mut cast_fields = [F::from(0u64); CAST_CT_LEN];
    cast_fields[..9].copy_from_slice(&fields);
    cast_fields[9] = r_com;
    let ct_open = cast_encrypt(&pp.pk_ea, &cast_fields, rho_enc)?;
    Ok(Ballot {
        com,
        ct_open,
        secret: CastSecret {
            opening: EncOpening { plaintext_fields: fields.to_vec(), rho: r_com },
            rho_enc,
        },
    })
}

/// Build a real ballot for `candidate`.
///
/// sigma = Sign_sk_i(eid_hash, i, candidate, R_i); the plaintext
/// (eid_hash, i, vk_i, candidate, R_i, sigma) is sealed into the CAST-ZK
/// format (commitment + encrypted opening; pi_cast attached separately).
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
    seal_ballot(pp, &plaintext, rng)
}
