//! Exact FilterAndTally.
//!
//! CRITICAL INVARIANT: duplicate handling is applied ONLY AFTER a ballot has
//! passed every validity check. Invalid ballots (fake-compliance, chaff,
//! garbage) never consume the voter's slot, so a fake ballot appearing
//! before the real one cannot block it.

use std::collections::HashSet;

use crate::crypto::encryption::commit_open;
use crate::crypto::hash::{h_com, h_reg, sig_msg_hash};
use crate::crypto::merkle::verify_path;
use crate::crypto::signature::verify;
use crate::errors::Result;
use crate::protocol::preprocessing::RegistrationState;
use crate::types::{
    AuthoritySecretState, Ballot, BallotPlaintext, DuplicateRule,
    InternalBallotEvaluation, InternalBallotStatus, PublicParams, TallyResult,
};

/// Run FilterAndTally over the public bulletin-board order.
///
/// Returns the public `TallyResult` and an internal per-ballot evaluation log
/// that is for TESTS/DEBUG ONLY and must never be published (it reveals
/// which ballots were counted, voter identities and rejection reasons).
pub fn filter_and_tally(
    pp: &PublicParams,
    authority_secret: &AuthoritySecretState,
    registration_state: &RegistrationState,
    ballots: &[Ballot],
) -> Result<(TallyResult, Vec<InternalBallotEvaluation>)> {
    let mut counts = vec![0u64; pp.candidates.len()];
    let mut counted_voters: HashSet<u64> = HashSet::new();
    let mut evaluations = Vec::with_capacity(ballots.len());
    let mut counted_ballots = 0u64;

    for (ballot_index, ballot) in ballots.iter().enumerate() {
        let status = evaluate_ballot(
            pp,
            authority_secret,
            registration_state,
            ballot,
            &mut counted_voters,
            &mut counts,
        );
        if let (InternalBallotStatus::Counted, _, _) = status {
            counted_ballots += 1;
        }
        evaluations.push(InternalBallotEvaluation {
            ballot_index,
            status: status.0,
            voter_id: status.1,
            candidate: status.2,
        });
    }

    Ok((TallyResult { counts, counted_ballots }, evaluations))
}

type BallotOutcome = (InternalBallotStatus, Option<u64>, Option<u64>);

fn evaluate_ballot(
    pp: &PublicParams,
    authority_secret: &AuthoritySecretState,
    registration_state: &RegistrationState,
    ballot: &Ballot,
    counted_voters: &mut HashSet<u64>,
    counts: &mut [u64],
) -> BallotOutcome {
    // (a) decrypt/open
    let opening = match commit_open(&ballot.ciphertext, &ballot.ea_payload) {
        Ok(o) => o,
        Err(_) => return (InternalBallotStatus::InvalidDecryption, None, None),
    };

    // (b) parse plaintext
    let pt: BallotPlaintext = match BallotPlaintext::from_fields(&opening.plaintext_fields) {
        Ok(p) => p,
        Err(_) => return (InternalBallotStatus::InvalidFormat, None, None),
    };

    // (c) election id binding
    if pt.eid_hash != pp.eid_hash {
        return (InternalBallotStatus::InvalidFormat, Some(pt.id), Some(pt.candidate));
    }

    // (d) candidate in C
    let Some(cand_pos) = pp.candidates.iter().position(|c| *c == pt.candidate) else {
        return (InternalBallotStatus::InvalidCandidate, Some(pt.id), Some(pt.candidate));
    };

    // (e) signature over (eid_hash, id, candidate, R)
    let msg = sig_msg_hash(pt.eid_hash, pt.id, pt.candidate, pt.r);
    if !verify(&pt.vk, msg, &pt.sigma) {
        return (InternalBallotStatus::InvalidSignature, Some(pt.id), Some(pt.candidate));
    }

    // (f) public registration record for (id, vk)
    let record = match registration_state.record(pt.id) {
        Some(rec) if rec.vk == pt.vk => rec,
        _ => {
            return (InternalBallotStatus::InvalidRegistration, Some(pt.id), Some(pt.candidate))
        }
    };

    // (g) authority nonce R_EA,i
    let Some(secret) = authority_secret.voter_secrets.get(&pt.id) else {
        return (InternalBallotStatus::InvalidRegistration, Some(pt.id), Some(pt.candidate));
    };

    // (h) hidden nonce relation + Merkle membership
    let h = h_com(pt.eid_hash, pt.id, &pt.vk, pt.r, secret.r_ea);
    let leaf = h_reg(pt.eid_hash, pt.id, &pt.vk, h);
    let path_ok = registration_state
        .paths
        .get(&pt.id)
        .map(|path| verify_path(registration_state.root, leaf, path))
        .unwrap_or(false);
    if !path_ok || leaf != record.leaf {
        return (InternalBallotStatus::InvalidRegistration, Some(pt.id), Some(pt.candidate));
    }

    // (i) ballot is VALID. (j) Only now apply the duplicate rule.
    match pp.duplicate_rule {
        DuplicateRule::FirstValidCounts => {
            if counted_voters.contains(&pt.id) {
                (InternalBallotStatus::DuplicateValidBallot, Some(pt.id), Some(pt.candidate))
            } else {
                counted_voters.insert(pt.id);
                counts[cand_pos] += 1;
                (InternalBallotStatus::Counted, Some(pt.id), Some(pt.candidate))
            }
        }
    }
}
