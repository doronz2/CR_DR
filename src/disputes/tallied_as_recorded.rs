//! Tallied-as-recorded dispute resolution (private judge).
//!
//! The judge privately receives the voter's claimed ballot opening, and the
//! authority nonce R_EA,i either directly from the EA or as a reconstruction
//! from >= t threshold shares. The judge can therefore test the hidden nonce
//! relation that neither the voter nor the coercer can test.
//!
//! The judge NEVER forwards R_EA,i to the voter (a transferable R_EA,i would
//! be a receipt), and its detailed report is judge-private.

use crate::crypto::encryption::{commit_open, EncOpening};
use crate::crypto::hash::{h_com, h_reg, sig_msg_hash};
use crate::crypto::merkle::verify_path;
use crate::crypto::shamir::Share;
use crate::crypto::signature::verify;
use crate::disputes::judge::{JudgeReport, Verdict};
use crate::protocol::bulletin_board::BulletinBoard;
use crate::protocol::preprocessing::RegistrationState;
use crate::types::{Ballot, BallotPlaintext, F, InternalBallotStatus, PublicParams};

/// How the judge obtains R_EA,i.
#[derive(Debug, Clone)]
pub enum NonceSource {
    /// Directly from the (single) election authority.
    Direct(F),
    /// Reconstructed from >= t threshold authority shares.
    ThresholdShares(Vec<Share>),
}

/// A voter's tallied-as-recorded complaint, delivered privately to the judge.
#[derive(Debug, Clone)]
pub struct TalliedAsRecordedComplaint {
    pub ballot: Ballot,
    pub opening: EncOpening,
}

/// Evidence the judge obtains from the authority side.
pub struct AuthorityEvidence<'a> {
    pub nonce_source: NonceSource,
    /// Internal evaluations of the ballots preceding the complained ballot
    /// on the board (judge-private; needed for duplicate adjudication).
    pub prior_evaluations: &'a [crate::types::InternalBallotEvaluation],
    /// Whether the public tally proof verified against the public statement.
    pub tally_proof_valid: bool,
}

/// Adjudicate a tallied-as-recorded complaint.
pub fn judge_tallied_as_recorded(
    pp: &PublicParams,
    registration_state: &RegistrationState,
    bb: &BulletinBoard,
    complaint: &TalliedAsRecordedComplaint,
    evidence: &AuthorityEvidence<'_>,
) -> JudgeReport {
    // (0) the complaint presumes the ballot is recorded.
    let Some(board_index) = bb
        .list_public_ballots()
        .iter()
        .position(|b| b.bytes == complaint.ballot.bytes)
    else {
        return JudgeReport::new(
            Verdict::Undetermined,
            "ballot is not recorded on the board; file a recorded-as-cast dispute instead",
        );
    };

    // (1) ballot opens/decrypts to the claimed plaintext.
    let opened = match commit_open(&complaint.ballot.ciphertext, &complaint.ballot.ea_payload) {
        Ok(o) => o,
        Err(_) => {
            return JudgeReport::new(Verdict::VoterFaulty, "ballot does not open correctly")
        }
    };
    if opened != complaint.opening {
        return JudgeReport::new(Verdict::VoterFaulty, "claimed opening does not match ballot");
    }
    let pt = match BallotPlaintext::from_fields(&opened.plaintext_fields) {
        Ok(p) => p,
        Err(_) => return JudgeReport::new(Verdict::VoterFaulty, "malformed plaintext"),
    };
    if pt.eid_hash != pp.eid_hash {
        return JudgeReport::new(Verdict::VoterFaulty, "wrong election id");
    }
    if !pp.candidates.contains(&pt.candidate) {
        return JudgeReport::new(Verdict::VoterFaulty, "invalid candidate");
    }

    // (2) signature verifies.
    let msg = sig_msg_hash(pt.eid_hash, pt.id, pt.candidate, pt.r);
    if !verify(&pt.vk, msg, &pt.sigma) {
        return JudgeReport::new(Verdict::VoterFaulty, "invalid signature");
    }

    // Public registration record.
    let Some(record) = registration_state.record(pt.id) else {
        return JudgeReport::new(Verdict::VoterFaulty, "voter id not registered");
    };
    if record.vk != pt.vk {
        return JudgeReport::new(Verdict::VoterFaulty, "vk does not match registration");
    }

    // (3-5) hidden nonce relation, using the judge-private R_EA,i.
    let r_ea = match &evidence.nonce_source {
        NonceSource::Direct(v) => *v,
        NonceSource::ThresholdShares(shares) => match crate::crypto::shamir::reconstruct(shares) {
            Ok(v) => v,
            Err(_) => {
                return JudgeReport::new(
                    Verdict::Undetermined,
                    "could not reconstruct authority nonce from shares",
                )
            }
        },
    };
    let h = h_com(pt.eid_hash, pt.id, &pt.vk, pt.r, r_ea);
    if h != record.h {
        // The registered commitment does not open to the voter's claimed R:
        // the voter presented a fake nonce (this is exactly the private
        // detection of a fake-compliance ballot).
        return JudgeReport::new(
            Verdict::VoterFaulty,
            "hidden nonce relation fails: claimed R is not the registered nonce",
        );
    }
    let leaf = h_reg(pt.eid_hash, pt.id, &pt.vk, h);
    let in_tree = registration_state
        .paths
        .get(&pt.id)
        .map(|p| verify_path(registration_state.root, leaf, p))
        .unwrap_or(false);
    if leaf != record.leaf || !in_tree {
        // The nonce relation holds against the public h, but registration
        // data is inconsistent with the Merkle root: authority-side fault.
        return JudgeReport::new(
            Verdict::AuthorityFaulty,
            "registration leaf inconsistent with the published root",
        );
    }

    // (6) duplicate status under the public rule.
    let dup_before = evidence.prior_evaluations.iter().any(|e| {
        e.ballot_index < board_index
            && e.voter_id == Some(pt.id)
            && matches!(e.status, InternalBallotStatus::Counted)
    });
    if dup_before {
        return JudgeReport::new(
            Verdict::VoterFaulty,
            "ballot is valid but an earlier valid ballot for this voter counts first",
        );
    }

    // (7) the ballot is valid and first: it must have been counted.
    if !evidence.tally_proof_valid {
        return JudgeReport::new(
            Verdict::AuthorityFaulty,
            "valid first ballot, and the public tally proof does not verify",
        );
    }
    JudgeReport::new(
        Verdict::Undetermined,
        "valid first ballot and a verifying tally proof: under proof soundness the ballot \
         was counted; no fault identified",
    )
}
