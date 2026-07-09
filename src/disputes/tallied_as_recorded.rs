//! Tallied-as-recorded dispute resolution (private judge).
//!
//! The judge privately receives the voter's claimed ballot opening, and the
//! authority nonce R_EA,i either directly from the EA or as a reconstruction
//! from >= t threshold shares. The judge can therefore test the hidden nonce
//! relation that neither the voter nor the coercer can test.
//!
//! The judge NEVER forwards R_EA,i to the voter (a transferable R_EA,i would
//! be a receipt), and its detailed report is judge-private.

use crate::crypto::encryption::EncOpening;
use crate::crypto::hash::{ct_commit, sig_msg_hash};
use crate::crypto::shamir::Share;
use crate::crypto::signature::verify;
use crate::disputes::judge::{JudgeReport, Verdict};
use crate::protocol::bulletin_board::AdmittedBoard;
use crate::protocol::filter_and_tally::{registration_check, RegistrationCheck};
use crate::protocol::preprocessing::RegistrationState;
use crate::types::{BallotPlaintext, F, InternalBallotStatus, PublicParams, PLAINTEXT_FIELD_LEN};

/// How the judge obtains R_EA,i.
#[derive(Debug, Clone)]
pub enum NonceSource {
    /// Directly from the (single) election authority.
    Direct(F),
    /// Reconstructed from >= t threshold authority shares.
    ThresholdShares(Vec<Share>),
}

/// A voter's tallied-as-recorded complaint, delivered privately to the
/// judge: the admitted commitment plus the voter's claimed opening
/// (opening fields + r_com), which the judge checks against `com`.
/// ADMISSION-PATH INDEPENDENT: only the commitment matters.
#[derive(Debug, Clone)]
pub struct TalliedAsRecordedComplaint {
    pub com: crate::types::F,
    pub opening: EncOpening,
}

/// Outcome of checking the public tally proof, as established by the judge.
/// A proof only counts as `Verified` if it cryptographically verifies AND its
/// public inputs are the current public statement — a proof for some other
/// statement proves nothing about this tally.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TallyProofStatus {
    /// Proof verifies against the current public statement.
    Verified,
    /// A proof was checked and it does not verify (or it is bound to a
    /// different statement than the current public one).
    Invalid,
    /// No proof (or no verifier) was available; nothing was checked.
    Unavailable,
}

/// Evidence the judge obtains from the authority side.
pub struct AuthorityEvidence<'a> {
    pub nonce_source: NonceSource,
    /// Internal evaluations of the ballots preceding the complained ballot
    /// on the board (judge-private; needed for duplicate adjudication).
    pub prior_evaluations: &'a [crate::types::InternalBallotEvaluation],
    /// Status of the public tally proof check.
    pub tally_proof: TallyProofStatus,
}

/// Adjudicate a tallied-as-recorded complaint.
pub fn judge_tallied_as_recorded(
    pp: &PublicParams,
    registration_state: &RegistrationState,
    admitted: &AdmittedBoard,
    complaint: &TalliedAsRecordedComplaint,
    evidence: &AuthorityEvidence<'_>,
) -> JudgeReport {
    // (0) the complaint presumes the commitment was admitted.
    let Some(board_index) = admitted.coms.iter().position(|c| *c == complaint.com) else {
        return JudgeReport::new(
            Verdict::Undetermined,
            "commitment is not on the admitted board; file a recorded-as-cast dispute instead",
        );
    };

    // (1) the claimed opening opens the ballot commitment.
    if complaint.opening.plaintext_fields.len() != PLAINTEXT_FIELD_LEN {
        return JudgeReport::new(Verdict::VoterFaulty, "malformed opening");
    }
    let mut fields = [F::from(0u64); PLAINTEXT_FIELD_LEN];
    fields.copy_from_slice(&complaint.opening.plaintext_fields);
    if ct_commit(&fields, complaint.opening.rho) != complaint.com {
        return JudgeReport::new(
            Verdict::VoterFaulty,
            "claimed opening does not open the ballot commitment",
        );
    }
    let pt = match BallotPlaintext::from_fields(&complaint.opening.plaintext_fields) {
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

    // (3-5) the SAME deterministic indexed-registration predicate the tally
    // relation uses (protocol::filter_and_tally::registration_check): the
    // claimed id selects row Reg[id]; vk equality; hidden nonce relation;
    // leaf/root consistency. R_EA,i is judge-private (direct from the
    // logical EA or reconstructed from >= t threshold shares) and is used
    // only inside this check — it never appears in the report.
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
    match registration_check(pp, registration_state, &pt, r_ea) {
        RegistrationCheck::Ok => {}
        RegistrationCheck::NotRegistered => {
            return JudgeReport::new(Verdict::VoterFaulty, "voter id not a registered row");
        }
        RegistrationCheck::VkMismatch => {
            return JudgeReport::new(Verdict::VoterFaulty, "vk does not match registration row");
        }
        RegistrationCheck::NonceMismatch => {
            // The registered commitment does not open to the voter's claimed
            // R: the voter presented a fake nonce (this is exactly the
            // PRIVATE detection of a fake-compliance ballot). The verdict is
            // voter-fault / no-authority-fault; neither R_EA,i nor any
            // validity label leaves the judge.
            return JudgeReport::new(
                Verdict::VoterFaulty,
                "hidden nonce relation fails: claimed R is not the registered nonce",
            );
        }
        RegistrationCheck::LeafInconsistent => {
            // The nonce relation holds against the public h, but the indexed
            // row is inconsistent with the Merkle root: authority-side fault.
            return JudgeReport::new(
                Verdict::AuthorityFaulty,
                "registration leaf inconsistent with the published root",
            );
        }
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

    // (7) the ballot is valid and first: it must have been counted. Whether
    // it actually was rests entirely on the tally proof, so an unchecked
    // proof must NOT be assumed valid.
    match evidence.tally_proof {
        TallyProofStatus::Invalid => JudgeReport::new(
            Verdict::AuthorityFaulty,
            "valid first ballot, and the public tally proof does not verify",
        ),
        TallyProofStatus::Unavailable => JudgeReport::new(
            Verdict::Undetermined,
            "valid first ballot, but no tally proof was checked against the current \
             statement; cannot conclude the ballot was counted",
        ),
        TallyProofStatus::Verified => JudgeReport::new(
            Verdict::NoAuthorityFault,
            "valid first ballot and a verifying tally proof: under proof soundness the ballot \
             was counted; no authority fault",
        ),
    }
}
