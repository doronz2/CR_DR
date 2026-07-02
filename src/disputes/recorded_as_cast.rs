//! Recorded-as-cast dispute resolution.
//!
//! Direct mode: the anonymous channel preserves exact ballot bytes, so a
//! voter privately checks BB membership by exact byte matching. The voter
//! must NOT expose which ballot matched (that would identify the real
//! ballot to a coercer); the check is local and optional.
//!
//! Authority-mediated mode: on submission the EA issues a receipt
//! Sign_EA(eid, ballot_hash, timestamp). If the ballot later fails to appear
//! on the board, the receipt is evidence against board/authority.

use crate::crypto::hash::{ballot_hash, sig_msg_hash};
use crate::crypto::poseidon_native::poseidon;
use crate::crypto::signature::{sign, verify, Signature};
use crate::disputes::judge::{JudgeReport, Verdict};
use crate::protocol::bulletin_board::BulletinBoard;
use crate::types::{AuthoritySecretState, Ballot, F, PublicParams};

/// Direct recorded-as-cast check: exact ciphertext bytes present on BB.
pub fn check_direct(bb: &BulletinBoard, ballot_bytes: &[u8]) -> bool {
    bb.contains_exact_bytes(ballot_bytes)
}

/// EA submission receipt: Sign_EA(eid_hash, ballot_hash, timestamp).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SubmissionReceipt {
    #[serde(with = "crate::types::fserde")]
    pub eid_hash: F,
    #[serde(with = "crate::types::fserde")]
    pub ballot_hash: F,
    pub timestamp: u64,
    pub sig: Signature,
}

fn receipt_msg(eid_hash: F, bh: F, timestamp: u64) -> F {
    poseidon(&[eid_hash, bh, F::from(timestamp)])
}

/// EA issues a submission receipt for a ballot it accepted for posting.
pub fn ea_issue_receipt<R: rand::RngCore + rand::CryptoRng>(
    pp: &PublicParams,
    authority_secret: &AuthoritySecretState,
    ballot: &Ballot,
    timestamp: u64,
    rng: &mut R,
) -> SubmissionReceipt {
    let bh = ballot_hash(&ballot.ciphertext.fields);
    let msg = receipt_msg(pp.eid_hash, bh, timestamp);
    SubmissionReceipt {
        eid_hash: pp.eid_hash,
        ballot_hash: bh,
        timestamp,
        sig: sign(&authority_secret.receipt_sk, msg, rng),
    }
}

/// Verify an EA receipt signature.
pub fn verify_receipt(pp: &PublicParams, receipt: &SubmissionReceipt) -> bool {
    let msg = receipt_msg(receipt.eid_hash, receipt.ballot_hash, receipt.timestamp);
    receipt.eid_hash == pp.eid_hash && verify(&pp.ea_receipt_vk, msg, &receipt.sig)
}

/// Judge adjudication of a recorded-as-cast complaint.
pub fn adjudicate_recorded_as_cast(
    pp: &PublicParams,
    bb: &BulletinBoard,
    ballot: &Ballot,
    receipt: Option<&SubmissionReceipt>,
) -> JudgeReport {
    if bb.contains_exact_bytes(&ballot.bytes) {
        return JudgeReport::new(
            Verdict::VoterFaulty,
            "ballot bytes are present on the board; complaint unfounded",
        );
    }
    match receipt {
        Some(rc) => {
            if !verify_receipt(pp, rc) {
                return JudgeReport::new(Verdict::VoterFaulty, "invalid EA receipt");
            }
            if rc.ballot_hash != ballot_hash(&ballot.ciphertext.fields) {
                return JudgeReport::new(
                    Verdict::VoterFaulty,
                    "receipt does not match the claimed ballot",
                );
            }
            JudgeReport::new(
                Verdict::BoardFaulty,
                "EA acknowledged submission but ballot bytes are missing from the board",
            )
        }
        None => JudgeReport::new(
            Verdict::Undetermined,
            "ballot absent and no submission receipt; no evidence either way",
        ),
    }
}

// Re-export used by tests for constructing receipt messages.
pub use crate::crypto::hash::ballot_hash as public_ballot_hash;

#[allow(unused)]
fn _receipt_msg_shape_note() {
    // The receipt message intentionally reuses the arity-3 Poseidon; the
    // signature message hash for ballots uses arity 4 (sig_msg_hash), so the
    // two domains cannot collide.
    let _ = sig_msg_hash;
}
