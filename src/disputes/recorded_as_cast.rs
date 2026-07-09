//! Recorded-as-cast dispute resolution, per admission path.
//!
//! **Path 1 (public cast-ZK)**: the anonymous channel preserves exact
//! ballot bytes, so a voter privately checks BB_raw membership by exact
//! byte matching (`check_direct`), and — since BB_adm = Clean(BB_raw) is
//! publicly recomputable — admission of a raw entry is publicly checkable
//! too. The voter must NOT expose which entry matched (that would identify
//! the real ballot to a coercer); the check is local and optional.
//!
//! **Path 2 (EA-mediated)**: on private submission the EA issues
//! receipt = Sign_EA(eid, com, timestamp). The receipt certifies
//! SUBMISSION/ADMISSION ONLY — never hidden validity, counted status,
//! nonce correctness or candidate validity — so fake-nonce ballots carry
//! receipts indistinguishable from real ones. If com is later absent from
//! the posted BB_adm, the receipt is evidence against the authority (the
//! EA is the poster in this model), adjudicated by
//! `adjudicate_admission_receipt`.

use crate::crypto::poseidon_native::poseidon;
use crate::crypto::signature::{sign, verify, Signature};
use crate::disputes::judge::{JudgeReport, Verdict};
use crate::protocol::bulletin_board::{AdmittedBoard, BulletinBoard};
use crate::types::{AuthoritySecretState, F, PublicParams};

/// Direct recorded-as-cast check (Path 1): exact entry bytes on BB_raw.
pub fn check_direct(bb: &BulletinBoard, ballot_bytes: &[u8]) -> bool {
    bb.contains_exact_bytes(ballot_bytes)
}

/// EA admission receipt (Path 2): Sign_EA(eid_hash, com, timestamp).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SubmissionReceipt {
    #[serde(with = "crate::types::fserde")]
    pub eid_hash: F,
    #[serde(with = "crate::types::fserde")]
    pub com: F,
    pub timestamp: u64,
    pub sig: Signature,
}

fn receipt_msg(eid_hash: F, com: F, timestamp: u64) -> F {
    poseidon(&[eid_hash, com, F::from(timestamp)])
}

/// EA issues an admission receipt for a commitment it admitted (Path 2).
/// Called from `protocol::admission::ea_admit_private` AFTER the
/// admission-level check (com opens) — and only that check: the receipt
/// must certify nothing about hidden validity.
pub fn ea_issue_admission_receipt<R: rand::RngCore + rand::CryptoRng>(
    pp: &PublicParams,
    authority_secret: &AuthoritySecretState,
    com: F,
    timestamp: u64,
    rng: &mut R,
) -> SubmissionReceipt {
    let msg = receipt_msg(pp.eid_hash, com, timestamp);
    SubmissionReceipt {
        eid_hash: pp.eid_hash,
        com,
        timestamp,
        sig: sign(&authority_secret.receipt_sk, msg, rng),
    }
}

/// Verify an EA receipt signature.
pub fn verify_receipt(pp: &PublicParams, receipt: &SubmissionReceipt) -> bool {
    let msg = receipt_msg(receipt.eid_hash, receipt.com, receipt.timestamp);
    receipt.eid_hash == pp.eid_hash && verify(&pp.ea_receipt_vk, msg, &receipt.sig)
}

/// Path-2 recorded-as-cast adjudication: the voter holds a receipt for
/// `com`; the judge checks the posted BB_adm. In this posting model the EA
/// posts BB_adm itself, so an admitted-but-unposted commitment is an
/// AUTHORITY fault (with a board operated by a distinct party it would be
/// BoardFaulty).
pub fn adjudicate_admission_receipt(
    pp: &PublicParams,
    admitted: &AdmittedBoard,
    receipt: &SubmissionReceipt,
) -> JudgeReport {
    if !verify_receipt(pp, receipt) {
        return JudgeReport::new(Verdict::VoterFaulty, "invalid EA receipt");
    }
    if admitted.contains(&receipt.com) {
        return JudgeReport::new(
            Verdict::VoterFaulty,
            "receipted commitment is on the admitted board; complaint unfounded",
        );
    }
    JudgeReport::new(
        Verdict::AuthorityFaulty,
        "EA receipted this commitment but did not post it to the admitted board",
    )
}

/// Path-1 recorded-as-cast adjudication over the RAW board: without a
/// receipt (Path 1 has none), absence of the exact entry bytes is not by
/// itself attributable — the channel model carries no acknowledgments.
pub fn adjudicate_recorded_as_cast(
    _pp: &PublicParams,
    bb: &BulletinBoard,
    ballot_bytes: &[u8],
) -> JudgeReport {
    if bb.contains_exact_bytes(ballot_bytes) {
        return JudgeReport::new(
            Verdict::VoterFaulty,
            "entry bytes are present on the raw board; complaint unfounded",
        );
    }
    JudgeReport::new(
        Verdict::Undetermined,
        "entry absent and no admission receipt exists on this path; no evidence either way",
    )
}
