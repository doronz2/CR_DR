//! Exact FilterAndTally.
//!
//! CRITICAL INVARIANT: duplicate handling is applied ONLY AFTER a ballot has
//! passed every validity check. Invalid ballots (fake-compliance, chaff,
//! garbage) never consume the voter's slot, so a fake ballot appearing
//! before the real one cannot block it.
//!
//! Stage structure (mirrors the ZK relation):
//!   per board slot: open/decrypt -> parse -> eid/candidate/signature ->
//!   INDEXED registration-row check (the claimed id selects row Reg[id];
//!   vk equality; hidden nonce relation h = H_com(eid,id,vk,R,R_EA)) ->
//!   emit record r_j = (valid_j, id_j, pos_j, m_j);
//!   then: sorted-record duplicate resolution (Strategy B) -> tally.

use crate::crypto::hash::{ct_commit, h_com, h_reg, sig_msg_hash};
use crate::crypto::merkle::verify_path;
use crate::crypto::signature::verify;
use crate::errors::{CrDrError, Result};
use crate::protocol::admission::AdmittedOpenings;
use crate::protocol::bulletin_board::AdmittedBoard;
use crate::protocol::duplicates::{counted_flags_sorted, BallotRecord};
use crate::protocol::preprocessing::RegistrationState;
use crate::types::{
    AuthoritySecretState, BallotPlaintext, DuplicateRule, InternalBallotEvaluation,
    InternalBallotStatus, Nonce, PublicParams, TallyResult, F, PLAINTEXT_FIELD_LEN,
};

/// The tally pipeline is ADMISSION-PATH INDEPENDENT: it consumes the
/// admitted board BB_adm = [com_1..com_M] plus the EA-private openings
/// store (filled by Path-1 decryption of ct_open, or by Path-2 private
/// submissions — protocol::admission). The opening of every admitted
/// commitment MUST open it: both admission paths guarantee this, and the
/// tally circuit HARD-opens com, so a non-opening entry is a hard error
/// here, never a soft-invalid ballot.
pub fn opening_checked(
    admitted: &AdmittedBoard,
    openings: &AdmittedOpenings,
    j: usize,
) -> Result<([F; PLAINTEXT_FIELD_LEN], F)> {
    let com = admitted
        .coms
        .get(j)
        .ok_or_else(|| CrDrError::Crypto(format!("admitted index {j} out of range")))?;
    let opening = openings
        .openings
        .get(j)
        .ok_or_else(|| CrDrError::Crypto(format!("no opening for admitted index {j}")))?;
    if opening.plaintext_fields.len() != PLAINTEXT_FIELD_LEN {
        return Err(CrDrError::Crypto("malformed opening in EA store".into()));
    }
    let mut pt = [F::from(0u64); PLAINTEXT_FIELD_LEN];
    pt.copy_from_slice(&opening.plaintext_fields);
    if ct_commit(&pt, opening.rho) != *com {
        return Err(CrDrError::Crypto(
            "stored opening does not open the admitted commitment — admission is a \
             precondition for tallying"
                .into(),
        ));
    }
    Ok((pt, opening.rho))
}

/// Outcome of the deterministic INDEXED registration check for a parsed
/// plaintext, given the (judge- or quorum-provided) authority nonce.
/// Shared by FilterAndTally and the dispute judge so both apply the exact
/// same validity predicate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistrationCheck {
    Ok,
    /// id is not a registered row index (out of range 0..N).
    NotRegistered,
    /// Row Reg[id] exists but its vk differs from the ballot's.
    VkMismatch,
    /// vk matches but h != H_com(eid, id, vk, R, R_EA): the claimed R is not
    /// the registered voter nonce (fake-compliance / chaff signature nonce).
    NonceMismatch,
    /// The nonce relation holds against the public h, but the row's leaf or
    /// Merkle path is inconsistent with the published root — an
    /// authority-side registration fault, not a voter fault.
    LeafInconsistent,
}

/// The deterministic indexed-registration validity predicate: fetch row
/// Reg[pt.id] (the identity determines the row — no prover choice), check
/// vk equality, the hidden nonce relation, and leaf/root consistency.
pub fn registration_check(
    pp: &PublicParams,
    registration_state: &RegistrationState,
    pt: &BallotPlaintext,
    r_ea: Nonce,
) -> RegistrationCheck {
    let num_voters = registration_state.num_voters() as u64;
    if pt.id >= num_voters {
        return RegistrationCheck::NotRegistered;
    }
    let Some(record) = registration_state.record(pt.id) else {
        return RegistrationCheck::NotRegistered;
    };
    if record.vk != pt.vk {
        return RegistrationCheck::VkMismatch;
    }
    let h = h_com(pt.eid_hash, pt.id, &pt.vk, pt.r, r_ea);
    if h != record.h {
        return RegistrationCheck::NonceMismatch;
    }
    let leaf = h_reg(pp.eid_hash, pt.id, &record.vk, record.h);
    let path_ok = registration_state
        .paths
        .get(&pt.id)
        .map(|path| verify_path(registration_state.root, leaf, path))
        .unwrap_or(false);
    if !path_ok || leaf != record.leaf {
        return RegistrationCheck::LeafInconsistent;
    }
    RegistrationCheck::Ok
}

/// Run FilterAndTally over the public bulletin-board order.
///
/// Returns the public `TallyResult` and an internal per-ballot evaluation log
/// that is for TESTS/DEBUG ONLY and must never be published (it reveals
/// which ballots were counted, voter identities and rejection reasons).
pub fn filter_and_tally(
    pp: &PublicParams,
    authority_secret: &AuthoritySecretState,
    registration_state: &RegistrationState,
    admitted: &AdmittedBoard,
    openings: &AdmittedOpenings,
) -> Result<(TallyResult, Vec<InternalBallotEvaluation>)> {
    if admitted.len() != openings.openings.len() {
        return Err(CrDrError::Crypto(format!(
            "admitted board has {} commitments but the EA store has {} openings",
            admitted.len(),
            openings.openings.len()
        )));
    }
    // Stage 1: per-ballot validity (no duplicate handling here).
    let mut statuses = Vec::with_capacity(admitted.len());
    let mut records = Vec::with_capacity(admitted.len());
    for pos in 0..admitted.len() {
        let (status, voter_id, candidate, cand_pos) =
            evaluate_ballot_validity(pp, authority_secret, registration_state, admitted, openings, pos)?;
        let valid = status == BallotValidity::Valid;
        records.push(BallotRecord {
            valid,
            id: if valid { voter_id.unwrap_or(0) } else { 0 },
            pos: pos as u64,
            cand_index: if valid { cand_pos.unwrap_or(0) as u64 } else { 0 },
        });
        statuses.push((status, voter_id, candidate, cand_pos));
    }

    // Stage 2: duplicates AFTER validity — sorted-record Strategy B.
    let counted = match pp.duplicate_rule {
        DuplicateRule::FirstValidCounts => counted_flags_sorted(&records),
    };

    // Stage 3: tally accumulation + internal log.
    let mut counts = vec![0u64; pp.candidates.len()];
    let mut counted_ballots = 0u64;
    let mut evaluations = Vec::with_capacity(admitted.len());
    for (j, ((status, voter_id, candidate, cand_pos), record)) in
        statuses.into_iter().zip(&records).enumerate()
    {
        let final_status = match status {
            BallotValidity::Valid if counted[j] => {
                counts[cand_pos.expect("valid ballot has candidate")] += 1;
                counted_ballots += 1;
                InternalBallotStatus::Counted
            }
            BallotValidity::Valid => InternalBallotStatus::DuplicateValidBallot,
            BallotValidity::Invalid(s) => s,
        };
        debug_assert_eq!(record.pos as usize, j);
        evaluations.push(InternalBallotEvaluation {
            ballot_index: j,
            status: final_status,
            voter_id,
            candidate,
        });
    }

    Ok((TallyResult { counts, counted_ballots }, evaluations))
}

/// Judge-side mirror of the validity predicate for ONE claimed identity:
/// is the opening at `pos` a VALID ballot claiming voter `id`, under the
/// given authorized nonce for that id? Prior ballots claiming other
/// identities are irrelevant to the duplicate rule and return false.
/// Mirrors `evaluate_ballot_validity` stage by stage (eid binding,
/// candidate set, signature, indexed registration + hidden nonce).
/// Hard-errors when the supplied opening does not open the admitted
/// commitment — that is an authority-evidence inconsistency, never a
/// property of the ballot.
pub fn ballot_is_valid_for_id(
    pp: &PublicParams,
    registration_state: &RegistrationState,
    admitted: &AdmittedBoard,
    openings: &AdmittedOpenings,
    pos: usize,
    id: u64,
    r_ea: crate::types::F,
) -> Result<bool> {
    let (pt_fields, _r_com) = opening_checked(admitted, openings, pos)?;
    let Ok(pt) = BallotPlaintext::from_fields(&pt_fields) else {
        return Ok(false);
    };
    if pt.id != id || pt.eid_hash != pp.eid_hash {
        return Ok(false);
    }
    if !pp.candidates.contains(&pt.candidate) {
        return Ok(false);
    }
    let msg = sig_msg_hash(pt.eid_hash, pt.id, pt.candidate, pt.r);
    if !verify(&pt.vk, msg, &pt.sigma) {
        return Ok(false);
    }
    Ok(registration_check(pp, registration_state, &pt, r_ea) == RegistrationCheck::Ok)
}

/// Validity verdict of a single ballot, before duplicate handling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BallotValidity {
    Valid,
    Invalid(InternalBallotStatus),
}

type ValidityOutcome = (BallotValidity, Option<u64>, Option<u64>, Option<usize>);

/// Stages (a)-(h): everything except duplicates. Returns the verdict plus
/// (voter_id, candidate, candidate index) when parseable. Decryption
/// failure is a hard error (see `decrypt_entry`).
fn evaluate_ballot_validity(
    pp: &PublicParams,
    authority_secret: &AuthoritySecretState,
    registration_state: &RegistrationState,
    admitted: &AdmittedBoard,
    openings: &AdmittedOpenings,
    pos: usize,
) -> Result<ValidityOutcome> {
    use BallotValidity::Invalid;

    // (a) the admitted commitment's opening (hard on inconsistency)
    let (pt_fields, _r_com) = opening_checked(admitted, openings, pos)?;

    // (b) parse plaintext
    let pt: BallotPlaintext = match BallotPlaintext::from_fields(&pt_fields) {
        Ok(p) => p,
        Err(_) => return Ok((Invalid(InternalBallotStatus::InvalidFormat), None, None, None)),
    };
    let ids = (Some(pt.id), Some(pt.candidate));

    // (c) election id binding
    if pt.eid_hash != pp.eid_hash {
        return Ok((Invalid(InternalBallotStatus::InvalidFormat), ids.0, ids.1, None));
    }

    // (d) candidate in C
    let Some(cand_pos) = pp.candidates.iter().position(|c| *c == pt.candidate) else {
        return Ok((Invalid(InternalBallotStatus::InvalidCandidate), ids.0, ids.1, None));
    };

    // (e) signature over (eid_hash, id, candidate, R)
    let msg = sig_msg_hash(pt.eid_hash, pt.id, pt.candidate, pt.r);
    if !verify(&pt.vk, msg, &pt.sigma) {
        return Ok((
            Invalid(InternalBallotStatus::InvalidSignature),
            ids.0,
            ids.1,
            Some(cand_pos),
        ));
    }

    // (f)-(h) indexed registration row + hidden nonce relation. The
    // authority nonce comes from an AUTHORIZED >= t reconstruction (the
    // logical-EA quorum); unregistered ids have no nonce and fail as such.
    let reg = match authority_secret.r_ea(pt.id) {
        Ok(r_ea) => registration_check(pp, registration_state, &pt, r_ea),
        Err(_) => RegistrationCheck::NotRegistered,
    };
    if reg != RegistrationCheck::Ok {
        return Ok((
            Invalid(InternalBallotStatus::InvalidRegistration),
            ids.0,
            ids.1,
            Some(cand_pos),
        ));
    }

    // (i) ballot is VALID; duplicates are the caller's stage.
    Ok((BallotValidity::Valid, ids.0, ids.1, Some(cand_pos)))
}
