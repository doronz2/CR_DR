//! Ballot ADMISSION: how commitments get onto the admitted board BB_adm
//! that the exact tally proof processes. Two paths, never mixed implicitly:
//!
//! ## Path 1 — public anonymous cast-ZK
//!
//! Voters post raw entries B = (com, ct_open, pi_cast) anonymously
//! (BB_raw). ANYONE recomputes BB_adm = Clean(BB_raw): keep exactly the
//! entries whose pi_cast verifies (`clean`). pi_cast attests casting
//! well-formedness ONLY (com and ct_open open to the same data) — never
//! hidden validity, authority nonces, counted status or duplicates — so
//! fake-compliance and chaff entries pass admission and remain in BB_adm;
//! they are rejected only later inside the private tally relation. The EA
//! obtains the tally openings by decrypting each admitted entry's ct_open
//! (`ea_open_admitted`).
//!
//! ## Path 2 — EA-mediated private submission
//!
//! The voter privately sends (com, opening, r_com) to the EA. The EA
//! checks ONLY admission-level consistency — com = H_ballot_com(opening,
//! r_com) — and returns receipt = Sign_EA(eid, com, timestamp). The
//! receipt certifies SUBMISSION/ADMISSION only: never hidden validity,
//! counted status, nonce correctness or candidate validity. In particular
//! a fake-nonce ballot receives exactly the same kind of receipt as a real
//! one (otherwise the receipt would be a coercion test). The EA later
//! posts BB_adm; recorded-as-cast disputes use the receipt
//! (`disputes::recorded_as_cast::adjudicate_admission_receipt`).
//!
//! Either way the tally pipeline downstream is identical: it consumes
//! (BB_adm, AdmittedOpenings) and hard-opens every commitment.

use crate::crypto::encryption::{cast_decrypt, EncOpening};
use crate::crypto::hash::ct_commit;
use crate::errors::{CrDrError, Result};
use crate::protocol::bulletin_board::{AdmittedBoard, BulletinBoard};
use crate::types::{AuthoritySecretState, Ballot, F, PLAINTEXT_FIELD_LEN, PublicBallot};
use crate::zk::cast::CastProof;

/// EA-PRIVATE openings of the admitted commitments, aligned with BB_adm:
/// `openings[j]` opens `admitted.coms[j]`. Path 1 fills this by decrypting
/// ct_open; Path 2 by storing the privately submitted openings. Never
/// published.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct AdmittedOpenings {
    pub openings: Vec<EncOpening>,
}

fn opening_opens(com: &F, opening: &EncOpening) -> bool {
    if opening.plaintext_fields.len() != PLAINTEXT_FIELD_LEN {
        return false;
    }
    let mut pt = [F::from(0u64); PLAINTEXT_FIELD_LEN];
    pt.copy_from_slice(&opening.plaintext_fields);
    ct_commit(&pt, opening.rho) == *com
}

// ---------------------------------------------------------------------------
// Path 1 — public anonymous cast-ZK
// ---------------------------------------------------------------------------

/// PUBLIC cleaning: BB_adm = Clean(BB_raw). Keeps exactly the entries whose
/// pi_cast verifies under `verify` (typically
/// `zk::cast::verify_cast_entry`); entries without a proof are dropped.
/// Returns the admitted board and the raw-board index of every admitted
/// entry (so the EA can decrypt the matching ct_opens).
pub fn clean<Fv>(
    raw: &BulletinBoard,
    proofs: &[Option<CastProof>],
    mut verify: Fv,
) -> Result<(AdmittedBoard, Vec<usize>)>
where
    Fv: FnMut(&PublicBallot, &CastProof) -> Result<bool>,
{
    if proofs.len() != raw.len() {
        return Err(CrDrError::Crypto(format!(
            "raw board has {} entries but {} proofs",
            raw.len(),
            proofs.len()
        )));
    }
    let mut admitted = AdmittedBoard::new();
    let mut indices = Vec::new();
    for (i, (entry, proof)) in raw.list_public_ballots().iter().zip(proofs).enumerate() {
        let ok = match proof {
            Some(p) => verify(entry, p)?,
            None => false,
        };
        if ok {
            admitted.coms.push(entry.com);
            indices.push(i);
        }
    }
    Ok((admitted, indices))
}

/// Path-1 EA step: decrypt the admitted entries' ct_opens into the
/// EA-private openings store. Fails on an undecryptable/inconsistent entry
/// (impossible when Clean verified its pi_cast).
pub fn ea_open_admitted(
    authority_secret: &AuthoritySecretState,
    raw: &BulletinBoard,
    admitted_indices: &[usize],
) -> Result<AdmittedOpenings> {
    let entries = raw.list_public_ballots();
    let mut openings = Vec::with_capacity(admitted_indices.len());
    for &i in admitted_indices {
        let entry = entries
            .get(i)
            .ok_or_else(|| CrDrError::Crypto(format!("admitted index {i} out of range")))?;
        let fields = cast_decrypt(&authority_secret.sk_ea, &entry.ct_open)?;
        let opening = EncOpening {
            plaintext_fields: fields[..PLAINTEXT_FIELD_LEN].to_vec(),
            rho: fields[PLAINTEXT_FIELD_LEN],
        };
        if !opening_opens(&entry.com, &opening) {
            return Err(CrDrError::Crypto(
                "decrypted opening does not open com — pi_cast verification is a \
                 precondition for admission"
                    .into(),
            ));
        }
        openings.push(opening);
    }
    Ok(AdmittedOpenings { openings })
}

// ---------------------------------------------------------------------------
// Path 2 — EA-mediated private submission
// ---------------------------------------------------------------------------

/// The EA's Path-2 admission state: the (eventually posted) admitted board
/// plus the EA-private openings. Coms become public when the EA posts
/// BB_adm; openings never do.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct EaAdmissionState {
    pub admitted: AdmittedBoard,
    pub openings: AdmittedOpenings,
}

/// Path-2 admission: the voter privately submits (com, opening, r_com).
/// The EA checks ONLY that the opening opens com — no hidden-nonce check,
/// no registration check, no candidate policy beyond what is stated here —
/// appends com to its admission state and returns
/// receipt = Sign_EA(eid, com, timestamp). Fake-nonce ballots receive
/// exactly the same receipt as real ones (coercion-resistance condition).
pub fn ea_admit_private<R: rand::RngCore + rand::CryptoRng>(
    pp: &crate::types::PublicParams,
    authority_secret: &AuthoritySecretState,
    state: &mut EaAdmissionState,
    com: F,
    opening: EncOpening,
    timestamp: u64,
    rng: &mut R,
) -> Result<crate::disputes::recorded_as_cast::SubmissionReceipt> {
    if !opening_opens(&com, &opening) {
        return Err(CrDrError::Crypto(
            "submission rejected: opening does not open com (admission-level check)".into(),
        ));
    }
    state.admitted.coms.push(com);
    state.openings.openings.push(opening);
    Ok(crate::disputes::recorded_as_cast::ea_issue_admission_receipt(
        pp,
        authority_secret,
        com,
        timestamp,
        rng,
    ))
}

// ---------------------------------------------------------------------------
// Test/bench helper (path-agnostic)
// ---------------------------------------------------------------------------

/// Build (BB_adm, openings) directly from voter-side ballots — models an
/// already-cleaned/admitted board for tests and benchmarks that do not
/// exercise an admission path themselves. NOT a protocol operation.
pub fn admitted_from_ballots(ballots: &[Ballot]) -> (AdmittedBoard, AdmittedOpenings) {
    let admitted = AdmittedBoard {
        coms: ballots.iter().map(|b| b.com).collect(),
    };
    let openings = AdmittedOpenings {
        openings: ballots.iter().map(|b| b.secret.opening.clone()).collect(),
    };
    (admitted, openings)
}
