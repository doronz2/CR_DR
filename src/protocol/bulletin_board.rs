//! Boards and the (modeled) anonymous channel.
//!
//! TWO boards, one tally input:
//!
//! * `BulletinBoard` (**BB_raw**) — raw public submissions for the PUBLIC
//!   CAST-ZK admission path only: entries B_j = (com_j, ct_open_j) with
//!   their pi_cast proofs. Fully public.
//! * [`AdmittedBoard`] (**BB_adm**) — the admitted commitment list
//!   [com_1..com_M]. THE input of the exact tally proof, whichever
//!   admission path produced it: Path 1 (BB_adm = Clean(BB_raw), keep
//!   entries with valid pi_cast — `protocol::admission::clean`) or Path 2
//!   (EA-mediated private submission with signed receipts —
//!   `protocol::admission::ea_admit_private`). The paths are NEVER mixed
//!   implicitly.
//!
//! The anonymous channel hides sender identity in the model and preserves
//! exact ballot bytes, so recorded-as-cast checking on BB_raw is exact
//! byte matching (bytes derived from the posted entry, never stored).

use rand::{CryptoRng, Rng, RngCore};

use crate::types::{fserde_vec, F, PublicBallot};

#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct BulletinBoard {
    entries: Vec<PublicBallot>,
}

impl BulletinBoard {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn append(&mut self, ballot: PublicBallot) {
        self.entries.push(ballot);
    }

    /// Public, ordered list of posted ballots.
    pub fn list_public_ballots(&self) -> &[PublicBallot] {
        &self.entries
    }

    /// Exact-byte membership test over the public ballot bytes.
    pub fn contains_exact_bytes(&self, ballot_bytes: &[u8]) -> bool {
        self.entries.iter().any(|b| b.bytes() == ballot_bytes)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// BB_adm: the admitted commitment list the tally proof processes. The
/// statement's bb_commitment is the Poseidon chain over exactly these
/// commitments; every com is hard-opened inside the tally circuit.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AdmittedBoard {
    #[serde(with = "fserde_vec")]
    pub coms: Vec<F>,
}

impl AdmittedBoard {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.coms.len()
    }

    pub fn is_empty(&self) -> bool {
        self.coms.is_empty()
    }

    /// Membership of a commitment (recorded-as-cast, Path 2 receipts).
    pub fn contains(&self, com: &F) -> bool {
        self.coms.contains(com)
    }
}

/// A Path-1 raw submission: the public entry plus its cast proof (entries
/// without a valid pi_cast are dropped by Clean and never admitted).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RawSubmission {
    pub entry: PublicBallot,
    pub pi_cast: Option<crate::zk::cast::CastProof>,
}

/// Modeled anonymous submission channel: collects raw submissions and
/// releases them in a random order with sender identities dropped. Entry
/// bytes are preserved verbatim.
#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct AnonymousChannel {
    pending: Vec<RawSubmission>,
}

impl AnonymousChannel {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn submit(&mut self, ballot: PublicBallot) {
        self.pending.push(RawSubmission { entry: ballot, pi_cast: None });
    }

    pub fn submit_with_proof(&mut self, ballot: PublicBallot, pi_cast: crate::zk::cast::CastProof) {
        self.pending.push(RawSubmission { entry: ballot, pi_cast: Some(pi_cast) });
    }

    /// Release all pending submissions in a fresh random order.
    pub fn flush_shuffled<R: RngCore + CryptoRng>(&mut self, rng: &mut R) -> Vec<RawSubmission> {
        let mut out = std::mem::take(&mut self.pending);
        // Fisher–Yates
        for i in (1..out.len()).rev() {
            let j = rng.gen_range(0..=i);
            out.swap(i, j);
        }
        out
    }
}
