//! Append-only public bulletin board and the (modeled) anonymous channel.
//!
//! The anonymous channel hides sender identity in the model and preserves
//! exact ballot bytes, so recorded-as-cast checking is exact byte matching.

use rand::{CryptoRng, Rng, RngCore};

use crate::types::Ballot;

#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct BulletinBoard {
    entries: Vec<Ballot>,
}

impl BulletinBoard {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn append(&mut self, ballot: Ballot) {
        self.entries.push(ballot);
    }

    /// Public, ordered list of posted ballots.
    pub fn list_public_ballots(&self) -> &[Ballot] {
        &self.entries
    }

    /// Exact-byte membership test over the public ballot bytes.
    pub fn contains_exact_bytes(&self, ballot_bytes: &[u8]) -> bool {
        self.entries.iter().any(|b| b.bytes == ballot_bytes)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Modeled anonymous submission channel: collects ballots and releases them
/// in a random order with sender identities dropped. Ballot bytes are
/// preserved verbatim.
#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct AnonymousChannel {
    pending: Vec<Ballot>,
}

impl AnonymousChannel {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn submit(&mut self, ballot: Ballot) {
        self.pending.push(ballot);
    }

    /// Release all pending ballots in a fresh random order.
    pub fn flush_shuffled<R: RngCore + CryptoRng>(&mut self, rng: &mut R) -> Vec<Ballot> {
        let mut out = std::mem::take(&mut self.pending);
        // Fisher–Yates
        for i in (1..out.len()).rev() {
            let j = rng.gen_range(0..=i);
            out.swap(i, j);
        }
        out
    }
}
