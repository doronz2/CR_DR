//! Private judge verdicts.
//!
//! IMPORTANT LEAKAGE NOTE: detailed judge verdicts are NOT part of the
//! coercion-resistance adversary view unless explicitly modeled as leakage.
//! A public/detailed verdict can reveal whether a voter evaded coercion
//! (see tests/negative_attack_tests.rs). Reports are therefore judge-private
//! and never contain R_EA,i.

/// Final dispute verdict.
///
/// Semantics:
///   * `AuthorityFaulty` — the evidence establishes an authority fault
///     (e.g. a valid first ballot with an INVALID tally proof, an
///     inconsistent registration leaf, a receipted-but-unposted
///     commitment in the EA-posts model);
///   * `VoterFaulty` — the complaint is unsupported (judge-internal: this
///     includes the fake-nonce case, which must NOT be distinguishable
///     externally — see `JudgeReport::external_verdict`);
///   * `BoardFaulty` — a board operated by a party distinct from the EA
///     failed to post admitted material;
///   * `NoAuthorityFault` — the complaint was processed and no authority
///     fault exists (e.g. a valid counted ballot with a VERIFYING tally
///     proof);
///   * `Undetermined` — the evidence decides nothing (e.g. no tally proof
///     was available to check).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    AuthorityFaulty,
    VoterFaulty,
    BoardFaulty,
    NoAuthorityFault,
    Undetermined,
}

/// Judge-private report. Contains a human-readable detail string for the
/// judge only. Never contains authority nonces and must not be published.
#[derive(Debug, Clone)]
pub struct JudgeReport {
    pub verdict: Verdict,
    pub detail: String,
}

impl JudgeReport {
    pub fn new(verdict: Verdict, detail: impl Into<String>) -> Self {
        JudgeReport { verdict, detail: detail.into() }
    }

    /// The verdict as it may be released OUTSIDE the judge. `VoterFaulty`
    /// is coarsened to `NoAuthorityFault`: an externally visible
    /// voter-fault verdict would let a coercer distinguish a fake-nonce
    /// complaint (fake compliance) from any other unsupported complaint,
    /// turning the dispute system itself into a coercion test. Authority-
    /// and board-fault verdicts are public by design (they trigger
    /// accountability), and `Undetermined` carries no voter-specific
    /// information.
    pub fn external_verdict(&self) -> Verdict {
        match self.verdict {
            Verdict::VoterFaulty => Verdict::NoAuthorityFault,
            v => v,
        }
    }
}
