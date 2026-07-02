//! Private judge verdicts.
//!
//! IMPORTANT LEAKAGE NOTE: detailed judge verdicts are NOT part of the
//! coercion-resistance adversary view unless explicitly modeled as leakage.
//! A public/detailed verdict can reveal whether a voter evaded coercion
//! (see tests/negative_attack_tests.rs). Reports are therefore judge-private
//! and never contain R_EA,i.

/// Final dispute verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    AuthorityFaulty,
    VoterFaulty,
    BoardFaulty,
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
}
