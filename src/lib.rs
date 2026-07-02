//! # CR-DR: Coercion-Resistant Voting with Private Dispute Resolution
//!
//! Research reference implementation of the CONSTRUCTION from the paper
//! "Coercion-Resistant Voting with Private Dispute Resolution".
//!
//! Implements: election setup, (cut-and-choose) preprocessing, threshold
//! authority nonce handling, voting, fake compliance, chaff ballots,
//! byte-preserving anonymous bulletin-board submission, exact FilterAndTally,
//! a Circom/Groth16 proof of the exact tally relation, and private
//! dispute-resolution checks.
//!
//! Deliberately NOT implemented: the coercion-resistance real/ideal game,
//! hybrid experiments, and adversary game code.
//!
//! THIS IS A RESEARCH PROTOTYPE, NOT PRODUCTION CRYPTOGRAPHY. See README.

pub mod crypto;
pub mod disputes;
pub mod errors;
pub mod protocol;
pub mod threshold;
pub mod types;
pub mod zk;

pub use errors::{CrDrError, Result};
pub use types::*;
