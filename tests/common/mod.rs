//! Shared test fixtures.
#![allow(dead_code)]

use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

use cr_dr::protocol::preprocessing::{finalize_registration, preprocess_voter, RegistrationState};
use cr_dr::protocol::setup::setup_election;
use cr_dr::types::{
    AuthoritySecretState, DuplicateRule, ElectionConfig, PublicParams, VoterState,
};

pub const CANDIDATES: [u64; 3] = [0, 1, 2];

pub struct Env {
    pub pp: PublicParams,
    pub authority: AuthoritySecretState,
    pub reg: RegistrationState,
    pub voters: Vec<VoterState>,
    pub rng: ChaCha20Rng,
}

pub fn rng(seed: u64) -> ChaCha20Rng {
    ChaCha20Rng::seed_from_u64(seed)
}

pub fn config() -> ElectionConfig {
    ElectionConfig {
        eid: "test-election".into(),
        candidates: CANDIDATES.to_vec(),
        max_voters: 8,
        max_ballots: 16,
        merkle_depth: 4,
        duplicate_rule: DuplicateRule::FirstValidCounts,
        threshold_params: None,
    }
}

/// Standard small election: 6 registered voters (ids 0..6).
pub fn small_election(seed: u64) -> Env {
    let mut rng = rng(seed);
    let (pp, mut authority) = setup_election(config(), &mut rng).unwrap();
    let mut voters = Vec::new();
    let mut records = Vec::new();
    for id in 0..6u64 {
        let (vs, rec) = preprocess_voter(&pp, &mut authority, id, &mut rng).unwrap();
        voters.push(vs);
        records.push(rec);
    }
    let reg = finalize_registration(&pp, &records).unwrap();
    Env { pp, authority, reg, voters, rng }
}
