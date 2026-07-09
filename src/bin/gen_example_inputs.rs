//! Deterministically regenerate the checked-in circuit example inputs:
//!   circuits/input_examples/small_valid_input.json
//!   circuits/input_examples/fake_before_real_input.json
//!
//! Both are full circom inputs (public inputs + private witness) for the
//! small FilterAndTally(16, 3, 4) circuit.
//!
//! With `medium` as the first argument, additionally writes a full-board
//! 128-slot input for the medium circuit to
//! build/inputs/medium_valid_input.json (not checked in — benchmark /
//! memory-measurement support).

use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

use cr_dr::protocol::admission::admitted_from_ballots;
use cr_dr::protocol::chaff::chaff_ballot;
use cr_dr::protocol::fake_compliance::{build_fake_ballot, fake_compliance};
use cr_dr::protocol::filter_and_tally::filter_and_tally;
use cr_dr::protocol::preprocessing::{finalize_registration, preprocess_voter};
use cr_dr::protocol::setup::setup_election;
use cr_dr::protocol::vote::cast_vote;
use cr_dr::types::{DuplicateRule, ElectionConfig};
use cr_dr::zk::circom_io::generate_witness_input;
use cr_dr::zk::mock_backend::relation_check_native;
use cr_dr::zk::statement::build_tally_statement;
use cr_dr::zk::witness::build_tally_witness;
use cr_dr::zk::SMALL_SHAPE;

fn main() -> anyhow::Result<()> {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let out_dir = root.join("circuits/input_examples");
    std::fs::create_dir_all(&out_dir)?;

    // ---- scenario 1: small valid election (real + fake + chaff) ----
    {
        let mut rng = ChaCha20Rng::seed_from_u64(41);
        let (pp, mut authority, reg, voters) = setup(&mut rng)?;
        let mut ballots = Vec::new();
        // real votes: candidates 0,1,1,2
        for (voter, cand) in voters.iter().take(4).zip([0u64, 1, 1, 2]) {
            ballots.push(cast_vote(&pp, &reg, voter, cand, &mut rng)?);
        }
        // one fake-compliance ballot from voter 4 (never casts a real one)
        let t = fake_compliance(&pp, &voters[4], 2, &mut rng)?;
        ballots.push(build_fake_ballot(&pp, &t, &mut rng)?);
        // two chaff ballots
        ballots.push(chaff_ballot(&pp, &mut rng)?);
        ballots.push(chaff_ballot(&pp, &mut rng)?);

        write_input(&root, "small_valid_input.json", &pp, &authority, &reg, &ballots)?;
        let _ = &mut authority;
    }

    // ---- scenario 2: fake ballot BEFORE the real ballot ----
    {
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let (pp, authority, reg, voters) = setup(&mut rng)?;
        let mut ballots = Vec::new();
        let coerced = &voters[0];
        // coercer's fake ballot first...
        let t = fake_compliance(&pp, coerced, 2, &mut rng)?;
        ballots.push(build_fake_ballot(&pp, &t, &mut rng)?);
        // ...then the voter's real ballot, which must still count
        ballots.push(cast_vote(&pp, &reg, coerced, 0, &mut rng)?);
        // one more honest voter and a chaff ballot
        ballots.push(cast_vote(&pp, &reg, &voters[1], 1, &mut rng)?);
        ballots.push(chaff_ballot(&pp, &mut rng)?);

        write_input(&root, "fake_before_real_input.json", &pp, &authority, &reg, &ballots)?;
    }

    // ---- optional: medium full-board input (bench/memory support) ----
    if std::env::args().nth(1).as_deref() == Some("medium") {
        use cr_dr::zk::MEDIUM_SHAPE;
        let mut rng = ChaCha20Rng::seed_from_u64(43);
        let config = ElectionConfig {
            eid: "example-election-medium".into(),
            candidates: vec![0, 1, 2],
            max_voters: 64,
            max_ballots: 128,
            merkle_depth: 6,
            duplicate_rule: DuplicateRule::FirstValidCounts,
            threshold_params: Some(cr_dr::types::ThresholdParams { t: 2, k: 3 }),
        };
        let (pp, mut authority) = setup_election(config, &mut rng)?;
        let mut voters = Vec::new();
        let mut records = Vec::new();
        for id in 0..40u64 {
            let (vs, rec) = preprocess_voter(&pp, &mut authority, id, &mut rng)?;
            voters.push(vs);
            records.push(rec);
        }
        let reg = finalize_registration(&pp, &records)?;
        let mut ballots = Vec::new();
        for v in voters.iter().take(5) {
            let t = fake_compliance(&pp, v, 2, &mut rng)?;
            ballots.push(build_fake_ballot(&pp, &t, &mut rng)?);
            ballots.push(cast_vote(&pp, &reg, v, 0, &mut rng)?);
        }
        for (i, v) in voters.iter().enumerate().skip(5) {
            ballots.push(cast_vote(&pp, &reg, v, 1 + (i as u64 % 2), &mut rng)?);
        }
        while ballots.len() < 128 {
            ballots.push(chaff_ballot(&pp, &mut rng)?);
        }

        let (admitted, openings) = admitted_from_ballots(&ballots);
        let (tally, _) = filter_and_tally(&pp, &authority, &reg, &admitted, &openings)?;
        let statement = build_tally_statement(&pp, &admitted, &reg, &tally);
        let witness = build_tally_witness(&pp, &authority, &reg, &admitted, &openings)?;
        assert!(relation_check_native(&statement, &witness, &MEDIUM_SHAPE));
        let input = generate_witness_input(&statement, &witness, &MEDIUM_SHAPE)?;
        let dir = root.join("build/inputs");
        std::fs::create_dir_all(&dir)?;
        let path = dir.join("medium_valid_input.json");
        std::fs::write(&path, serde_json::to_string_pretty(&input)?)?;
        println!("wrote {} (tally: {:?})", path.display(), tally.counts);
    }

    Ok(())
}

type Setup = (
    cr_dr::types::PublicParams,
    cr_dr::types::AuthoritySecretState,
    cr_dr::protocol::preprocessing::RegistrationState,
    Vec<cr_dr::types::VoterState>,
);

fn setup(rng: &mut ChaCha20Rng) -> anyhow::Result<Setup> {
    let config = ElectionConfig {
        eid: "example-election".into(),
        candidates: vec![0, 1, 2],
        max_voters: 8,
        max_ballots: 16,
        merkle_depth: 4,
        duplicate_rule: DuplicateRule::FirstValidCounts,
        threshold_params: None,
    };
    let (pp, mut authority) = setup_election(config, rng)?;
    let mut voters = Vec::new();
    let mut records = Vec::new();
    for id in 0..6u64 {
        let (vs, rec) = preprocess_voter(&pp, &mut authority, id, rng)?;
        voters.push(vs);
        records.push(rec);
    }
    let reg = finalize_registration(&pp, &records)?;
    Ok((pp, authority, reg, voters))
}

fn write_input(
    root: &std::path::Path,
    name: &str,
    pp: &cr_dr::types::PublicParams,
    authority: &cr_dr::types::AuthoritySecretState,
    reg: &cr_dr::protocol::preprocessing::RegistrationState,
    ballots: &[cr_dr::types::Ballot],
) -> anyhow::Result<()> {
    let (admitted, openings) = admitted_from_ballots(ballots);
    let (tally, _) = filter_and_tally(pp, authority, reg, &admitted, &openings)?;
    let statement = build_tally_statement(pp, &admitted, reg, &tally);
    let witness = build_tally_witness(pp, authority, reg, &admitted, &openings)?;
    assert!(
        relation_check_native(&statement, &witness, &SMALL_SHAPE),
        "example must satisfy the native relation"
    );
    let input = generate_witness_input(&statement, &witness, &SMALL_SHAPE)?;
    let path = root.join("circuits/input_examples").join(name);
    std::fs::write(&path, serde_json::to_string_pretty(&input)?)?;
    println!("wrote {} (tally: {:?})", path.display(), tally.counts);
    Ok(())
}
