//! End-to-end demo of the CR-DR construction on a small election.
//! Prints ONLY public outputs (plus explicitly-labeled modeling notes).

use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

use cr_dr::protocol::bulletin_board::{AnonymousChannel, BulletinBoard};
use cr_dr::protocol::chaff::chaff_ballot;
use cr_dr::protocol::fake_compliance::{build_fake_ballot, fake_compliance};
use cr_dr::protocol::filter_and_tally::filter_and_tally;
use cr_dr::protocol::preprocessing::{finalize_registration, preprocess_voter};
use cr_dr::protocol::setup::setup_election;
use cr_dr::protocol::vote::cast_vote;
use cr_dr::types::{DuplicateRule, ElectionConfig};
use cr_dr::zk::groth16_backend::SnarkjsBackend;
use cr_dr::zk::mock_backend::relation_check_native;
use cr_dr::zk::statement::build_tally_statement;
use cr_dr::zk::witness::build_tally_witness;
use cr_dr::zk::SMALL_SHAPE;

fn main() -> anyhow::Result<()> {
    let mut rng = ChaCha20Rng::seed_from_u64(2026);

    let config = ElectionConfig {
        eid: "demo-election-2026".into(),
        candidates: vec![0, 1, 2],
        max_voters: 8,
        max_ballots: 16,
        merkle_depth: 4,
        duplicate_rule: DuplicateRule::FirstValidCounts,
        threshold_params: None,
    };
    let (pp, mut authority) = setup_election(config, &mut rng)?;

    // Preprocessing: 6 voters.
    let mut voters = Vec::new();
    let mut records = Vec::new();
    for id in 0..6u64 {
        let (vs, rec) = preprocess_voter(&pp, &mut authority, id, &mut rng)?;
        voters.push(vs);
        records.push(rec);
    }
    let reg = finalize_registration(&pp, &records)?;
    println!("registration merkle root: {}", cr_dr::types::f_to_dec(&reg.root));

    // Voting through the anonymous channel. Voter 0 is coerced: the coercer
    // submits a fake-compliance ballot for candidate 2; the voter's real
    // ballot (candidate 0) goes through the anonymous channel too.
    let mut channel = AnonymousChannel::new();
    let coerced = &voters[0];
    let transcript = fake_compliance(&pp, coerced, 2, &mut rng)?;
    channel.submit(build_fake_ballot(&pp, &transcript, &mut rng)?);
    channel.submit(cast_vote(&pp, &reg, coerced, 0, &mut rng)?);
    for (voter, cand) in voters[1..].iter().zip([0u64, 1, 1, 2, 0]) {
        channel.submit(cast_vote(&pp, &reg, voter, cand, &mut rng)?);
    }
    for _ in 0..3 {
        channel.submit(chaff_ballot(&pp, &mut rng)?);
    }

    let mut bb = BulletinBoard::new();
    for ballot in channel.flush_shuffled(&mut rng) {
        bb.append(ballot);
    }
    println!("bulletin board: {} ballots posted", bb.len());

    // FilterAndTally (public output only).
    let (tally, _internal) = filter_and_tally(&pp, &authority, &reg, bb.list_public_ballots())?;
    println!("tally: candidates {:?} -> counts {:?} (counted ballots: {})",
        pp.candidates, tally.counts, tally.counted_ballots);

    // ZK statement + native relation check.
    let statement = build_tally_statement(&pp, &bb, &reg, &tally);
    let witness = build_tally_witness(&pp, &authority, &reg, bb.list_public_ballots())?;
    let ok = relation_check_native(&statement, &witness, &SMALL_SHAPE);
    println!("native relation check: {}", if ok { "ACCEPT" } else { "REJECT" });

    // Groth16 (requires compiled circuit artifacts; see scripts/).
    let backend = SnarkjsBackend::small(SnarkjsBackend::crate_root());
    if backend.toolchain_available() {
        let input = cr_dr::zk::circom_io::generate_witness_input(&statement, &witness, &SMALL_SHAPE)?;
        println!("generating Groth16 proof (snarkjs)...");
        let (proof, public) = backend.prove(&input)?;
        let verified = backend.verify(&proof, &public)?;
        println!("groth16 proof verified: {verified}");
    } else {
        println!("groth16 artifacts not found; run scripts/compile_circuits.sh and scripts/setup_groth16.sh");
    }

    Ok(())
}
