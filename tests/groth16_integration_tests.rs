//! End-to-end Groth16 integration tests via the snarkjs CLI backend.
//!
//! These tests require the compiled circuit artifacts:
//!     scripts/install_circom_deps.sh
//!     scripts/compile_circuits.sh small
//!     scripts/setup_groth16.sh small
//! If the artifacts are missing the tests SKIP (pass with a notice), so
//! `cargo test` stays green on machines without the ZK toolchain.

mod common;

use cr_dr::protocol::bulletin_board::BulletinBoard;
use cr_dr::protocol::chaff::chaff_ballot;
use cr_dr::protocol::fake_compliance::{build_fake_ballot, fake_compliance};
use cr_dr::protocol::filter_and_tally::filter_and_tally;
use cr_dr::protocol::vote::cast_vote;
use cr_dr::zk::circom_io::generate_witness_input;
use cr_dr::zk::groth16_backend::SnarkjsBackend;
use cr_dr::zk::mock_backend::relation_check_native;
use cr_dr::zk::statement::build_tally_statement;
use cr_dr::zk::witness::build_tally_witness;
use cr_dr::zk::SMALL_SHAPE;

fn backend() -> Option<SnarkjsBackend> {
    let b = SnarkjsBackend::small(SnarkjsBackend::crate_root());
    if b.toolchain_available() {
        Some(b)
    } else {
        eprintln!("SKIP: groth16 artifacts not found (run scripts/compile_circuits.sh + setup_groth16.sh)");
        None
    }
}

fn build_valid_input(seed: u64) -> (serde_json::Value, cr_dr::zk::statement::TallyStatement) {
    let mut env = common::small_election(seed);
    let mut bb = BulletinBoard::new();
    // fake before real for voter 0 + honest voters + chaff
    let coerced = env.voters[0].clone();
    let t = fake_compliance(&env.pp, &coerced, 2, &mut env.rng).unwrap();
    bb.append(build_fake_ballot(&env.pp, &t, &mut env.rng).unwrap());
    bb.append(cast_vote(&env.pp, &env.reg, &coerced, 0, &mut env.rng).unwrap());
    let v1 = env.voters[1].clone();
    let v2 = env.voters[2].clone();
    bb.append(cast_vote(&env.pp, &env.reg, &v1, 1, &mut env.rng).unwrap());
    bb.append(cast_vote(&env.pp, &env.reg, &v2, 1, &mut env.rng).unwrap());
    bb.append(chaff_ballot(&env.pp, &mut env.rng).unwrap());

    let (tally, _) =
        filter_and_tally(&env.pp, &env.authority, &env.reg, bb.list_public_ballots()).unwrap();
    assert_eq!(tally.counts, vec![1, 2, 0]); // real vote for 0 counted, fake for 2 rejected
    let statement = build_tally_statement(&env.pp, &bb, &env.reg, &tally);
    let witness =
        build_tally_witness(&env.pp, &env.authority, &env.reg, bb.list_public_ballots()).unwrap();
    assert!(relation_check_native(&statement, &witness, &SMALL_SHAPE));
    (generate_witness_input(&statement, &witness, &SMALL_SHAPE).unwrap(), statement)
}

#[test]
fn groth16_proves_and_verifies_valid_instance() {
    let Some(b) = backend() else { return };
    let (input, _) = build_valid_input(80);
    let (proof, public) = b.prove(&input).expect("proving must succeed");
    assert!(b.verify(&proof, &public).unwrap(), "valid proof must verify");
}

#[test]
fn groth16_rejects_tampered_public_input() {
    let Some(b) = backend() else { return };
    let (input, _) = build_valid_input(81);
    let (proof, public) = b.prove(&input).unwrap();

    // Tamper with one public input value.
    let mut bad_public = public.clone();
    let arr = bad_public.as_array_mut().unwrap();
    let first = arr[0].as_str().unwrap().to_string();
    let bumped = if first == "1" { "2".to_string() } else { "1".to_string() };
    arr[0] = serde_json::Value::String(bumped);
    assert!(!b.verify(&proof, &bad_public).unwrap(), "tampered public input must fail");
}

#[test]
fn groth16_rejects_wrong_tally_at_witness_generation() {
    let Some(b) = backend() else { return };
    let (mut input, _) = build_valid_input(82);
    // Claim one extra vote for candidate 0: the witness must be unsatisfiable.
    let tc = input["tally_counts"].as_array_mut().unwrap();
    let bumped = (tc[0].as_str().unwrap().parse::<u64>().unwrap() + 1).to_string();
    tc[0] = serde_json::Value::String(bumped);
    assert!(b.prove(&input).is_err(), "wrong tally must not be provable");
}

#[test]
fn groth16_rejects_proof_public_mismatch_across_instances() {
    let Some(b) = backend() else { return };
    let (input_a, _) = build_valid_input(83);
    let (input_b, _) = build_valid_input(84); // different election (different keys/nonces)
    let (proof_a, _public_a) = b.prove(&input_a).unwrap();
    let (_proof_b, public_b) = b.prove(&input_b).unwrap();
    assert!(!b.verify(&proof_a, &public_b).unwrap(), "cross-instance proof must fail");
}

#[test]
fn proof_object_contains_no_witness_data() {
    let Some(b) = backend() else { return };
    let (input, statement) = build_valid_input(85);
    let (proof, public) = b.prove(&input).unwrap();

    // The proof is exactly the three Groth16 group elements + metadata.
    let keys: Vec<&str> = proof.as_object().unwrap().keys().map(|s| s.as_str()).collect();
    for k in &keys {
        assert!(
            ["pi_a", "pi_b", "pi_c", "protocol", "curve"].contains(k),
            "unexpected proof field: {k}"
        );
    }

    // Public inputs are exactly the statement values: no per-ballot data,
    // no identities, no validity labels. 11 = 8 scalars + 3 tally counts.
    assert_eq!(public.as_array().unwrap().len(), 11);
    let public_strs: Vec<String> = public
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    // Every public value is one of the statement's fields.
    let allowed: Vec<String> = vec![
        cr_dr::types::f_to_dec(&statement.eid_hash),
        cr_dr::types::f_to_dec(&statement.mr),
        cr_dr::types::f_to_dec(&statement.candidate_set_commitment),
        cr_dr::types::f_to_dec(&statement.bb_commitment),
        cr_dr::types::f_to_dec(&statement.pk_ea_commitment),
        statement.num_ballots.to_string(),
        statement.num_voters.to_string(),
        statement.duplicate_rule_id.to_string(),
        statement.tally_counts[0].to_string(),
        statement.tally_counts[1].to_string(),
        statement.tally_counts[2].to_string(),
    ];
    for v in &public_strs {
        assert!(allowed.contains(v), "public input {v} is not a statement value");
    }
}
