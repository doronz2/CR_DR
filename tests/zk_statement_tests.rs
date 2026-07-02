mod common;

use cr_dr::protocol::bulletin_board::{AnonymousChannel, BulletinBoard};
use cr_dr::protocol::chaff::chaff_ballot;
use cr_dr::protocol::fake_compliance::{build_fake_ballot, fake_compliance};
use cr_dr::protocol::filter_and_tally::filter_and_tally;
use cr_dr::protocol::vote::cast_vote;
use cr_dr::zk::mock_backend::relation_check_native;
use cr_dr::zk::statement::build_tally_statement;
use cr_dr::zk::witness::build_tally_witness;
use cr_dr::zk::SMALL_SHAPE;

struct Instance {
    env: common::Env,
    bb: BulletinBoard,
    tally: cr_dr::types::TallyResult,
    statement: cr_dr::zk::statement::TallyStatement,
    witness: cr_dr::zk::witness::TallyWitness,
}

fn build_instance(seed: u64) -> Instance {
    let mut env = common::small_election(seed);
    let mut channel = AnonymousChannel::new();
    // coerced voter 0: fake for candidate 2, real for candidate 0
    let coerced = env.voters[0].clone();
    let t = fake_compliance(&env.pp, &coerced, 2, &mut env.rng).unwrap();
    channel.submit(build_fake_ballot(&env.pp, &t, &mut env.rng).unwrap());
    channel.submit(cast_vote(&env.pp, &env.reg, &coerced, 0, &mut env.rng).unwrap());
    for (i, cand) in [1u64, 1, 2].iter().enumerate() {
        let voter = env.voters[i + 1].clone();
        channel.submit(cast_vote(&env.pp, &env.reg, &voter, *cand, &mut env.rng).unwrap());
    }
    channel.submit(chaff_ballot(&env.pp, &mut env.rng).unwrap());
    let mut bb = BulletinBoard::new();
    for b in channel.flush_shuffled(&mut env.rng) {
        bb.append(b);
    }
    let (tally, _) =
        filter_and_tally(&env.pp, &env.authority, &env.reg, bb.list_public_ballots()).unwrap();
    let statement = build_tally_statement(&env.pp, &bb, &env.reg, &tally);
    let witness =
        build_tally_witness(&env.pp, &env.authority, &env.reg, bb.list_public_ballots()).unwrap();
    Instance { env, bb, tally, statement, witness }
}

#[test]
fn native_relation_accepts_valid_witness() {
    let inst = build_instance(70);
    assert_eq!(inst.tally.counts, vec![1, 2, 1]);
    assert!(relation_check_native(&inst.statement, &inst.witness, &SMALL_SHAPE));
}

#[test]
fn native_relation_rejects_wrong_tally() {
    let inst = build_instance(71);
    let mut bad = inst.statement.clone();
    bad.tally_counts[2] += 1;
    assert!(!relation_check_native(&bad, &inst.witness, &SMALL_SHAPE));
    let mut bad2 = inst.statement.clone();
    bad2.tally_counts.swap(0, 1);
    assert!(!relation_check_native(&bad2, &inst.witness, &SMALL_SHAPE));
}

#[test]
fn native_relation_rejects_tampered_public_inputs() {
    let inst = build_instance(72);
    let f1 = cr_dr::types::F::from(1u64);

    let mut bad = inst.statement.clone();
    bad.bb_commitment += f1;
    assert!(!relation_check_native(&bad, &inst.witness, &SMALL_SHAPE));

    let mut bad = inst.statement.clone();
    bad.mr += f1;
    assert!(!relation_check_native(&bad, &inst.witness, &SMALL_SHAPE));

    let mut bad = inst.statement.clone();
    bad.eid_hash += f1;
    assert!(!relation_check_native(&bad, &inst.witness, &SMALL_SHAPE));

    let mut bad = inst.statement.clone();
    bad.duplicate_rule_id = 2;
    assert!(!relation_check_native(&bad, &inst.witness, &SMALL_SHAPE));

    let mut bad = inst.statement.clone();
    bad.num_ballots += 1;
    assert!(!relation_check_native(&bad, &inst.witness, &SMALL_SHAPE));
}

#[test]
fn witness_flags_match_native_evaluation() {
    let inst = build_instance(73);
    let (_, evals) = filter_and_tally(
        &inst.env.pp,
        &inst.env.authority,
        &inst.env.reg,
        inst.bb.list_public_ballots(),
    )
    .unwrap();
    let counted: u64 = inst.witness.rows.iter().filter(|r| r.expect_counted).count() as u64;
    assert_eq!(counted, inst.tally.counted_ballots);
    for (row, eval) in inst.witness.rows.iter().zip(&evals) {
        use cr_dr::types::InternalBallotStatus::*;
        assert_eq!(row.expect_counted, matches!(eval.status, Counted));
        assert_eq!(row.expect_valid, matches!(eval.status, Counted | DuplicateValidBallot));
    }
}

#[test]
fn statement_contains_no_identities_or_validity_labels() {
    let inst = build_instance(74);
    let v = serde_json::to_value(&inst.statement).unwrap();
    let keys: Vec<&str> = v.as_object().unwrap().keys().map(|s| s.as_str()).collect();
    let expected = [
        "eid_hash",
        "pk_ea_commitment",
        "mr",
        "candidate_set_commitment",
        "tally_counts",
        "bb_commitment",
        "num_ballots",
        "num_voters",
        "duplicate_rule_id",
    ];
    for k in &keys {
        assert!(expected.contains(k), "unexpected public statement field: {k}");
    }
    // And the public tally result exposes only counts.
    let t = serde_json::to_value(&inst.tally).unwrap();
    let mut tally_keys: Vec<&str> = t.as_object().unwrap().keys().map(|s| s.as_str()).collect();
    tally_keys.sort_unstable();
    assert_eq!(tally_keys, vec!["counted_ballots", "counts"]);
}

#[test]
fn relation_rejects_witness_ballot_swap() {
    // Swapping two ballots in the witness breaks the BB chain binding.
    let inst = build_instance(75);
    let mut bad = inst.witness.clone();
    if bad.rows.len() >= 2 && bad.rows[0].ct != bad.rows[1].ct {
        bad.rows.swap(0, 1);
        assert!(!relation_check_native(&inst.statement, &bad, &SMALL_SHAPE));
    }
}
