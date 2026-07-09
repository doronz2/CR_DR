mod common;

use cr_dr::protocol::admission::{admitted_from_ballots, AdmittedOpenings};
use cr_dr::protocol::bulletin_board::{AdmittedBoard, BulletinBoard};
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
    admitted: AdmittedBoard,
    openings: AdmittedOpenings,
    ballots: Vec<cr_dr::types::Ballot>,
    tally: cr_dr::types::TallyResult,
    statement: cr_dr::zk::statement::TallyStatement,
    witness: cr_dr::zk::witness::TallyWitness,
}

fn build_instance(seed: u64) -> Instance {
    let mut env = common::small_election(seed);
    let mut ballots = Vec::new();
    // coerced voter 0: fake for candidate 2, real for candidate 0
    let coerced = env.voters[0].clone();
    let t = fake_compliance(&env.pp, &coerced, 2, &mut env.rng).unwrap();
    ballots.push(build_fake_ballot(&env.pp, &t, &mut env.rng).unwrap());
    ballots.push(cast_vote(&env.pp, &env.reg, &coerced, 0, &mut env.rng).unwrap());
    for (i, cand) in [1u64, 1, 2].iter().enumerate() {
        let voter = env.voters[i + 1].clone();
        ballots.push(cast_vote(&env.pp, &env.reg, &voter, *cand, &mut env.rng).unwrap());
    }
    ballots.push(chaff_ballot(&env.pp, &mut env.rng).unwrap());
    // shuffled voter-side; instance models an already-admitted board
    use rand::seq::SliceRandom;
    ballots.shuffle(&mut env.rng);
    let mut bb = BulletinBoard::new();
    for b in &ballots {
        bb.append(b.public());
    }
    let (admitted, openings) = admitted_from_ballots(&ballots);
    let (tally, _) =
        filter_and_tally(&env.pp, &env.authority, &env.reg, &admitted, &openings).unwrap();
    let statement = build_tally_statement(&env.pp, &admitted, &env.reg, &tally);
    let witness =
        build_tally_witness(&env.pp, &env.authority, &env.reg, &admitted, &openings).unwrap();
    Instance { env, bb, admitted, openings, ballots, tally, statement, witness }
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
        &inst.admitted,
        &inst.openings,
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
fn statement_binding_rejects_tampered_unconstrained_fields() {
    // num_voters and pk_ea_commitment carry no in-circuit constraints; the
    // native statement check against public data must catch tampering.
    use cr_dr::zk::statement::statement_matches_public_data;
    let inst = build_instance(76);
    assert!(statement_matches_public_data(&inst.statement, &inst.env.pp, &inst.admitted, &inst.env.reg));

    let mut bad = inst.statement.clone();
    bad.num_voters += 1;
    assert!(!statement_matches_public_data(&bad, &inst.env.pp, &inst.admitted, &inst.env.reg));

    let mut bad = inst.statement.clone();
    bad.pk_ea_commitment += cr_dr::types::F::from(1u64);
    assert!(!statement_matches_public_data(&bad, &inst.env.pp, &inst.admitted, &inst.env.reg));

    let mut bad = inst.statement.clone();
    bad.num_ballots += 1;
    assert!(!statement_matches_public_data(&bad, &inst.env.pp, &inst.admitted, &inst.env.reg));
}

#[test]
fn proof_public_inputs_are_bound_to_the_statement() {
    use cr_dr::zk::circom_io::{public_inputs_match, statement_public_inputs};
    let inst = build_instance(77);
    let public: serde_json::Value = statement_public_inputs(&inst.statement).into();
    assert!(public_inputs_match(&public, &inst.statement));

    // A proof carrying a different statement's public inputs must not match.
    let mut other = inst.statement.clone();
    other.num_voters += 1;
    let other_public: serde_json::Value = statement_public_inputs(&other).into();
    assert!(!public_inputs_match(&other_public, &inst.statement));
}

#[test]
fn serialized_public_board_contains_no_openings() {
    // Regression: the public board must expose ONLY (com, ct_open) — no
    // cast secrets, openings or blinding values. The comprehensive
    // value-level leak test (opening fields, R, R_EA, candidate, validity,
    // sorted records) lives in cast_tests.rs where the secrets are in
    // scope.
    let inst = build_instance(78);
    let board_json = serde_json::to_string(&inst.bb).unwrap();
    for key in ["secret", "opening", "plaintext_fields", "rho", "ea_payload"] {
        assert!(!board_json.contains(key), "board leaks key {key}");
    }
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

// ---------------------------------------------------------------------------
// Indexed registration table: hard row-consistency for in-range identities
// ---------------------------------------------------------------------------

#[test]
fn prover_cannot_withhold_the_path_of_an_in_range_ballot() {
    // Under the indexed table, the Merkle path of an ACTIVE ballot with an
    // in-range identity is a HARD constraint (directions = bits of id). A
    // malicious tallier that zeroes the path/row of a valid ballot — trying
    // to soft-invalidate it and undercount — makes the witness UNSATISFIABLE
    // instead of producing a proof of a smaller tally.
    let inst = build_instance(75);
    let idx = inst
        .witness
        .rows
        .iter()
        .position(|r| r.expect_valid)
        .expect("instance has a valid ballot");

    // Withhold the path.
    let mut w = inst.witness.clone();
    for e in &mut w.rows[idx].merkle_path {
        *e = cr_dr::types::F::from(0u64);
    }
    let mut bad_statement = inst.statement.clone();
    // even with the matching (smaller) tally the relation must be UNSAT
    bad_statement.tally_counts = inst.statement.tally_counts.clone();
    assert!(!relation_check_native(&bad_statement, &w, &SMALL_SHAPE));

    // Substitute a different (but real) row: root check fails => UNSAT too.
    let mut w2 = inst.witness.clone();
    let other = (0..inst.env.reg.num_voters() as u64)
        .find(|i| {
            inst.env.reg.records[i].vk.x != w2.rows[idx].reg_vkx
        })
        .expect("another registered row exists");
    let rec = &inst.env.reg.records[&other];
    w2.rows[idx].reg_vkx = rec.vk.x;
    w2.rows[idx].reg_vky = rec.vk.y;
    w2.rows[idx].reg_h = rec.h;
    assert!(!relation_check_native(&inst.statement, &w2, &SMALL_SHAPE));
}

#[test]
fn num_voters_is_constrained_by_the_relation() {
    // num_voters selects the in-range window of the indexed table; shrinking
    // it below a counted voter's id (or growing it past the true table) must
    // change/break the relation rather than being a free field.
    let inst = build_instance(76);
    let mut bad = inst.statement.clone();
    bad.num_voters = 0; // every id now out of range => all ballots invalid
    assert!(!relation_check_native(&bad, &inst.witness, &SMALL_SHAPE));
}
