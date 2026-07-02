mod common;

use cr_dr::protocol::fake_compliance::{build_fake_ballot, fake_compliance};
use cr_dr::protocol::filter_and_tally::filter_and_tally;
use cr_dr::protocol::vote::cast_vote;
use cr_dr::types::InternalBallotStatus;

#[test]
fn first_valid_ballot_counts_second_ignored() {
    let mut env = common::small_election(60);
    let voter = env.voters[0].clone();
    let b1 = cast_vote(&env.pp, &env.reg, &voter, 1, &mut env.rng).unwrap();
    let b2 = cast_vote(&env.pp, &env.reg, &voter, 2, &mut env.rng).unwrap();
    let (tally, _) = filter_and_tally(&env.pp, &env.authority, &env.reg, &[b1, b2]).unwrap();
    assert_eq!(tally.counts, vec![0, 1, 0]);
}

#[test]
fn invalid_ballots_never_consume_the_slot() {
    // fake, fake, real, real: both fakes rejected, first real counts,
    // second real is the duplicate.
    let mut env = common::small_election(61);
    let voter = env.voters[0].clone();
    let t1 = fake_compliance(&env.pp, &voter, 2, &mut env.rng).unwrap();
    let t2 = fake_compliance(&env.pp, &voter, 1, &mut env.rng).unwrap();
    let ballots = vec![
        build_fake_ballot(&env.pp, &t1, &mut env.rng).unwrap(),
        build_fake_ballot(&env.pp, &t2, &mut env.rng).unwrap(),
        cast_vote(&env.pp, &env.reg, &voter, 0, &mut env.rng).unwrap(),
        cast_vote(&env.pp, &env.reg, &voter, 1, &mut env.rng).unwrap(),
    ];
    let (tally, evals) =
        filter_and_tally(&env.pp, &env.authority, &env.reg, &ballots).unwrap();
    assert_eq!(evals[0].status, InternalBallotStatus::InvalidRegistration);
    assert_eq!(evals[1].status, InternalBallotStatus::InvalidRegistration);
    assert_eq!(evals[2].status, InternalBallotStatus::Counted);
    assert_eq!(evals[3].status, InternalBallotStatus::DuplicateValidBallot);
    assert_eq!(tally.counts, vec![1, 0, 0]);
}

#[test]
fn real_then_fake_keeps_real_counted() {
    let mut env = common::small_election(62);
    let voter = env.voters[0].clone();
    let real = cast_vote(&env.pp, &env.reg, &voter, 0, &mut env.rng).unwrap();
    let t = fake_compliance(&env.pp, &voter, 2, &mut env.rng).unwrap();
    let fake = build_fake_ballot(&env.pp, &t, &mut env.rng).unwrap();
    let (tally, evals) =
        filter_and_tally(&env.pp, &env.authority, &env.reg, &[real, fake]).unwrap();
    assert_eq!(evals[0].status, InternalBallotStatus::Counted);
    assert_eq!(evals[1].status, InternalBallotStatus::InvalidRegistration);
    assert_eq!(tally.counts, vec![1, 0, 0]);
}

#[test]
fn duplicates_across_different_voters_do_not_interact() {
    let mut env = common::small_election(63);
    let v0 = env.voters[0].clone();
    let v1 = env.voters[1].clone();
    let ballots = vec![
        cast_vote(&env.pp, &env.reg, &v0, 0, &mut env.rng).unwrap(),
        cast_vote(&env.pp, &env.reg, &v1, 0, &mut env.rng).unwrap(),
        cast_vote(&env.pp, &env.reg, &v1, 1, &mut env.rng).unwrap(),
    ];
    let (tally, evals) =
        filter_and_tally(&env.pp, &env.authority, &env.reg, &ballots).unwrap();
    assert_eq!(evals[2].status, InternalBallotStatus::DuplicateValidBallot);
    assert_eq!(tally.counts, vec![2, 0, 0]);
}
