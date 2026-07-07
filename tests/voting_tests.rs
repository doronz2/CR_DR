mod common;

use cr_dr::protocol::filter_and_tally::filter_and_tally;
use cr_dr::protocol::vote::cast_vote;
use cr_dr::types::InternalBallotStatus;

#[test]
fn real_ballot_is_counted() {
    let mut env = common::small_election(20);
    let ballot = cast_vote(&env.pp, &env.reg, &env.voters[0], 1, &mut env.rng).unwrap();
    let (tally, evals) =
        filter_and_tally(&env.pp, &env.authority, &env.reg, &[ballot]).unwrap();
    assert_eq!(tally.counts, vec![0, 1, 0]);
    assert_eq!(tally.counted_ballots, 1);
    assert_eq!(evals[0].status, InternalBallotStatus::Counted);
}

#[test]
fn cast_vote_rejects_unknown_candidate() {
    let mut env = common::small_election(21);
    assert!(cast_vote(&env.pp, &env.reg, &env.voters[0], 99, &mut env.rng).is_err());
}

#[test]
fn cast_vote_rejects_unregistered_voter() {
    let mut env = common::small_election(22);
    let mut ghost = env.voters[0].clone();
    ghost.id = 42;
    assert!(cast_vote(&env.pp, &env.reg, &ghost, 0, &mut env.rng).is_err());
}

#[test]
fn several_voters_tally_correctly() {
    let mut env = common::small_election(23);
    let mut ballots = Vec::new();
    for (i, cand) in [0u64, 1, 1, 2, 0, 0].iter().enumerate() {
        let voter = env.voters[i].clone();
        ballots.push(cast_vote(&env.pp, &env.reg, &voter, *cand, &mut env.rng).unwrap());
    }
    let (tally, _) = filter_and_tally(&env.pp, &env.authority, &env.reg, &ballots).unwrap();
    assert_eq!(tally.counts, vec![3, 2, 1]);
    assert_eq!(tally.counted_ballots, 6);
}

#[test]
fn ballot_bytes_are_the_exact_public_ciphertext_encoding() {
    let mut env = common::small_election(24);
    let ballot = cast_vote(&env.pp, &env.reg, &env.voters[0], 1, &mut env.rng).unwrap();
    assert_eq!(ballot.bytes(), ballot.ciphertext.to_bytes());
    assert_eq!(ballot.bytes().len(), 32); // one field element in commitment mode
}
