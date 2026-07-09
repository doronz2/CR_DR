mod common;

use cr_dr::protocol::admission::admitted_from_ballots;

use cr_dr::crypto::hash::sig_msg_hash;
use cr_dr::crypto::signature::verify;
use cr_dr::protocol::fake_compliance::{build_fake_ballot, fake_compliance};
use cr_dr::protocol::filter_and_tally::filter_and_tally;
use cr_dr::protocol::vote::cast_vote;
use cr_dr::types::InternalBallotStatus;

#[test]
fn fake_ballot_signature_verifies_for_the_coercer() {
    // The coercer holds the transcript (sk, vk, R~, m*, sigma~) and can run
    // exactly the public signature check — it passes.
    let mut env = common::small_election(30);
    let t = fake_compliance(&env.pp, &env.voters[0], 2, &mut env.rng).unwrap();
    let msg = sig_msg_hash(env.pp.eid_hash, t.voter_id, t.requested_candidate, t.r_fake);
    assert!(verify(&t.vk, msg, &t.sigma_fake));
    // And the fake nonce is not the real one.
    assert_ne!(t.r_fake, env.voters[0].r);
}

#[test]
fn fake_ballot_is_rejected_by_filter_and_tally() {
    let mut env = common::small_election(31);
    let t = fake_compliance(&env.pp, &env.voters[0], 2, &mut env.rng).unwrap();
    let fake = build_fake_ballot(&env.pp, &t, &mut env.rng).unwrap();
    let (tally, evals) = { let (adm, opn) = admitted_from_ballots(&[fake.clone()]); filter_and_tally(&env.pp, &env.authority, &env.reg, &adm, &opn) }.unwrap();
    assert_eq!(tally.counts, vec![0, 0, 0]);
    // It fails exactly at the hidden nonce / registration relation.
    assert_eq!(evals[0].status, InternalBallotStatus::InvalidRegistration);
}

#[test]
fn fake_ballot_before_real_ballot_does_not_block_the_real_one() {
    // THE critical invariant: duplicate handling only after validity.
    let mut env = common::small_election(32);
    let voter = env.voters[0].clone();
    let t = fake_compliance(&env.pp, &voter, 2, &mut env.rng).unwrap();
    let fake = build_fake_ballot(&env.pp, &t, &mut env.rng).unwrap();
    let real = cast_vote(&env.pp, &env.reg, &voter, 0, &mut env.rng).unwrap();

    let (tally, evals) =
        { let (adm, opn) = admitted_from_ballots(&[fake.clone(), real.clone()]); filter_and_tally(&env.pp, &env.authority, &env.reg, &adm, &opn) }.unwrap();
    assert_eq!(evals[0].status, InternalBallotStatus::InvalidRegistration);
    assert_eq!(evals[1].status, InternalBallotStatus::Counted);
    // The real vote (candidate 0) counts; the coerced choice (2) does not.
    assert_eq!(tally.counts, vec![1, 0, 0]);
}

#[test]
fn fake_and_real_ballots_have_identical_public_shape() {
    let mut env = common::small_election(33);
    let voter = env.voters[0].clone();
    let t = fake_compliance(&env.pp, &voter, 2, &mut env.rng).unwrap();
    let fake = build_fake_ballot(&env.pp, &t, &mut env.rng).unwrap();
    let real = cast_vote(&env.pp, &env.reg, &voter, 0, &mut env.rng).unwrap();
    assert_eq!(fake.ct_open.masked.len(), real.ct_open.masked.len());
    assert_eq!(fake.bytes().len(), real.bytes().len());
}
