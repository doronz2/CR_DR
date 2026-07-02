mod common;

use cr_dr::protocol::chaff::chaff_ballot;
use cr_dr::protocol::fake_compliance::{build_fake_ballot, fake_compliance};
use cr_dr::protocol::filter_and_tally::filter_and_tally;
use cr_dr::types::InternalBallotStatus;

#[test]
fn chaff_is_rejected_by_filter_and_tally() {
    let mut env = common::small_election(40);
    let mut ballots = Vec::new();
    for _ in 0..5 {
        ballots.push(chaff_ballot(&env.pp, &mut env.rng).unwrap());
    }
    let (tally, evals) = filter_and_tally(&env.pp, &env.authority, &env.reg, &ballots).unwrap();
    assert_eq!(tally.counts, vec![0, 0, 0]);
    assert_eq!(tally.counted_ballots, 0);
    for e in &evals {
        assert_eq!(e.status, InternalBallotStatus::InvalidRegistration);
    }
}

#[test]
fn chaff_has_the_same_public_shape_and_rejection_class_as_fake_ballots() {
    let mut env = common::small_election(41);
    let chaff = chaff_ballot(&env.pp, &mut env.rng).unwrap();
    let t = fake_compliance(&env.pp, &env.voters[0], 1, &mut env.rng).unwrap();
    let fake = build_fake_ballot(&env.pp, &t, &mut env.rng).unwrap();

    // Same public object shape.
    assert_eq!(chaff.ciphertext.fields.len(), fake.ciphertext.fields.len());
    assert_eq!(chaff.bytes.len(), fake.bytes.len());

    // Same internal rejection class (InvalidRegistration for both), so even
    // the tallier's internal log does not separate chaff from fake ballots.
    let (_, evals) =
        filter_and_tally(&env.pp, &env.authority, &env.reg, &[chaff, fake]).unwrap();
    assert_eq!(evals[0].status, InternalBallotStatus::InvalidRegistration);
    assert_eq!(evals[1].status, InternalBallotStatus::InvalidRegistration);
}

#[test]
fn chaff_carries_no_explicit_marker() {
    // The serialized public ballot is just ciphertext + payload, identical
    // key structure for chaff and real ballots.
    let mut env = common::small_election(42);
    let chaff = chaff_ballot(&env.pp, &mut env.rng).unwrap();
    let real = cr_dr::protocol::vote::cast_vote(&env.pp, &env.reg, &env.voters[0], 0, &mut env.rng)
        .unwrap();
    let chaff_json: serde_json::Value = serde_json::to_value(&chaff).unwrap();
    let real_json: serde_json::Value = serde_json::to_value(&real).unwrap();
    let keys = |v: &serde_json::Value| {
        v.as_object().unwrap().keys().cloned().collect::<Vec<_>>()
    };
    assert_eq!(keys(&chaff_json), keys(&real_json));
}
