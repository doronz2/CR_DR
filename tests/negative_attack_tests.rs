//! Negative tests: demonstrate the attacks that arise when the design
//! invariants are broken. Each test implements a deliberately-broken variant
//! locally and shows the resulting leak/attack, contrasted with the correct
//! behavior of the real implementation.

mod common;

use cr_dr::protocol::admission::admitted_from_ballots;

use std::collections::HashSet;

use cr_dr::crypto::hash::h_com;
use cr_dr::disputes::judge::Verdict;
use cr_dr::disputes::tallied_as_recorded::{
    judge_tallied_as_recorded, AuthorityEvidence, NonceSource, TalliedAsRecordedComplaint,
    TallyProofStatus,
};
use cr_dr::protocol::bulletin_board::BulletinBoard;
use cr_dr::protocol::fake_compliance::{build_fake_ballot, fake_compliance};
use cr_dr::protocol::filter_and_tally::filter_and_tally;
use cr_dr::protocol::vote::cast_vote;
use cr_dr::types::{BallotPlaintext, InternalBallotStatus};

/// BROKEN variant: consume the voter's slot BEFORE validity checking (i.e.
/// duplicate handling on the claimed id of any parseable ballot).
fn broken_tally_duplicates_before_validity(
    env: &common::Env,
    ballots: &[cr_dr::types::Ballot],
) -> Vec<u64> {
    let mut counts = vec![0u64; env.pp.candidates.len()];
    let mut seen: HashSet<u64> = HashSet::new();
    for ballot in ballots {
        // (broken tallier reads the opening from the voter-side secret,
        // standing in for its EA decryption of ct_open)
        let Ok(pt) = BallotPlaintext::from_fields(&ballot.secret.opening.plaintext_fields)
        else {
            continue;
        };
        // WRONG: slot consumed before any validity check.
        if !seen.insert(pt.id) {
            continue;
        }
        // validity after duplicate handling (the bug)
        let (_, evals) =
            { let (adm, opn) = admitted_from_ballots(&[ballot.clone()]); filter_and_tally(&env.pp, &env.authority, &env.reg, &adm, &opn) }.unwrap();
        if evals[0].status == InternalBallotStatus::Counted {
            let pos = env.pp.candidates.iter().position(|c| *c == pt.candidate).unwrap();
            counts[pos] += 1;
        }
    }
    counts
}

#[test]
fn duplicate_handling_before_validity_lets_fake_block_real() {
    let mut env = common::small_election(110);
    let voter = env.voters[0].clone();
    let t = fake_compliance(&env.pp, &voter, 2, &mut env.rng).unwrap();
    let fake = build_fake_ballot(&env.pp, &t, &mut env.rng).unwrap();
    let real = cast_vote(&env.pp, &env.reg, &voter, 0, &mut env.rng).unwrap();
    let board = vec![fake, real];

    // Broken order: the fake ballot consumes the slot; the real vote is lost
    // (forced abstention / vote cancellation by the coercer).
    let broken = broken_tally_duplicates_before_validity(&env, &board);
    assert_eq!(broken, vec![0, 0, 0]);

    // Correct order: the real vote counts.
    let (tally, _) = { let (adm, opn) = admitted_from_ballots(&board); filter_and_tally(&env.pp, &env.authority, &env.reg, &adm, &opn) }.unwrap();
    assert_eq!(tally.counts, vec![1, 0, 0]);
}

#[test]
fn publishing_accepted_identities_leaks_forced_abstention() {
    // If the set of counted voter ids were public, a coercer demanding
    // abstention (or fake compliance) could check whether the coerced
    // voter's id was counted — a direct evasion test.
    let mut env = common::small_election(111);
    let coerced = env.voters[0].clone();
    let t = fake_compliance(&env.pp, &coerced, 2, &mut env.rng).unwrap();
    let board = vec![
        build_fake_ballot(&env.pp, &t, &mut env.rng).unwrap(),
        cast_vote(&env.pp, &env.reg, &coerced, 0, &mut env.rng).unwrap(),
        cast_vote(&env.pp, &env.reg, &env.voters[1].clone(), 1, &mut env.rng).unwrap(),
    ];
    let (tally, internal) = { let (adm, opn) = admitted_from_ballots(&board); filter_and_tally(&env.pp, &env.authority, &env.reg, &adm, &opn) }.unwrap();

    // THE LEAK (if internal data were published): the coerced voter's id
    // appears as counted even though the coercer only authorized the fake.
    let counted_ids: HashSet<u64> = internal
        .iter()
        .filter(|e| e.status == InternalBallotStatus::Counted)
        .filter_map(|e| e.voter_id)
        .collect();
    assert!(counted_ids.contains(&coerced.id)); // coercer would detect evasion

    // The PUBLIC outputs expose no identities: only counts and sizes.
    let public = serde_json::to_value(&tally).unwrap();
    let mut keys: Vec<&str> = public.as_object().unwrap().keys().map(|s| s.as_str()).collect();
    keys.sort_unstable();
    assert_eq!(keys, vec!["counted_ballots", "counts"]);
    // (InternalBallotEvaluation deliberately does not implement Serialize.)
}

#[test]
fn giving_r_ea_to_the_coercer_breaks_fake_compliance() {
    // If the coercer learns R_EA,i, the fake nonce is detectable: the
    // coercer recomputes h and compares with the public registration record.
    let mut env = common::small_election(112);
    let coerced = env.voters[0].clone();
    let t = fake_compliance(&env.pp, &coerced, 2, &mut env.rng).unwrap();
    let r_ea = env.authority.r_ea(coerced.id).unwrap(); // leaked!
    let record = env.reg.record(coerced.id).unwrap();

    // Coercer's test on the surrendered (fake) nonce: FAILS -> fake detected.
    let h_fake = h_com(env.pp.eid_hash, coerced.id, &t.vk, t.r_fake, r_ea);
    assert_ne!(h_fake, record.h, "coercer detects the fake nonce given R_EA");

    // The same test on the real nonce SUCCEEDS -> distinguishes real/fake.
    let h_real = h_com(env.pp.eid_hash, coerced.id, &coerced.vk, coerced.r, r_ea);
    assert_eq!(h_real, record.h);

    // Without R_EA the coercer cannot run this test at all: both fake and
    // real nonces are just field elements, and h binds them only through
    // the hidden R_EA (hiding follows from Poseidon preimage resistance).
}

#[test]
fn public_detailed_verdicts_leak_evasion_status() {
    // If judge verdicts were public and detailed, the verdict on a
    // fake-compliance ballot ("nonce relation fails") differs from the
    // verdict on a real ballot — a coercer filing (or observing) disputes
    // could distinguish compliance from evasion.
    let mut env = common::small_election(113);
    let coerced = env.voters[0].clone();

    let t = fake_compliance(&env.pp, &coerced, 2, &mut env.rng).unwrap();
    let fake = build_fake_ballot(&env.pp, &t, &mut env.rng).unwrap();
    let real = cast_vote(&env.pp, &env.reg, &coerced, 0, &mut env.rng).unwrap();
    let (adm, opn) = admitted_from_ballots(&[fake.clone(), real.clone()]);
    let (_, evals) =
        filter_and_tally(&env.pp, &env.authority, &env.reg, &adm, &opn).unwrap();
    let r_ea = env.authority.r_ea(coerced.id).unwrap();

    let judge = |ballot: &cr_dr::types::Ballot| {
        let opening = ballot.secret.opening.clone();
        let complaint = TalliedAsRecordedComplaint { com: ballot.com, opening };
        let evidence = AuthorityEvidence {
            nonce_source: NonceSource::Direct(r_ea),
            prior_evaluations: &evals,
            tally_proof: TallyProofStatus::Verified,
        };
        judge_tallied_as_recorded(&env.pp, &env.reg, &adm, &complaint, &evidence)
    };

    let fake_report = judge(&fake);
    let real_report = judge(&real);

    // The verdicts differ — publishing them would reveal that the voter's
    // "compliant" ballot was fake (evasion detected by the coercer).
    assert_eq!(fake_report.verdict, Verdict::VoterFaulty);
    assert_ne!(fake_report.verdict, real_report.verdict);
    // Hence: detailed verdicts must stay judge-private (see README).
}
