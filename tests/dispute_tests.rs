mod common;

use cr_dr::crypto::encryption::commit_open;
use cr_dr::disputes::judge::Verdict;
use cr_dr::disputes::recorded_as_cast::{
    adjudicate_recorded_as_cast, check_direct, ea_issue_receipt, verify_receipt,
};
use cr_dr::disputes::tallied_as_recorded::{
    judge_tallied_as_recorded, AuthorityEvidence, NonceSource, TalliedAsRecordedComplaint,
};
use cr_dr::protocol::bulletin_board::BulletinBoard;
use cr_dr::protocol::fake_compliance::{build_fake_ballot, fake_compliance};
use cr_dr::protocol::filter_and_tally::filter_and_tally;
use cr_dr::protocol::vote::cast_vote;
use cr_dr::threshold::trusted_dealer::share_all_nonces;
use cr_dr::types::{f_to_dec, ThresholdParams};

#[test]
fn recorded_as_cast_succeeds_when_bytes_present() {
    let mut env = common::small_election(90);
    let ballot = cast_vote(&env.pp, &env.reg, &env.voters[0], 0, &mut env.rng).unwrap();
    let mut bb = BulletinBoard::new();
    bb.append(ballot.clone());
    assert!(check_direct(&bb, &ballot.bytes));
}

#[test]
fn recorded_as_cast_fails_when_absent_without_receipt() {
    let mut env = common::small_election(91);
    let ballot = cast_vote(&env.pp, &env.reg, &env.voters[0], 0, &mut env.rng).unwrap();
    let bb = BulletinBoard::new(); // ballot never posted
    assert!(!check_direct(&bb, &ballot.bytes));
    let report = adjudicate_recorded_as_cast(&env.pp, &bb, &ballot, None);
    assert_eq!(report.verdict, Verdict::Undetermined);
}

#[test]
fn receipt_identifies_missing_posted_ballot() {
    let mut env = common::small_election(92);
    let ballot = cast_vote(&env.pp, &env.reg, &env.voters[0], 0, &mut env.rng).unwrap();
    let receipt = ea_issue_receipt(&env.pp, &env.authority, &ballot, 123456, &mut env.rng);
    assert!(verify_receipt(&env.pp, &receipt));

    let bb = BulletinBoard::new(); // EA acknowledged but never posted
    let report = adjudicate_recorded_as_cast(&env.pp, &bb, &ballot, Some(&receipt));
    assert_eq!(report.verdict, Verdict::BoardFaulty);
}

#[test]
fn judge_detects_fake_nonce_privately() {
    let mut env = common::small_election(93);
    let coerced = env.voters[0].clone();
    // The coercer files a dispute over the fake-compliance ballot.
    let t = fake_compliance(&env.pp, &coerced, 2, &mut env.rng).unwrap();
    let fake = build_fake_ballot(&env.pp, &t, &mut env.rng).unwrap();
    let mut bb = BulletinBoard::new();
    bb.append(fake.clone());
    let (_, evals) =
        filter_and_tally(&env.pp, &env.authority, &env.reg, bb.list_public_ballots()).unwrap();

    let opening = commit_open(&fake.ciphertext, &fake.ea_payload).unwrap();
    let complaint = TalliedAsRecordedComplaint { ballot: fake, opening };
    let r_ea = env.authority.voter_secrets[&coerced.id].r_ea;
    let evidence = AuthorityEvidence {
        nonce_source: NonceSource::Direct(r_ea),
        prior_evaluations: &evals,
        tally_proof_valid: true,
    };
    let report = judge_tallied_as_recorded(&env.pp, &env.reg, &bb, &complaint, &evidence);
    // The judge privately identifies the fake nonce...
    assert_eq!(report.verdict, Verdict::VoterFaulty);
    assert!(report.detail.contains("nonce"));
    // ...and the report never contains R_EA,i itself.
    assert!(!format!("{report:?}").contains(&f_to_dec(&r_ea)));
}

#[test]
fn judge_accepts_valid_first_ballot_with_verifying_proof() {
    let mut env = common::small_election(94);
    let voter = env.voters[0].clone();
    let real = cast_vote(&env.pp, &env.reg, &voter, 0, &mut env.rng).unwrap();
    let mut bb = BulletinBoard::new();
    bb.append(real.clone());
    let (_, evals) =
        filter_and_tally(&env.pp, &env.authority, &env.reg, bb.list_public_ballots()).unwrap();

    let opening = commit_open(&real.ciphertext, &real.ea_payload).unwrap();
    let complaint = TalliedAsRecordedComplaint { ballot: real, opening };
    let evidence = AuthorityEvidence {
        nonce_source: NonceSource::Direct(env.authority.voter_secrets[&voter.id].r_ea),
        prior_evaluations: &evals,
        tally_proof_valid: true,
    };
    let report = judge_tallied_as_recorded(&env.pp, &env.reg, &bb, &complaint, &evidence);
    assert_eq!(report.verdict, Verdict::Undetermined); // counted under proof soundness
}

#[test]
fn judge_blames_authority_when_tally_proof_fails() {
    let mut env = common::small_election(95);
    let voter = env.voters[0].clone();
    let real = cast_vote(&env.pp, &env.reg, &voter, 0, &mut env.rng).unwrap();
    let mut bb = BulletinBoard::new();
    bb.append(real.clone());
    let (_, evals) =
        filter_and_tally(&env.pp, &env.authority, &env.reg, bb.list_public_ballots()).unwrap();

    let opening = commit_open(&real.ciphertext, &real.ea_payload).unwrap();
    let complaint = TalliedAsRecordedComplaint { ballot: real, opening };
    let evidence = AuthorityEvidence {
        nonce_source: NonceSource::Direct(env.authority.voter_secrets[&voter.id].r_ea),
        prior_evaluations: &evals,
        tally_proof_valid: false,
    };
    let report = judge_tallied_as_recorded(&env.pp, &env.reg, &bb, &complaint, &evidence);
    assert_eq!(report.verdict, Verdict::AuthorityFaulty);
}

#[test]
fn judge_works_with_threshold_share_reconstruction() {
    let mut env = common::small_election(96);
    share_all_nonces(&mut env.authority, ThresholdParams { t: 3, k: 5 }, &mut env.rng).unwrap();
    let voter = env.voters[0].clone();
    let real = cast_vote(&env.pp, &env.reg, &voter, 1, &mut env.rng).unwrap();
    let mut bb = BulletinBoard::new();
    bb.append(real.clone());
    let (_, evals) =
        filter_and_tally(&env.pp, &env.authority, &env.reg, bb.list_public_ballots()).unwrap();

    // Judge receives t = 3 shares (not the nonce itself, and not from the voter).
    let shares = env.authority.threshold_nonce_shares.as_ref().unwrap()[&voter.id][0..3].to_vec();
    let opening = commit_open(&real.ciphertext, &real.ea_payload).unwrap();
    let complaint = TalliedAsRecordedComplaint { ballot: real, opening };
    let evidence = AuthorityEvidence {
        nonce_source: NonceSource::ThresholdShares(shares),
        prior_evaluations: &evals,
        tally_proof_valid: true,
    };
    let report = judge_tallied_as_recorded(&env.pp, &env.reg, &bb, &complaint, &evidence);
    assert_eq!(report.verdict, Verdict::Undetermined); // valid + counted
}

#[test]
fn judge_flags_duplicate_complaints_correctly() {
    let mut env = common::small_election(97);
    let voter = env.voters[0].clone();
    let b1 = cast_vote(&env.pp, &env.reg, &voter, 0, &mut env.rng).unwrap();
    let b2 = cast_vote(&env.pp, &env.reg, &voter, 2, &mut env.rng).unwrap();
    let mut bb = BulletinBoard::new();
    bb.append(b1);
    bb.append(b2.clone());
    let (_, evals) =
        filter_and_tally(&env.pp, &env.authority, &env.reg, bb.list_public_ballots()).unwrap();

    let opening = commit_open(&b2.ciphertext, &b2.ea_payload).unwrap();
    let complaint = TalliedAsRecordedComplaint { ballot: b2, opening };
    let evidence = AuthorityEvidence {
        nonce_source: NonceSource::Direct(env.authority.voter_secrets[&voter.id].r_ea),
        prior_evaluations: &evals,
        tally_proof_valid: true,
    };
    let report = judge_tallied_as_recorded(&env.pp, &env.reg, &bb, &complaint, &evidence);
    assert_eq!(report.verdict, Verdict::VoterFaulty);
    assert!(report.detail.contains("earlier valid ballot"));
}
