mod common;

use cr_dr::protocol::admission::admitted_from_ballots;

use cr_dr::disputes::judge::Verdict;
use cr_dr::disputes::recorded_as_cast::{
    adjudicate_admission_receipt, adjudicate_recorded_as_cast, check_direct, verify_receipt,
};
use cr_dr::protocol::admission::{ea_admit_private, EaAdmissionState};
use cr_dr::disputes::tallied_as_recorded::{
    judge_tallied_as_recorded, AuthorityEvidence, NonceSource, TalliedAsRecordedComplaint,
    TallyProofStatus,
};
use cr_dr::protocol::bulletin_board::BulletinBoard;
use cr_dr::protocol::fake_compliance::{build_fake_ballot, fake_compliance};
use cr_dr::protocol::vote::cast_vote;
use cr_dr::threshold::trusted_dealer::share_all_nonces;
use cr_dr::types::{f_to_dec, ThresholdParams};

#[test]
fn recorded_as_cast_succeeds_when_bytes_present() {
    let mut env = common::small_election(90);
    let ballot = cast_vote(&env.pp, &env.reg, &env.voters[0], 0, &mut env.rng).unwrap();
    let mut bb = BulletinBoard::new();
    bb.append(ballot.public());
    assert!(check_direct(&bb, &ballot.bytes()));

    // Adjudication needs MORE than byte presence: the accompanying
    // pi_cast must verify (Clean drops proofless entries).
    let dummy = cr_dr::zk::cast::CastProof {
        proof: serde_json::Value::Null,
        public: serde_json::Value::Null,
    };
    let proofs = vec![Some(dummy)];
    let report =
        adjudicate_recorded_as_cast(&env.pp, &bb, &proofs, &ballot.bytes(), |_, _| Ok(true))
            .unwrap();
    assert_eq!(report.verdict, Verdict::VoterFaulty); // present + admitted => unfounded
}

#[test]
fn recorded_as_cast_entry_without_verifying_proof_is_not_present() {
    // The reviewer scenario: the entry bytes are on BB_raw but the proof
    // is missing/tampered, so Clean drops the entry — adjudication must
    // NOT report it as recorded.
    let mut env = common::small_election(89);
    let ballot = cast_vote(&env.pp, &env.reg, &env.voters[0], 0, &mut env.rng).unwrap();
    let mut bb = BulletinBoard::new();
    bb.append(ballot.public());

    // proof missing entirely
    let report = adjudicate_recorded_as_cast(
        &env.pp,
        &bb,
        &[None],
        &ballot.bytes(),
        |_, _| Ok(true),
    )
    .unwrap();
    assert_eq!(report.verdict, Verdict::Undetermined);
    assert!(report.detail.contains("no verifying pi_cast"));

    // proof present but failing verification (tampered)
    let dummy = cr_dr::zk::cast::CastProof {
        proof: serde_json::Value::Null,
        public: serde_json::Value::Null,
    };
    let report = adjudicate_recorded_as_cast(
        &env.pp,
        &bb,
        &[Some(dummy)],
        &ballot.bytes(),
        |_, _| Ok(false),
    )
    .unwrap();
    assert_eq!(report.verdict, Verdict::Undetermined);
}

#[test]
fn recorded_as_cast_fails_when_absent_without_receipt() {
    let mut env = common::small_election(91);
    let ballot = cast_vote(&env.pp, &env.reg, &env.voters[0], 0, &mut env.rng).unwrap();
    let bb = BulletinBoard::new(); // ballot never posted
    assert!(!check_direct(&bb, &ballot.bytes()));
    let report =
        adjudicate_recorded_as_cast(&env.pp, &bb, &[], &ballot.bytes(), |_, _| Ok(true)).unwrap();
    assert_eq!(report.verdict, Verdict::Undetermined);
    assert!(report.detail.contains("entry absent"));
}

#[test]
fn receipt_identifies_missing_admitted_commitment() {
    // Path 2: the EA admitted the commitment (receipt) but never posted it.
    let mut env = common::small_election(92);
    let ballot = cast_vote(&env.pp, &env.reg, &env.voters[0], 0, &mut env.rng).unwrap();
    let mut state = EaAdmissionState::default();
    let receipt = ea_admit_private(
        &env.pp,
        &env.authority,
        &mut state,
        ballot.com,
        ballot.secret.opening.clone(),
        123456,
        &mut env.rng,
    )
    .unwrap();
    assert!(verify_receipt(&env.pp, &receipt));

    // EA posts an EMPTY admitted board despite the receipt.
    let posted = cr_dr::protocol::bulletin_board::AdmittedBoard::new();
    let report = adjudicate_admission_receipt(&env.pp, &posted, &receipt);
    assert_eq!(report.verdict, Verdict::AuthorityFaulty);

    // Honest posting: complaint unfounded.
    let report2 = adjudicate_admission_receipt(&env.pp, &state.admitted, &receipt);
    assert_eq!(report2.verdict, Verdict::VoterFaulty);
}

#[test]
fn fake_nonce_ballot_receives_identical_receipt() {
    // Coercion-resistance condition: Path-2 admission checks ONLY that the
    // opening opens com, so a fake-nonce ballot gets exactly the same kind
    // of receipt as a real one — the receipt is not a coercion test.
    let mut env = common::small_election(99);
    let coerced = env.voters[0].clone();
    let t = fake_compliance(&env.pp, &coerced, 2, &mut env.rng).unwrap();
    let fake = build_fake_ballot(&env.pp, &t, &mut env.rng).unwrap();
    let real = cast_vote(&env.pp, &env.reg, &coerced, 0, &mut env.rng).unwrap();

    let mut state = EaAdmissionState::default();
    let r1 = ea_admit_private(&env.pp, &env.authority, &mut state, fake.com,
        fake.secret.opening.clone(), 7, &mut env.rng).unwrap();
    let r2 = ea_admit_private(&env.pp, &env.authority, &mut state, real.com,
        real.secret.opening.clone(), 7, &mut env.rng).unwrap();
    assert!(verify_receipt(&env.pp, &r1) && verify_receipt(&env.pp, &r2));
    // Structurally identical receipts (same fields, same signer, same
    // timestamp semantics); both commitments admitted.
    assert!(state.admitted.contains(&fake.com) && state.admitted.contains(&real.com));
    let k1: Vec<_> = serde_json::to_value(&r1).unwrap().as_object().unwrap().keys().cloned().collect();
    let k2: Vec<_> = serde_json::to_value(&r2).unwrap().as_object().unwrap().keys().cloned().collect();
    assert_eq!(k1, k2);
}

#[test]
fn judge_detects_fake_nonce_privately() {
    let mut env = common::small_election(93);
    let coerced = env.voters[0].clone();
    // The coercer files a dispute over the fake-compliance ballot.
    let t = fake_compliance(&env.pp, &coerced, 2, &mut env.rng).unwrap();
    let fake = build_fake_ballot(&env.pp, &t, &mut env.rng).unwrap();
    let (adm, opn) = admitted_from_ballots(&[fake.clone()]);

    let opening = fake.secret.opening.clone();
    let complaint = TalliedAsRecordedComplaint { com: fake.com, opening };
    let r_ea = env.authority.r_ea(coerced.id).unwrap();
    let evidence = AuthorityEvidence {
        nonce_source: NonceSource::Direct(r_ea),
        openings: &opn,
        tally_proof: TallyProofStatus::Verified,
    };
    let report = judge_tallied_as_recorded(&env.pp, &env.reg, &adm, &complaint, &evidence);
    // The judge privately identifies the fake nonce...
    assert_eq!(report.verdict, Verdict::VoterFaulty);
    assert!(report.detail.contains("nonce"));
    // ...the EXTERNALLY releasable verdict is coarsened to NoAuthorityFault,
    // so the dispute outcome cannot serve as a coercer's nonce test...
    assert_eq!(report.external_verdict(), Verdict::NoAuthorityFault);
    // ...and the report never contains R_EA,i itself.
    assert!(!format!("{report:?}").contains(&f_to_dec(&r_ea)));
}

#[test]
fn judge_accepts_valid_first_ballot_with_verifying_proof() {
    let mut env = common::small_election(94);
    let voter = env.voters[0].clone();
    let real = cast_vote(&env.pp, &env.reg, &voter, 0, &mut env.rng).unwrap();
    let (adm, opn) = admitted_from_ballots(&[real.clone()]);

    let opening = real.secret.opening.clone();
    let complaint = TalliedAsRecordedComplaint { com: real.com, opening };
    let evidence = AuthorityEvidence {
        nonce_source: NonceSource::Direct(env.authority.r_ea(voter.id).unwrap()),
        openings: &opn,
        tally_proof: TallyProofStatus::Verified,
    };
    let report = judge_tallied_as_recorded(&env.pp, &env.reg, &adm, &complaint, &evidence);
    assert_eq!(report.verdict, Verdict::NoAuthorityFault); // counted under proof soundness
}

#[test]
fn judge_blames_authority_when_tally_proof_fails() {
    let mut env = common::small_election(95);
    let voter = env.voters[0].clone();
    let real = cast_vote(&env.pp, &env.reg, &voter, 0, &mut env.rng).unwrap();
    let (adm, opn) = admitted_from_ballots(&[real.clone()]);

    let opening = real.secret.opening.clone();
    let complaint = TalliedAsRecordedComplaint { com: real.com, opening };
    let evidence = AuthorityEvidence {
        nonce_source: NonceSource::Direct(env.authority.r_ea(voter.id).unwrap()),
        openings: &opn,
        tally_proof: TallyProofStatus::Invalid,
    };
    let report = judge_tallied_as_recorded(&env.pp, &env.reg, &adm, &complaint, &evidence);
    assert_eq!(report.verdict, Verdict::AuthorityFaulty);
}

#[test]
fn judge_does_not_assume_missing_tally_proof_verifies() {
    // A valid first ballot with NO checkable tally proof must stay
    // Undetermined — the judge must never fail open by assuming the proof
    // would have verified.
    let mut env = common::small_election(98);
    let voter = env.voters[0].clone();
    let real = cast_vote(&env.pp, &env.reg, &voter, 0, &mut env.rng).unwrap();
    let (adm, opn) = admitted_from_ballots(&[real.clone()]);

    let opening = real.secret.opening.clone();
    let complaint = TalliedAsRecordedComplaint { com: real.com, opening };
    let evidence = AuthorityEvidence {
        nonce_source: NonceSource::Direct(env.authority.r_ea(voter.id).unwrap()),
        openings: &opn,
        tally_proof: TallyProofStatus::Unavailable,
    };
    let report = judge_tallied_as_recorded(&env.pp, &env.reg, &adm, &complaint, &evidence);
    assert_eq!(report.verdict, Verdict::Undetermined);
    assert!(report.detail.contains("no tally proof"));
}

#[test]
fn judge_works_with_threshold_share_reconstruction() {
    let mut env = common::small_election(96);
    share_all_nonces(&mut env.authority, ThresholdParams { t: 3, k: 5 }, &mut env.rng).unwrap();
    let voter = env.voters[0].clone();
    let real = cast_vote(&env.pp, &env.reg, &voter, 1, &mut env.rng).unwrap();
    let (adm, opn) = admitted_from_ballots(&[real.clone()]);

    // Judge receives t = 3 shares (not the nonce itself, and not from the voter).
    let shares = env.authority.voter_secrets[&voter.id].r_ea_shares[0..3].to_vec();
    let opening = real.secret.opening.clone();
    let complaint = TalliedAsRecordedComplaint { com: real.com, opening };
    let evidence = AuthorityEvidence {
        nonce_source: NonceSource::ThresholdShares(shares),
        openings: &opn,
        tally_proof: TallyProofStatus::Verified,
    };
    let report = judge_tallied_as_recorded(&env.pp, &env.reg, &adm, &complaint, &evidence);
    assert_eq!(report.verdict, Verdict::NoAuthorityFault); // valid + counted
}

#[test]
fn judge_rejects_fabricated_prior_opening() {
    // Fault-soundness hardening: the judge RECOMPUTES the duplicate
    // predicate from the openings store; a lying authority that hands the
    // judge a wrong opening for a prior slot (e.g. to hide an earlier
    // valid ballot) is caught by commitment binding.
    let mut env = common::small_election(101);
    let voter = env.voters[0].clone();
    let b1 = cast_vote(&env.pp, &env.reg, &voter, 0, &mut env.rng).unwrap();
    let b2 = cast_vote(&env.pp, &env.reg, &voter, 2, &mut env.rng).unwrap();
    let (adm, mut opn) = admitted_from_ballots(&[b1, b2.clone()]);
    // authority "loses" the true opening of slot 0 and substitutes garbage
    opn.openings[0].rho += cr_dr::types::F::from(1u64);

    let complaint =
        TalliedAsRecordedComplaint { com: b2.com, opening: b2.secret.opening.clone() };
    let evidence = AuthorityEvidence {
        nonce_source: NonceSource::Direct(env.authority.r_ea(voter.id).unwrap()),
        openings: &opn,
        tally_proof: TallyProofStatus::Verified,
    };
    let report = judge_tallied_as_recorded(&env.pp, &env.reg, &adm, &complaint, &evidence);
    assert_eq!(report.verdict, Verdict::AuthorityFaulty);
    assert!(report.detail.contains("does not open"));
}

#[test]
fn judge_flags_duplicate_complaints_correctly() {
    let mut env = common::small_election(97);
    let voter = env.voters[0].clone();
    let b1 = cast_vote(&env.pp, &env.reg, &voter, 0, &mut env.rng).unwrap();
    let b2 = cast_vote(&env.pp, &env.reg, &voter, 2, &mut env.rng).unwrap();
    let (adm, opn) = admitted_from_ballots(&[b1.clone(), b2.clone()]);

    let opening = b2.secret.opening.clone();
    let complaint = TalliedAsRecordedComplaint { com: b2.com, opening };
    let evidence = AuthorityEvidence {
        nonce_source: NonceSource::Direct(env.authority.r_ea(voter.id).unwrap()),
        openings: &opn,
        tally_proof: TallyProofStatus::Verified,
    };
    let report = judge_tallied_as_recorded(&env.pp, &env.reg, &adm, &complaint, &evidence);
    assert_eq!(report.verdict, Verdict::VoterFaulty);
    assert!(report.detail.contains("earlier valid ballot"));
}
