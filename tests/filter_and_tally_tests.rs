mod common;

use cr_dr::protocol::admission::admitted_from_ballots;

use ark_ff::UniformRand;
use cr_dr::crypto::hash::sig_msg_hash;
use cr_dr::crypto::signature::sign;
use cr_dr::protocol::filter_and_tally::filter_and_tally;
use cr_dr::protocol::vote::cast_vote;
use cr_dr::types::{Ballot, BallotPlaintext, F, InternalBallotStatus, VoterState};

fn ballot_from_plaintext(pt: &BallotPlaintext, env: &common::Env, rng: &mut rand_chacha::ChaCha20Rng) -> Ballot {
    cr_dr::protocol::vote::seal_ballot(&env.pp, pt, rng).unwrap()
}

fn signed_plaintext(
    env: &common::Env,
    voter: &VoterState,
    candidate: u64,
    r: F,
    rng: &mut rand_chacha::ChaCha20Rng,
) -> BallotPlaintext {
    let msg = sig_msg_hash(env.pp.eid_hash, voter.id, candidate, r);
    BallotPlaintext {
        eid_hash: env.pp.eid_hash,
        id: voter.id,
        vk: voter.vk,
        candidate,
        r,
        sigma: sign(&voter.sk, msg, rng),
    }
}

#[test]
fn inconsistent_entry_is_a_hard_error_not_soft_invalid() {
    // CAST-ZK: an entry whose ct_open does not decrypt to the committed
    // opening cannot exist on a pi_cast-verified board. Tallying such an
    // entry is a HARD error (the tally circuit hard-opens com), never a
    // silent soft-invalid.
    let mut env = common::small_election(50);
    let ballot = cast_vote(&env.pp, &env.reg, &env.voters[0], 0, &mut env.rng).unwrap();
    let mut entry = ballot.public();
    entry.com += cr_dr::types::F::from(1u64); // com no longer matches ct_open
    assert!(filter_and_tally(&env.pp, &env.authority, &env.reg, &cr_dr::protocol::bulletin_board::AdmittedBoard { coms: vec![entry.com] }, &cr_dr::protocol::admission::AdmittedOpenings { openings: vec![ballot.secret.opening.clone()] }).is_err());
}

#[test]
fn invalid_candidate_rejected() {
    let mut env = common::small_election(51);
    let voter = env.voters[0].clone();
    let mut rng = env.rng.clone();
    let pt = signed_plaintext(&env, &voter, 99, voter.r, &mut rng); // 99 not in C
    let ballot = ballot_from_plaintext(&pt, &env, &mut rng);
    let (_, evals) = { let (adm, opn) = admitted_from_ballots(&[ballot.clone()]); filter_and_tally(&env.pp, &env.authority, &env.reg, &adm, &opn) }.unwrap();
    assert_eq!(evals[0].status, InternalBallotStatus::InvalidCandidate);
}

#[test]
fn invalid_signature_rejected() {
    let mut env = common::small_election(52);
    let voter = env.voters[0].clone();
    let mut rng = env.rng.clone();
    let mut pt = signed_plaintext(&env, &voter, 1, voter.r, &mut rng);
    pt.sigma.s += F::from(1u64); // break the signature
    let ballot = ballot_from_plaintext(&pt, &env, &mut rng);
    let (_, evals) = { let (adm, opn) = admitted_from_ballots(&[ballot.clone()]); filter_and_tally(&env.pp, &env.authority, &env.reg, &adm, &opn) }.unwrap();
    assert_eq!(evals[0].status, InternalBallotStatus::InvalidSignature);
}

#[test]
fn signature_by_wrong_key_rejected() {
    let mut env = common::small_election(53);
    let voter0 = env.voters[0].clone();
    let voter1 = env.voters[1].clone();
    let mut rng = env.rng.clone();
    // voter1 signs, but the ballot claims voter0's identity/vk.
    let msg = sig_msg_hash(env.pp.eid_hash, voter0.id, 1, voter0.r);
    let pt = BallotPlaintext {
        eid_hash: env.pp.eid_hash,
        id: voter0.id,
        vk: voter0.vk,
        candidate: 1,
        r: voter0.r,
        sigma: sign(&voter1.sk, msg, &mut rng),
    };
    let ballot = ballot_from_plaintext(&pt, &env, &mut rng);
    let (_, evals) = { let (adm, opn) = admitted_from_ballots(&[ballot.clone()]); filter_and_tally(&env.pp, &env.authority, &env.reg, &adm, &opn) }.unwrap();
    assert_eq!(evals[0].status, InternalBallotStatus::InvalidSignature);
}

#[test]
fn wrong_nonce_rejected_as_invalid_registration() {
    let mut env = common::small_election(54);
    let voter = env.voters[0].clone();
    let mut rng = env.rng.clone();
    let wrong_r = F::rand(&mut rng);
    let pt = signed_plaintext(&env, &voter, 1, wrong_r, &mut rng);
    let ballot = ballot_from_plaintext(&pt, &env, &mut rng);
    let (_, evals) = { let (adm, opn) = admitted_from_ballots(&[ballot.clone()]); filter_and_tally(&env.pp, &env.authority, &env.reg, &adm, &opn) }.unwrap();
    assert_eq!(evals[0].status, InternalBallotStatus::InvalidRegistration);
}

#[test]
fn wrong_eid_rejected_as_invalid_format() {
    let mut env = common::small_election(55);
    let voter = env.voters[0].clone();
    let mut rng = env.rng.clone();
    let mut pt = signed_plaintext(&env, &voter, 1, voter.r, &mut rng);
    pt.eid_hash += F::from(1u64);
    let ballot = ballot_from_plaintext(&pt, &env, &mut rng);
    let (_, evals) = { let (adm, opn) = admitted_from_ballots(&[ballot.clone()]); filter_and_tally(&env.pp, &env.authority, &env.reg, &adm, &opn) }.unwrap();
    assert_eq!(evals[0].status, InternalBallotStatus::InvalidFormat);
}

#[test]
fn duplicate_valid_ballot_ignored() {
    let mut env = common::small_election(56);
    let voter = env.voters[0].clone();
    let b1 = cast_vote(&env.pp, &env.reg, &voter, 0, &mut env.rng).unwrap();
    let b2 = cast_vote(&env.pp, &env.reg, &voter, 2, &mut env.rng).unwrap();
    let (tally, evals) =
        { let (adm, opn) = admitted_from_ballots(&[b1.clone(), b2.clone()]); filter_and_tally(&env.pp, &env.authority, &env.reg, &adm, &opn) }.unwrap();
    assert_eq!(evals[0].status, InternalBallotStatus::Counted);
    assert_eq!(evals[1].status, InternalBallotStatus::DuplicateValidBallot);
    assert_eq!(tally.counts, vec![1, 0, 0]); // first valid counts
}

#[test]
fn empty_board_gives_zero_tally() {
    let env = common::small_election(57);
    let (tally, evals) = filter_and_tally(&env.pp, &env.authority, &env.reg, &Default::default(), &Default::default()).unwrap();
    assert_eq!(tally.counts, vec![0, 0, 0]);
    assert!(evals.is_empty());
}
