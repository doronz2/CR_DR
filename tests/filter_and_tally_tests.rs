mod common;

use ark_ff::UniformRand;
use cr_dr::crypto::encryption::{commit_encrypt, opening_to_payload};
use cr_dr::crypto::hash::sig_msg_hash;
use cr_dr::crypto::signature::sign;
use cr_dr::protocol::filter_and_tally::filter_and_tally;
use cr_dr::protocol::vote::cast_vote;
use cr_dr::types::{Ballot, BallotPlaintext, F, InternalBallotStatus, VoterState};

fn ballot_from_plaintext(pt: &BallotPlaintext, rng: &mut rand_chacha::ChaCha20Rng) -> Ballot {
    let (ciphertext, opening) = commit_encrypt(&pt.to_fields(), rng);
    Ballot { ciphertext, ea_payload: opening_to_payload(&opening) }
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
fn invalid_decryption_rejected() {
    let mut env = common::small_election(50);
    let mut ballot = cast_vote(&env.pp, &env.reg, &env.voters[0], 0, &mut env.rng).unwrap();
    ballot.ea_payload[10] ^= 0xFF; // corrupt the opening payload
    let (tally, evals) = filter_and_tally(&env.pp, &env.authority, &env.reg, &[ballot]).unwrap();
    assert_eq!(evals[0].status, InternalBallotStatus::InvalidDecryption);
    assert_eq!(tally.counted_ballots, 0);
}

#[test]
fn invalid_candidate_rejected() {
    let mut env = common::small_election(51);
    let voter = env.voters[0].clone();
    let mut rng = env.rng.clone();
    let pt = signed_plaintext(&env, &voter, 99, voter.r, &mut rng); // 99 not in C
    let ballot = ballot_from_plaintext(&pt, &mut rng);
    let (_, evals) = filter_and_tally(&env.pp, &env.authority, &env.reg, &[ballot]).unwrap();
    assert_eq!(evals[0].status, InternalBallotStatus::InvalidCandidate);
}

#[test]
fn invalid_signature_rejected() {
    let mut env = common::small_election(52);
    let voter = env.voters[0].clone();
    let mut rng = env.rng.clone();
    let mut pt = signed_plaintext(&env, &voter, 1, voter.r, &mut rng);
    pt.sigma.s += F::from(1u64); // break the signature
    let ballot = ballot_from_plaintext(&pt, &mut rng);
    let (_, evals) = filter_and_tally(&env.pp, &env.authority, &env.reg, &[ballot]).unwrap();
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
    let ballot = ballot_from_plaintext(&pt, &mut rng);
    let (_, evals) = filter_and_tally(&env.pp, &env.authority, &env.reg, &[ballot]).unwrap();
    assert_eq!(evals[0].status, InternalBallotStatus::InvalidSignature);
}

#[test]
fn wrong_nonce_rejected_as_invalid_registration() {
    let mut env = common::small_election(54);
    let voter = env.voters[0].clone();
    let mut rng = env.rng.clone();
    let wrong_r = F::rand(&mut rng);
    let pt = signed_plaintext(&env, &voter, 1, wrong_r, &mut rng);
    let ballot = ballot_from_plaintext(&pt, &mut rng);
    let (_, evals) = filter_and_tally(&env.pp, &env.authority, &env.reg, &[ballot]).unwrap();
    assert_eq!(evals[0].status, InternalBallotStatus::InvalidRegistration);
}

#[test]
fn wrong_eid_rejected_as_invalid_format() {
    let mut env = common::small_election(55);
    let voter = env.voters[0].clone();
    let mut rng = env.rng.clone();
    let mut pt = signed_plaintext(&env, &voter, 1, voter.r, &mut rng);
    pt.eid_hash += F::from(1u64);
    let ballot = ballot_from_plaintext(&pt, &mut rng);
    let (_, evals) = filter_and_tally(&env.pp, &env.authority, &env.reg, &[ballot]).unwrap();
    assert_eq!(evals[0].status, InternalBallotStatus::InvalidFormat);
}

#[test]
fn duplicate_valid_ballot_ignored() {
    let mut env = common::small_election(56);
    let voter = env.voters[0].clone();
    let b1 = cast_vote(&env.pp, &env.reg, &voter, 0, &mut env.rng).unwrap();
    let b2 = cast_vote(&env.pp, &env.reg, &voter, 2, &mut env.rng).unwrap();
    let (tally, evals) =
        filter_and_tally(&env.pp, &env.authority, &env.reg, &[b1, b2]).unwrap();
    assert_eq!(evals[0].status, InternalBallotStatus::Counted);
    assert_eq!(evals[1].status, InternalBallotStatus::DuplicateValidBallot);
    assert_eq!(tally.counts, vec![1, 0, 0]); // first valid counts
}

#[test]
fn empty_board_gives_zero_tally() {
    let env = common::small_election(57);
    let (tally, evals) = filter_and_tally(&env.pp, &env.authority, &env.reg, &[]).unwrap();
    assert_eq!(tally.counts, vec![0, 0, 0]);
    assert!(evals.is_empty());
}
