//! Circuit-safety requirement: the tally proof must remain TOTAL over all
//! admitted commitments.
//!
//! After public admission, every admitted commitment has SOME opening, but
//! that opening may contain malformed user-controlled fields: off-curve vk,
//! off-curve signature point, non-canonical signature scalar, invalid
//! candidate. The rule:
//!
//!   * HARD check: com = H_ballot_com(opening, r_com)  (admission implies
//!     an opening exists, so this is always satisfiable for the prover);
//!   * every semantic validity check after that must be SOFT — the row's
//!     valid flag becomes 0, the witness NEVER becomes unsatisfiable —
//!     unless the property is already guaranteed by cast-ZK.
//!
//! Each test here (a) crafts a malformed-but-openable admitted entry,
//! (b) checks the native tally classifies it invalid without erroring, and
//! (c) checks the native relation (the constraint-for-constraint circuit
//! mirror) STILL ACCEPTS the honest witness — i.e. no user-controlled
//! opening can make the whole tally proof impossible. A final test proves
//! a poisoned board with the REAL small Groth16 circuit.

mod common;

use cr_dr::crypto::hash::sig_msg_hash;
use cr_dr::crypto::signature::{sign, subgroup_order_as_field, VerificationKey};
use cr_dr::protocol::admission::{admitted_from_ballots, ea_admit_private, EaAdmissionState};
use cr_dr::protocol::chaff::chaff_ballot;
use cr_dr::protocol::fake_compliance::{build_fake_ballot, fake_compliance};
use cr_dr::protocol::filter_and_tally::filter_and_tally;
use cr_dr::protocol::vote::{cast_vote, seal_ballot};
use cr_dr::types::{Ballot, BallotPlaintext, F, InternalBallotStatus, VoterState};
use cr_dr::zk::mock_backend::relation_check_native;
use cr_dr::zk::statement::build_tally_statement;
use cr_dr::zk::witness::build_tally_witness;
use cr_dr::zk::SMALL_SHAPE;

/// An honestly signed plaintext for `voter`, before poisoning.
fn signed_plaintext(
    env: &common::Env,
    voter: &VoterState,
    candidate: u64,
    rng: &mut rand_chacha::ChaCha20Rng,
) -> BallotPlaintext {
    let msg = sig_msg_hash(env.pp.eid_hash, voter.id, candidate, voter.r);
    BallotPlaintext {
        eid_hash: env.pp.eid_hash,
        id: voter.id,
        vk: voter.vk,
        candidate,
        r: voter.r,
        sigma: sign(&voter.sk, msg, rng),
    }
}

/// Board = [honest vote for candidate 0, poisoned ballot, chaff]. Asserts:
/// admission accepts the poisoned entry, the native tally classifies it
/// with `expected_status` (no hard error), the honest vote still counts,
/// and the native relation accepts the witness (the proof stays possible).
fn assert_no_dos(mut env: common::Env, poisoned: BallotPlaintext, expected_status: InternalBallotStatus) {
    let honest = cast_vote(&env.pp, &env.reg, &env.voters[1], 0, &mut env.rng).unwrap();
    let bad: Ballot = seal_ballot(&env.pp, &poisoned, &mut env.rng).unwrap();
    let chaff = chaff_ballot(&env.pp, &mut env.rng).unwrap();

    // The poisoned entry is ADMISSIBLE: its opening opens its commitment,
    // which is all Path-2 admission (and pi_cast on Path 1) certifies.
    let mut state = EaAdmissionState::default();
    ea_admit_private(
        &env.pp,
        &env.authority,
        &mut state,
        bad.com,
        bad.secret.opening.clone(),
        7,
        &mut env.rng,
    )
    .expect("malformed-but-openable submissions are admitted");

    let ballots = vec![honest, bad, chaff];
    let (admitted, openings) = admitted_from_ballots(&ballots);

    let (tally, evals) = filter_and_tally(&env.pp, &env.authority, &env.reg, &admitted, &openings)
        .expect("tally must be total over admitted commitments");
    assert_eq!(evals[1].status, expected_status, "poisoned ballot status");
    assert_eq!(tally.counts, vec![1, 0, 0], "only the honest vote counts");

    let statement = build_tally_statement(&env.pp, &admitted, &env.reg, &tally);
    let witness = build_tally_witness(&env.pp, &env.authority, &env.reg, &admitted, &openings)
        .expect("witness construction must be total");
    assert!(
        relation_check_native(&statement, &witness, &SMALL_SHAPE),
        "the tally proof must remain satisfiable with the poisoned entry on board"
    );
}

#[test]
fn off_curve_vk_does_not_dos_tally() {
    let env = common::small_election(90);
    let voter = env.voters[0].clone();
    let mut rng = env.rng.clone();
    let mut pt = signed_plaintext(&env, &voter, 1, &mut rng);
    pt.vk = VerificationKey { x: F::from(1u64), y: F::from(2u64) }; // off-curve
    assert_no_dos(env, pt, InternalBallotStatus::InvalidSignature);
}

#[test]
fn off_curve_sig_r_does_not_dos_tally() {
    let env = common::small_election(91);
    let voter = env.voters[0].clone();
    let mut rng = env.rng.clone();
    let mut pt = signed_plaintext(&env, &voter, 1, &mut rng);
    pt.sigma.rx = F::from(1u64); // (1, 2) is not on BabyJubJub
    pt.sigma.ry = F::from(2u64);
    assert_no_dos(env, pt, InternalBallotStatus::InvalidSignature);
}

#[test]
fn oversized_sig_s_does_not_dos_tally() {
    let env = common::small_election(92);
    let voter = env.voters[0].clone();
    let mut rng = env.rng.clone();
    let mut pt = signed_plaintext(&env, &voter, 1, &mut rng);
    pt.sigma.s = -F::from(1u64); // p-1: high bits set, far above l
    assert_no_dos(env, pt, InternalBallotStatus::InvalidSignature);
}

#[test]
fn malleated_non_canonical_sig_s_does_not_dos_tally() {
    // THE canonicity regression: s+l satisfies the curve equation
    // ((s+l)*Base8 = s*Base8) and stays below 2^251, so a voter could
    // malleate her own VALID signature into a non-canonical one. Circuit
    // and native verifier must both reject it (valid=0) — if they
    // disagreed, the public tally would contradict the circuit's validity
    // bit and the proof would be unsatisfiable (a voter-triggered DoS).
    let env = common::small_election(93);
    let voter = env.voters[0].clone();
    let mut rng = env.rng.clone();
    let mut pt = signed_plaintext(&env, &voter, 1, &mut rng);
    pt.sigma.s += subgroup_order_as_field();
    assert_no_dos(env, pt, InternalBallotStatus::InvalidSignature);
}

#[test]
fn invalid_candidate_does_not_dos_tally() {
    let env = common::small_election(94);
    let voter = env.voters[0].clone();
    let mut rng = env.rng.clone();
    let pt = signed_plaintext(&env, &voter, 99, &mut rng); // 99 not in C
    assert_no_dos(env, pt, InternalBallotStatus::InvalidCandidate);
}

#[test]
fn fake_and_chaff_are_admitted_but_privately_rejected() {
    // Fake-compliance and chaff ballots MUST pass admission (that is the
    // coercion-resistance condition) and be rejected only inside the
    // private tally relation.
    let mut env = common::small_election(95);
    let coerced = env.voters[0].clone();
    let t = fake_compliance(&env.pp, &coerced, 2, &mut env.rng).unwrap();
    let fake = build_fake_ballot(&env.pp, &t, &mut env.rng).unwrap();
    let chaff = chaff_ballot(&env.pp, &mut env.rng).unwrap();
    let honest = cast_vote(&env.pp, &env.reg, &env.voters[1], 1, &mut env.rng).unwrap();

    let mut state = EaAdmissionState::default();
    for b in [&fake, &chaff, &honest] {
        ea_admit_private(
            &env.pp,
            &env.authority,
            &mut state,
            b.com,
            b.secret.opening.clone(),
            9,
            &mut env.rng,
        )
        .expect("fake/chaff/honest all pass admission");
    }

    let (tally, evals) =
        filter_and_tally(&env.pp, &env.authority, &env.reg, &state.admitted, &state.openings)
            .unwrap();
    assert_eq!(tally.counts, vec![0, 1, 0], "only the honest ballot counts");
    assert_ne!(evals[0].status, InternalBallotStatus::Counted, "fake rejected privately");
    assert_ne!(evals[1].status, InternalBallotStatus::Counted, "chaff rejected privately");
    assert_eq!(evals[2].status, InternalBallotStatus::Counted);

    let statement = build_tally_statement(&env.pp, &state.admitted, &env.reg, &tally);
    let witness =
        build_tally_witness(&env.pp, &env.authority, &env.reg, &state.admitted, &state.openings)
            .unwrap();
    assert!(relation_check_native(&statement, &witness, &SMALL_SHAPE));
}

#[test]
fn poisoned_board_proves_with_real_groth16_circuit() {
    // One board containing ALL four malformed-opening classes plus honest
    // votes, proven with the REAL small circuit: the poison rows become
    // valid=0 and the proof succeeds. Skips if artifacts are missing.
    use cr_dr::zk::circom_io::generate_witness_input;
    use cr_dr::zk::groth16_backend::SnarkjsBackend;

    let b = SnarkjsBackend::small(SnarkjsBackend::crate_root());
    if !b.toolchain_available() {
        eprintln!("SKIP: groth16 artifacts not found");
        return;
    }

    let mut env = common::small_election(96);
    let mut rng = env.rng.clone();
    let poisons: Vec<BallotPlaintext> = {
        let mut v = Vec::new();
        let mut pt = signed_plaintext(&env, &env.voters[0].clone(), 1, &mut rng);
        pt.vk = VerificationKey { x: F::from(1u64), y: F::from(2u64) };
        v.push(pt);
        let mut pt = signed_plaintext(&env, &env.voters[1].clone(), 1, &mut rng);
        pt.sigma.rx = F::from(1u64);
        pt.sigma.ry = F::from(2u64);
        v.push(pt);
        let mut pt = signed_plaintext(&env, &env.voters[2].clone(), 1, &mut rng);
        pt.sigma.s += subgroup_order_as_field();
        v.push(pt);
        v.push(signed_plaintext(&env, &env.voters[3].clone(), 99, &mut rng));
        v
    };
    let mut ballots: Vec<Ballot> = poisons
        .iter()
        .map(|pt| seal_ballot(&env.pp, pt, &mut rng).unwrap())
        .collect();
    ballots.push(cast_vote(&env.pp, &env.reg, &env.voters[4].clone(), 0, &mut env.rng).unwrap());
    ballots.push(cast_vote(&env.pp, &env.reg, &env.voters[5].clone(), 2, &mut env.rng).unwrap());

    let (admitted, openings) = admitted_from_ballots(&ballots);
    let (tally, _) =
        filter_and_tally(&env.pp, &env.authority, &env.reg, &admitted, &openings).unwrap();
    assert_eq!(tally.counts, vec![1, 0, 1], "only the two honest votes count");

    let statement = build_tally_statement(&env.pp, &admitted, &env.reg, &tally);
    let witness =
        build_tally_witness(&env.pp, &env.authority, &env.reg, &admitted, &openings).unwrap();
    assert!(relation_check_native(&statement, &witness, &SMALL_SHAPE));

    let input = generate_witness_input(&statement, &witness, &SMALL_SHAPE).unwrap();
    let (proof, public) = b.prove(&input).expect("poisoned board must still prove");
    assert!(b.verify(&proof, &public).unwrap());
}
