mod common;

use cr_dr::crypto::hash::{h_com, h_reg};
use cr_dr::crypto::merkle::verify_path;
use cr_dr::protocol::preprocessing::{
    estimate_cut_and_choose_soundness, finalize_registration, preprocess_voter,
    preprocess_voter_cut_and_choose, preprocess_voter_cut_and_choose_with_cheat,
};
use cr_dr::protocol::setup::setup_election;

#[test]
fn voter_receives_sk_and_r_but_not_r_ea() {
    let mut env = common::small_election(10);
    let (vs, _rec) = preprocess_voter(&env.pp, &mut env.authority, 7, &mut env.rng).unwrap();
    let secret = &env.authority.voter_secrets[&7];
    // The voter's R matches the authority record.
    assert_eq!(vs.r, secret.r);
    // R_EA exists on the authority side and differs from everything the
    // voter holds. (VoterState has no r_ea field at all — the strongest
    // guarantee is structural; here we check the values are independent.)
    assert_ne!(secret.r_ea, vs.r);
    assert_ne!(secret.r_ea, cr_dr::types::F::from(vs.id));
}

#[test]
fn public_record_commitments_are_correct() {
    let mut env = common::small_election(11);
    let (vs, rec) = preprocess_voter(&env.pp, &mut env.authority, 7, &mut env.rng).unwrap();
    let secret = &env.authority.voter_secrets[&7];
    let h = h_com(env.pp.eid_hash, 7, &vs.vk, vs.r, secret.r_ea);
    assert_eq!(rec.h, h);
    assert_eq!(rec.leaf, h_reg(env.pp.eid_hash, 7, &vs.vk, h));
}

#[test]
fn merkle_root_verifies_all_leaves() {
    let env = common::small_election(12);
    for rec in env.reg.records.values() {
        let path = &env.reg.paths[&rec.id];
        assert!(verify_path(env.reg.root, rec.leaf, path));
    }
}

#[test]
fn duplicate_voter_id_rejected_in_preprocessing() {
    let mut env = common::small_election(13);
    assert!(preprocess_voter(&env.pp, &mut env.authority, 0, &mut env.rng).is_err());
}

#[test]
fn duplicate_voter_id_rejected_in_finalization() {
    let mut rng = common::rng(14);
    let (pp, mut authority) = setup_election(common::config(), &mut rng).unwrap();
    let (_v1, rec1) = preprocess_voter(&pp, &mut authority, 0, &mut rng).unwrap();
    let mut rec2 = rec1.clone();
    rec2.id = 0;
    assert!(finalize_registration(&pp, &[rec1, rec2]).is_err());
}

#[test]
fn cut_and_choose_honest_registration_works() {
    let mut rng = common::rng(15);
    let (pp, mut authority) = setup_election(common::config(), &mut rng).unwrap();
    let (vs, rec, transcript) =
        preprocess_voter_cut_and_choose(&pp, &mut authority, 3, 8, &mut rng).unwrap();
    assert_eq!(transcript.q, 8);
    assert_eq!(transcript.opened.len(), 7);
    // Final pair is consistent with the published record.
    let secret = &authority.voter_secrets[&3];
    assert_eq!(rec.h, h_com(pp.eid_hash, 3, &vs.vk, vs.r, secret.r_ea));
}

#[test]
fn cut_and_choose_detects_cheating_when_corrupted_pair_is_audited() {
    // With q = 4 and one corrupted pair, ~3/4 of runs must abort with
    // evidence; a run survives only if the corrupted pair is the final one.
    let mut detected = 0;
    let mut survived = 0;
    for seed in 0..200u64 {
        let mut rng = common::rng(1000 + seed);
        let (pp, mut authority) = setup_election(common::config(), &mut rng).unwrap();
        match preprocess_voter_cut_and_choose_with_cheat(&pp, &mut authority, 3, 4, 0, &mut rng)
        {
            Err(_) => detected += 1,
            Ok(_) => survived += 1,
        }
    }
    assert!(detected > 0 && survived > 0);
    let survival_rate = survived as f64 / 200.0;
    assert!((survival_rate - 0.25).abs() < 0.12, "survival {survival_rate} !~ 1/q = 0.25");
}

#[test]
fn cut_and_choose_soundness_estimate_is_about_one_over_q() {
    let mut rng = common::rng(16);
    for q in [2usize, 4, 8] {
        let est = estimate_cut_and_choose_soundness(q, 20_000, &mut rng);
        let expect = 1.0 / q as f64;
        assert!((est - expect).abs() < 0.02, "q={q}: {est} !~ {expect}");
    }
}
