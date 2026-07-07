mod common;

use cr_dr::crypto::hash::{h_com, h_reg};
use cr_dr::crypto::merkle::verify_path;
use cr_dr::protocol::preprocessing::{
    estimate_cut_and_choose_soundness, finalize_registration, preprocess_voter,
    preprocess_voter_cut_and_choose, preprocess_voter_cut_and_choose_with_cheat,
};
use cr_dr::protocol::setup::setup_election;

#[test]
fn voter_state_cannot_carry_r_ea() {
    // Structural: VoterState = (id, sk, vk, R_i) and nothing else. The
    // serialized form is the exhaustive field list — no slot exists for
    // R_EA,i or any share of it.
    let mut env = common::small_election(10);
    let (vs, _rec) = preprocess_voter(&env.pp, &mut env.authority, 7, &mut env.rng).unwrap();
    let json = serde_json::to_value(&vs).unwrap();
    let mut keys: Vec<&str> =
        json.as_object().unwrap().keys().map(|s| s.as_str()).collect();
    keys.sort_unstable();
    assert_eq!(keys, ["id", "r", "sk", "vk"]);
    // And the voter's R_i is independent of the authority-side nonce.
    let r_ea = env.authority.r_ea(7).unwrap();
    assert_ne!(r_ea, vs.r);
}

#[test]
fn authority_state_cannot_recover_r_i() {
    // Structural: the authority's per-voter record holds only (id, vk,
    // R_EA-shares). Its serialized form contains no field for R_i, and the
    // voter's actual R_i value appears nowhere in the whole serialized
    // authority state.
    let mut env = common::small_election(11);
    let (vs, _rec) = preprocess_voter(&env.pp, &mut env.authority, 7, &mut env.rng).unwrap();
    let secret_json = serde_json::to_value(&env.authority.voter_secrets[&7]).unwrap();
    let mut keys: Vec<&str> =
        secret_json.as_object().unwrap().keys().map(|s| s.as_str()).collect();
    keys.sort_unstable();
    assert_eq!(keys, ["id", "r_ea_shares", "vk"]);
    let full_state = serde_json::to_string(&env.authority).unwrap();
    assert!(!full_state.contains(&cr_dr::types::f_to_dec(&vs.r)));
}

#[test]
fn below_threshold_shares_cannot_reconstruct_r_ea() {
    // With threshold params (t=3, k=5), any t-1 shares interpolate to a
    // value unrelated to R_EA,i; only >= t (the authorized quorum) recover it.
    let mut rng = common::rng(19);
    let mut cfg = common::config();
    cfg.threshold_params = Some(cr_dr::types::ThresholdParams { t: 3, k: 5 });
    let (pp, mut authority) =
        cr_dr::protocol::setup::setup_election(cfg, &mut rng).unwrap();
    let (_vs, _rec) = preprocess_voter(&pp, &mut authority, 0, &mut rng).unwrap();

    let shares = &authority.voter_secrets[&0].r_ea_shares;
    assert_eq!(shares.len(), 5);
    let authorized = authority.r_ea(0).unwrap();
    let below_threshold =
        cr_dr::crypto::shamir::reconstruct(&shares[0..2]).unwrap();
    assert_ne!(below_threshold, authorized);
    assert_eq!(
        cr_dr::crypto::shamir::reconstruct(&shares[1..4]).unwrap(),
        authorized
    );
}

#[test]
fn public_record_commitments_are_correct() {
    let mut env = common::small_election(11);
    let (vs, rec) = preprocess_voter(&env.pp, &mut env.authority, 7, &mut env.rng).unwrap();
    // The authorized quorum reconstruction yields the R_EA that h commits to.
    let r_ea = env.authority.r_ea(7).unwrap();
    let h = h_com(env.pp.eid_hash, 7, &vs.vk, vs.r, r_ea);
    assert_eq!(rec.h, h);
    assert_eq!(rec.leaf, h_reg(env.pp.eid_hash, 7, &vs.vk, h));
}

#[test]
fn registration_ids_must_be_dense_for_the_indexed_table() {
    // The table is indexed: id = leaf index, so ids must be exactly 0..N-1.
    let mut rng = common::rng(20);
    let (pp, mut authority) =
        cr_dr::protocol::setup::setup_election(common::config(), &mut rng).unwrap();
    let (_v0, rec0) = preprocess_voter(&pp, &mut authority, 0, &mut rng).unwrap();
    let (_v2, rec2) = preprocess_voter(&pp, &mut authority, 2, &mut rng).unwrap();
    // Gap at id 1: finalization must reject.
    assert!(finalize_registration(&pp, &[rec0.clone(), rec2]).is_err());
    // Dense 0..1 works.
    let (_v1, rec1) = preprocess_voter(&pp, &mut authority, 1, &mut rng).unwrap();
    let reg = finalize_registration(&pp, &[rec0, rec1]).unwrap();
    assert_eq!(reg.num_voters(), 2);
    assert_eq!(reg.leaf_index[&0], 0);
    assert_eq!(reg.leaf_index[&1], 1);
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
    // Final pair is consistent with the published record (authorized
    // quorum reconstruction of the threshold-shared R_EA).
    let r_ea = authority.r_ea(3).unwrap();
    assert_eq!(rec.h, h_com(pp.eid_hash, 3, &vs.vk, vs.r, r_ea));
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
