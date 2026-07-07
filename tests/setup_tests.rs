mod common;

use cr_dr::crypto::hash::eid_to_field;
use cr_dr::protocol::setup::setup_election;
use cr_dr::types::ThresholdParams;

#[test]
fn setup_produces_consistent_public_params() {
    let mut rng = common::rng(1);
    let (pp, authority) = setup_election(common::config(), &mut rng).unwrap();
    assert_eq!(pp.eid_hash, eid_to_field(&pp.eid));
    assert_eq!(pp.candidates, common::CANDIDATES.to_vec());
    assert_eq!(pp.duplicate_rule.id(), 1);
    assert!(authority.voter_secrets.is_empty());
    assert_eq!(authority.threshold, cr_dr::types::ThresholdParams::single());
}

#[test]
fn setup_rejects_empty_candidates() {
    let mut rng = common::rng(2);
    let mut cfg = common::config();
    cfg.candidates.clear();
    assert!(setup_election(cfg, &mut rng).is_err());
}

#[test]
fn setup_rejects_duplicate_candidates() {
    let mut rng = common::rng(3);
    let mut cfg = common::config();
    cfg.candidates = vec![0, 1, 1];
    assert!(setup_election(cfg, &mut rng).is_err());
}

#[test]
fn setup_rejects_max_voters_beyond_tree_capacity() {
    let mut rng = common::rng(4);
    let mut cfg = common::config();
    cfg.max_voters = 17; // 2^4 = 16
    assert!(setup_election(cfg, &mut rng).is_err());
}

#[test]
fn setup_rejects_bad_threshold_params() {
    let mut rng = common::rng(5);
    let mut cfg = common::config();
    cfg.threshold_params = Some(ThresholdParams { t: 4, k: 3 });
    assert!(setup_election(cfg, &mut rng).is_err());
}
