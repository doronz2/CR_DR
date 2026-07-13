//! TIER-3 (decentralized / coSNARK) tests.
//!
//! The partition/reconstruction tests are native and always run. The full
//! 3-party MPC proof test is OPT-IN (needs the co-circom binary, the
//! vchunkmpc8 artifacts, and demo TLS assets); enable with
//! `CR_DR_TIER3_MPC=1 cargo test --test tier3_tests -- --nocapture`.

mod common;

use cr_dr::crypto::shamir::{reconstruct, Share};
use cr_dr::protocol::admission::admitted_from_ballots;
use cr_dr::protocol::chaff::chaff_ballot;
use cr_dr::protocol::fake_compliance::{build_fake_ballot, fake_compliance};
use cr_dr::protocol::preprocessing::{finalize_registration, preprocess_voter};
use cr_dr::protocol::setup::setup_election;
use cr_dr::protocol::vote::cast_vote;
use cr_dr::types::{DuplicateRule, ElectionConfig, ThresholdParams, F};
use cr_dr::zk::chunked::{build_chunked_tally, ChunkedTally};
use cr_dr::zk::tier3::{chunk_providers, provider_leaks_r_ea};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

/// Small depth-14 instance over `width`-slot chunks (matches ValidityChunkMpc).
fn instance(seed: u64, voters: usize, width: usize) -> (ChunkedTally, cr_dr::types::AuthoritySecretState) {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let config = ElectionConfig {
        eid: "tier3-test".into(),
        candidates: vec![0, 1, 2],
        max_voters: 1 << 14,
        max_ballots: 1 << 24,
        merkle_depth: 14,
        duplicate_rule: DuplicateRule::FirstValidCounts,
        threshold_params: Some(ThresholdParams { t: 2, k: 3 }),
    };
    let (pp, mut authority) = setup_election(config, &mut rng).unwrap();
    let (mut voters_v, mut records) = (Vec::new(), Vec::new());
    for id in 0..voters as u64 {
        let (vs, rec) = preprocess_voter(&pp, &mut authority, id, &mut rng).unwrap();
        voters_v.push(vs);
        records.push(rec);
    }
    let reg = finalize_registration(&pp, &records).unwrap();
    let mut ballots = Vec::new();
    for v in voters_v.iter().take(2) {
        let t = fake_compliance(&pp, v, 2, &mut rng).unwrap();
        ballots.push(build_fake_ballot(&pp, &t, &mut rng).unwrap());
        ballots.push(cast_vote(&pp, &reg, v, 0, &mut rng).unwrap());
    }
    for (i, v) in voters_v.iter().enumerate().skip(2) {
        ballots.push(cast_vote(&pp, &reg, v, 1 + (i as u64 % 2), &mut rng).unwrap());
    }
    let board = voters.div_ceil(width).max(1) * width;
    while ballots.len() < board {
        ballots.push(chaff_ballot(&pp, &mut rng).unwrap());
    }
    let (admitted, openings) = admitted_from_ballots(&ballots);
    let ct = build_chunked_tally(&pp, &authority, &reg, &admitted, &openings, width, &mut rng).unwrap();
    (ct, authority)
}

#[test]
fn provider_partition_hides_r_ea() {
    // No provider file may contain R_EA; the two authority files carry
    // ONLY their own separately-named share array.
    let (ct, authority) = instance(1, 20, 8);
    for k in 0..ct.k_chunks {
        let p = chunk_providers(&ct, &authority, k).unwrap();
        assert!(!provider_leaks_r_ea(&p.opening), "opening leaks R_EA");
        assert!(!provider_leaks_r_ea(&p.authority_a));
        assert!(!provider_leaks_r_ea(&p.authority_b));
        // authority files are single-key and disjoint
        let a = p.authority_a.as_object().unwrap();
        let b = p.authority_b.as_object().unwrap();
        assert_eq!(a.keys().collect::<Vec<_>>(), vec!["r_ea_share_a"]);
        assert_eq!(b.keys().collect::<Vec<_>>(), vec!["r_ea_share_b"]);
        // opening carries the openings but neither share array
        let o = p.opening.as_object().unwrap();
        assert!(o.contains_key("pt") && o.contains_key("rho"));
        assert!(!o.contains_key("r_ea_share_a") && !o.contains_key("r_ea_share_b"));
    }
}

#[test]
fn in_circuit_combine_matches_shamir_reconstruction() {
    // The in-circuit Lagrange combine (2*a - b, LagrangeCombineT2) must
    // equal shamir::reconstruct over the same two shares — i.e. the true
    // R_EA — so the MPC computes the identical witness. chunk_providers
    // asserts (2a-b == tier1 r_ea) internally; here we independently
    // confirm the shares reconstruct via the general Shamir path too.
    let (ct, authority) = instance(2, 30, 8);
    // Reconstruct straight from stored shares for one registered voter.
    let voter0 = authority.voter_secrets.get(&0).unwrap();
    let a = voter0.r_ea_shares[0];
    let b = voter0.r_ea_shares[1];
    let combined = F::from(2u64) * a.value - b.value;
    let shamir = reconstruct(&[
        Share { index: a.index, value: a.value },
        Share { index: b.index, value: b.value },
    ])
    .unwrap();
    assert_eq!(combined, shamir, "2*s1 - s2 must equal Shamir reconstruction at x=0");
    assert_eq!(a.index, 1);
    assert_eq!(b.index, 2);
    // Building the providers succeeds => every slot's (2a-b) matched the
    // Tier-1 reconstructed r_ea (the internal assert in chunk_providers).
    for k in 0..ct.k_chunks {
        chunk_providers(&ct, &authority, k).unwrap();
    }
}

#[test]
fn full_providers_hide_r_ea_records_and_tally() {
    // FULL Tier-3: the monolithic-circuit provider inputs must contain no
    // R_EA, no tally, and no records/sorted/duplicate/partial-tally arrays
    // — those are all computed inside the MPC. The opening provider carries
    // only openings + the PUBLIC statement + registration rows; the two
    // authority providers carry only their own share arrays.
    use cr_dr::protocol::admission::admitted_from_ballots;
    use cr_dr::protocol::setup::setup_election;
    use cr_dr::zk::tier3::full_providers;
    let mut rng = ChaCha20Rng::seed_from_u64(6000);
    let config = ElectionConfig {
        eid: "tier3-full-test".into(),
        candidates: vec![0, 1, 2],
        max_voters: 64,
        max_ballots: 128,
        merkle_depth: 6,
        duplicate_rule: DuplicateRule::FirstValidCounts,
        threshold_params: Some(ThresholdParams { t: 2, k: 3 }),
    };
    let (pp, mut authority) = setup_election(config, &mut rng).unwrap();
    let (mut vs, mut recs) = (Vec::new(), Vec::new());
    for id in 0..30u64 {
        let (v, r) = preprocess_voter(&pp, &mut authority, id, &mut rng).unwrap();
        vs.push(v);
        recs.push(r);
    }
    let reg = finalize_registration(&pp, &recs).unwrap();
    let mut ballots = Vec::new();
    for (i, v) in vs.iter().enumerate() {
        ballots.push(cast_vote(&pp, &reg, v, 1 + (i as u64 % 2), &mut rng).unwrap());
    }
    let (admitted, openings) = admitted_from_ballots(&ballots);
    let p = full_providers(&pp, &authority, &reg, &admitted, &openings, 128, 6).unwrap();

    let o = p.opening.as_object().unwrap();
    assert!(!o.contains_key("r_ea") && !o.contains_key("tally_counts"));
    // no record / sorted / duplicate / partial-tally / grand-product arrays
    for forbidden in ["records", "sorted", "counted", "partial_tallies", "acc_p", "acc_q", "rc"] {
        assert!(!o.contains_key(forbidden), "opening leaks {forbidden}");
    }
    // opening supplies openings + registration + public statement only
    for req in ["pt", "rho", "ct", "reg_vkx", "reg_h", "path_elements", "bb_commitment", "num_ballots"] {
        assert!(o.contains_key(req), "opening missing {req}");
    }
    assert_eq!(o["pt"].as_array().unwrap().len(), 128);
    assert_eq!(p.authority_a.as_object().unwrap().keys().collect::<Vec<_>>(), vec!["r_ea_share_a"]);
    assert_eq!(p.authority_b.as_object().unwrap().keys().collect::<Vec<_>>(), vec!["r_ea_share_b"]);
}

#[test]
fn tier3_full_relation_collaborative_proof_verifies() {
    // OPT-IN heavy test: the FULL relation (validity+sort+duplicate+tally)
    // proven in 3-party MPC collaborative proving, revealing the correct
    // tally. Uses the central-witness path (co-circom v0.10.0 cannot
    // MPC-extend the duplicate/tally stage — see TIER3_DESIGN.md), so it
    // exercises decentralized PROVING of the full relation. Skips without
    // the env var / artifacts.
    if std::env::var("CR_DR_TIER3_MPC").is_err() {
        eprintln!("SKIP: set CR_DR_TIER3_MPC=1 to run the full-relation MPC proof test");
        return;
    }
    use cr_dr::protocol::admission::admitted_from_ballots;
    use cr_dr::protocol::filter_and_tally::filter_and_tally;
    use cr_dr::protocol::setup::setup_election;
    use cr_dr::zk::groth16_backend::SnarkjsBackend;
    use cr_dr::zk::tier3::{full_providers, merged_input, CoCircomBackend};

    let root = SnarkjsBackend::crate_root();
    let Some(be) = CoCircomBackend::discover_named(&root, "filter_and_tally_small_mpc_naive") else {
        eprintln!("SKIP: small_mpc_naive artifacts not found");
        return;
    };
    if !be.assets_dir.join("key0.der").exists() {
        eprintln!("SKIP: demo TLS assets missing");
        return;
    }
    let mut rng = ChaCha20Rng::seed_from_u64(7000);
    let config = ElectionConfig {
        eid: "tier3-full-mpc-test".into(),
        candidates: vec![0, 1, 2],
        max_voters: 16,
        max_ballots: 16,
        merkle_depth: 4,
        duplicate_rule: DuplicateRule::FirstValidCounts,
        threshold_params: Some(ThresholdParams { t: 2, k: 3 }),
    };
    let (pp, mut authority) = setup_election(config, &mut rng).unwrap();
    let (mut vs, mut recs) = (Vec::new(), Vec::new());
    for id in 0..6u64 {
        let (v, r) = preprocess_voter(&pp, &mut authority, id, &mut rng).unwrap();
        vs.push(v);
        recs.push(r);
    }
    let reg = finalize_registration(&pp, &recs).unwrap();
    let mut ballots = Vec::new();
    for (i, v) in vs.iter().enumerate() {
        ballots.push(cast_vote(&pp, &reg, v, 1 + (i as u64 % 2), &mut rng).unwrap());
    }
    let (admitted, openings) = admitted_from_ballots(&ballots);
    let (expected, _) = filter_and_tally(&pp, &authority, &reg, &admitted, &openings).unwrap();
    let providers = full_providers(&pp, &authority, &reg, &admitted, &openings, 16, 4).unwrap();
    let work = be.assets_dir.join("test_full");
    std::fs::create_dir_all(&work).unwrap();
    let (proof, public) = be.prove_collaborative(&merged_input(&providers), &work).unwrap();
    assert!(be.verify(&proof, &public).unwrap(), "full-relation MPC proof must verify");
    let got: serde_json::Value = serde_json::from_slice(&std::fs::read(&public).unwrap()).unwrap();
    let tally: Vec<u64> = got.as_array().unwrap().iter().take(3)
        .map(|v| v.as_str().unwrap().parse().unwrap()).collect();
    assert_eq!(tally, expected.counts, "MPC-revealed tally must equal the expected tally");
}

#[test]
fn tier3_mpc_proof_verifies_end_to_end() {
    // OPT-IN heavy test: a real 3-party REP3 MPC proof of the validity
    // relation that verifies under the standard key. Needs co-circom +
    // vchunkmpc8 artifacts + demo TLS assets. Skips otherwise.
    if std::env::var("CR_DR_TIER3_MPC").is_err() {
        eprintln!("SKIP: set CR_DR_TIER3_MPC=1 to run the real 3-party MPC proof test");
        return;
    }
    use cr_dr::zk::chunked::validity_chunk_publics;
    use cr_dr::zk::groth16_backend::SnarkjsBackend;
    use cr_dr::zk::tier3::CoCircomBackend;

    let root = SnarkjsBackend::crate_root();
    let Some(be) = CoCircomBackend::discover_width(&root, 8) else {
        eprintln!("SKIP: co-circom / vchunkmpc8 artifacts not found");
        return;
    };
    if !be.assets_dir.join("key0.der").exists() {
        eprintln!("SKIP: demo TLS assets missing (run prove_tier3 --width 8 once to stage them)");
        return;
    }
    let (ct, authority) = instance(5000, 20, 8);
    let providers = chunk_providers(&ct, &authority, 0).unwrap();
    let work = be.assets_dir.join("test_chunk0");
    std::fs::create_dir_all(&work).unwrap();
    let (proof, public) = be.prove_chunk(&providers, &work).unwrap();
    assert!(be.verify(&proof, &public).unwrap(), "MPC proof must verify");
    let got: serde_json::Value = serde_json::from_slice(&std::fs::read(&public).unwrap()).unwrap();
    let got: Vec<String> = got.as_array().unwrap().iter().map(|v| v.as_str().unwrap().to_string()).collect();
    assert_eq!(got, validity_chunk_publics(&ct, 0), "MPC publics must bind the Tier-1 statement");
}
