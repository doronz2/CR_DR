//! PUBLIC chunked-transcript verification: `verify_chunked_public_transcript`
//! consumes only (statement, admitted board, public transcript, proof
//! objects) — no witness data — and must reject every malicious transcript
//! mutation. The Groth16 verifier is stubbed with `Ok(true)` here so these
//! tests isolate the PUBLIC checks (real proof verification is exercised
//! end-to-end by `prove_chunked`, which routes through the same function).

mod common;

use cr_dr::protocol::admission::admitted_from_ballots;
use cr_dr::protocol::bulletin_board::AdmittedBoard;
use cr_dr::protocol::chaff::chaff_ballot;
use cr_dr::protocol::filter_and_tally::filter_and_tally;
use cr_dr::protocol::preprocessing::{finalize_registration, preprocess_voter};
use cr_dr::protocol::setup::setup_election;
use cr_dr::protocol::vote::cast_vote;
use cr_dr::types::{DuplicateRule, ElectionConfig, F};
use cr_dr::zk::chunked::{
    build_chunked_tally, chunked_relation_check_native, transcript_sorted_run_publics,
    transcript_tally_sum_publics, transcript_validity_publics, verify_chunked_public_transcript,
    ChunkedProofs, ChunkedTally, ChunkedTranscript, CHUNK_SIZE,
};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use serde_json::Value;

struct Fixture {
    ct: ChunkedTally,
    admitted: AdmittedBoard,
}

/// K=2 chunked board (256 slots): voter 0 votes TWICE (both valid), with
/// her ballots pinned into DIFFERENT chunks (slot 0 and slot 200 — no
/// shuffle), 9 more honest voters, chaff fill.
fn build(seed: u64) -> Fixture {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let config = ElectionConfig {
        eid: "chunked-transcript-test".into(),
        candidates: vec![0, 1, 2],
        max_voters: 64,
        max_ballots: 1 << 16,
        merkle_depth: 6,
        duplicate_rule: DuplicateRule::FirstValidCounts,
        threshold_params: Some(cr_dr::types::ThresholdParams { t: 2, k: 3 }),
    };
    let (pp, mut authority) = setup_election(config, &mut rng).unwrap();
    let mut voters = Vec::new();
    let mut records = Vec::new();
    for id in 0..10u64 {
        let (vs, rec) = preprocess_voter(&pp, &mut authority, id, &mut rng).unwrap();
        voters.push(vs);
        records.push(rec);
    }
    let reg = finalize_registration(&pp, &records).unwrap();

    // slot 0: voter 0's FIRST valid ballot (candidate 0) — chunk 0
    let mut ballots = vec![cast_vote(&pp, &reg, &voters[0], 0, &mut rng).unwrap()];
    // slots 1..10: voters 1..10, candidate 1
    for v in voters.iter().skip(1) {
        ballots.push(cast_vote(&pp, &reg, v, 1, &mut rng).unwrap());
    }
    // chaff up to slot 200
    while ballots.len() < 200 {
        ballots.push(chaff_ballot(&pp, &mut rng).unwrap());
    }
    // slot 200: voter 0's SECOND valid ballot (candidate 2) — chunk 1
    ballots.push(cast_vote(&pp, &reg, &voters[0], 2, &mut rng).unwrap());
    while ballots.len() < 256 {
        ballots.push(chaff_ballot(&pp, &mut rng).unwrap());
    }

    let (admitted, openings) = admitted_from_ballots(&ballots);
    let (tally, _) = filter_and_tally(&pp, &authority, &reg, &admitted, &openings).unwrap();
    // duplicate rule: voter 0's first valid ballot counts, her second does not
    assert_eq!(tally.counts, vec![1, 9, 0], "cross-chunk duplicate counted exactly once");
    let ct = build_chunked_tally(&pp, &authority, &reg, &admitted, &openings, CHUNK_SIZE, &mut rng)
        .unwrap();
    assert_eq!(ct.k_chunks, 2);
    Fixture { ct, admitted }
}

/// Honest proof objects: null proofs carrying the EXPECTED publics (the
/// Groth16 verify step is stubbed; these tests target the public checks).
fn honest_proofs(ct: &ChunkedTally) -> ChunkedProofs {
    let tr = ct.transcript();
    let arr = |v: Vec<String>| Value::Array(v.into_iter().map(Value::String).collect());
    ChunkedProofs {
        validity: (0..ct.k_chunks)
            .map(|k| (Value::Null, arr(transcript_validity_publics(&ct.statement, &tr, k))))
            .collect(),
        sorted_run: (0..ct.k_chunks)
            .map(|k| (Value::Null, arr(transcript_sorted_run_publics(&tr, k))))
            .collect(),
        tally_sum: (Value::Null, arr(transcript_tally_sum_publics(&ct.statement, &tr))),
    }
}

fn verify(f: &Fixture, tr: &ChunkedTranscript, proofs: &ChunkedProofs) -> bool {
    verify_chunked_public_transcript(&f.ct.statement, &f.admitted, tr, proofs, |_, _, _| Ok(true))
        .unwrap()
}

#[test]
fn honest_transcript_verifies_and_cross_chunk_duplicate_counts_once() {
    let f = build(200);
    assert!(chunked_relation_check_native(&f.ct));
    let tr = f.ct.transcript();
    assert!(verify(&f, &tr, &honest_proofs(&f.ct)));
    // the tally bound by the transcript's tally-sum publics is the
    // statement tally, which counted the cross-chunk duplicate once
    assert_eq!(f.ct.statement.tally_counts, vec![1, 9, 0]);
}

#[test]
fn swapped_chunk_proofs_rejected() {
    let f = build(201);
    let tr = f.ct.transcript();
    let mut proofs = honest_proofs(&f.ct);
    proofs.validity.swap(0, 1); // proof k=1 presented as k=0
    assert!(!verify(&f, &tr, &proofs));
    let mut proofs = honest_proofs(&f.ct);
    proofs.sorted_run.swap(0, 1);
    assert!(!verify(&f, &tr, &proofs));
}

#[test]
fn broken_board_chain_rejected() {
    let f = build(202);
    let mut tr = f.ct.transcript();
    tr.bb[1] += F::from(1u64);
    assert!(!verify(&f, &tr, &honest_proofs(&f.ct)));
}

#[test]
fn dropped_admitted_commitment_rejected() {
    let f = build(203);
    let tr = f.ct.transcript();
    let mut admitted = f.admitted.clone();
    admitted.coms.remove(37);
    assert!(!verify_chunked_public_transcript(
        &f.ct.statement,
        &admitted,
        &tr,
        &honest_proofs(&f.ct),
        |_, _, _| Ok(true)
    )
    .unwrap());
}

#[test]
fn broken_boundary_chain_rejected() {
    let f = build(204);
    // boundary_cm[0] must be the public sentinel
    let mut tr = f.ct.transcript();
    tr.boundary_cm[0] += F::from(1u64);
    assert!(!verify(&f, &tr, &honest_proofs(&f.ct)));
    // an interior boundary commitment cannot be replaced: run k's out and
    // run k+1's in come from the SAME transcript entry, so a mismatch with
    // the carried proof publics is detected
    let mut tr = f.ct.transcript();
    tr.boundary_cm[1] += F::from(1u64);
    assert!(!verify(&f, &tr, &honest_proofs(&f.ct)));
}

#[test]
fn forged_challenge_rejected() {
    let f = build(205);
    let mut tr = f.ct.transcript();
    tr.gamma += F::from(1u64);
    assert!(!verify(&f, &tr, &honest_proofs(&f.ct)));
    let mut tr = f.ct.transcript();
    tr.delta += F::from(1u64);
    assert!(!verify(&f, &tr, &honest_proofs(&f.ct)));
}

#[test]
fn changed_record_commitment_rejected() {
    let f = build(206);
    let mut tr = f.ct.transcript();
    tr.rc[1] += F::from(1u64); // breaks Fiat-Shamir derivation
    assert!(!verify(&f, &tr, &honest_proofs(&f.ct)));
}

#[test]
fn changed_sorted_run_commitment_rejected() {
    let f = build(207);
    let mut tr = f.ct.transcript();
    tr.sc[0] += F::from(1u64);
    assert!(!verify(&f, &tr, &honest_proofs(&f.ct)));
}

#[test]
fn shifted_partial_tally_rejected() {
    let f = build(208);
    // the partial tallies are hidden inside tc; substituting a different
    // tally commitment breaks the binding to the carried proof publics
    let mut tr = f.ct.transcript();
    tr.tc[0] += F::from(1u64);
    assert!(!verify(&f, &tr, &honest_proofs(&f.ct)));
}

#[test]
fn tampered_product_chain_rejected() {
    let f = build(209);
    // product chains must start at the public commitment to 1
    let mut tr = f.ct.transcript();
    tr.acc_p_cm[0] += F::from(1u64);
    assert!(!verify(&f, &tr, &honest_proofs(&f.ct)));
    // an interior accumulator commitment cannot be replaced: run k's out
    // and run k+1's in come from the SAME transcript entry, so a mismatch
    // with the carried proof publics is detected
    let mut tr = f.ct.transcript();
    tr.acc_q_cm[1] += F::from(1u64);
    assert!(!verify(&f, &tr, &honest_proofs(&f.ct)));
    // the final accumulator commitments are bound by the tally-sum publics
    let mut tr = f.ct.transcript();
    let last = tr.acc_p_cm.len() - 1;
    tr.acc_p_cm[last] += F::from(1u64);
    assert!(!verify(&f, &tr, &honest_proofs(&f.ct)));
}

#[test]
fn carried_publics_must_match_transcript_exactly() {
    let f = build(210);
    let tr = f.ct.transcript();
    // extra public input appended to a proof
    let mut proofs = honest_proofs(&f.ct);
    if let Value::Array(a) = &mut proofs.validity[0].1 {
        a.push(Value::String("1".into()));
    }
    assert!(!verify(&f, &tr, &proofs));
    // tally-sum proof claiming a different final tally
    let mut proofs = honest_proofs(&f.ct);
    if let Value::Array(a) = &mut proofs.tally_sum.1 {
        let last = a.len() - 1;
        a[last] = Value::String("999".into());
    }
    assert!(!verify(&f, &tr, &proofs));
}

#[test]
fn failed_groth16_verification_rejects() {
    let f = build(211);
    let tr = f.ct.transcript();
    let proofs = honest_proofs(&f.ct);
    // any single proof failing Groth16 verification fails the aggregate
    let mut calls = 0;
    let ok = verify_chunked_public_transcript(&f.ct.statement, &f.admitted, &tr, &proofs, |_, _, _| {
        calls += 1;
        Ok(calls != 2)
    })
    .unwrap();
    assert!(!ok);
}

#[test]
fn public_transcript_field_audit() {
    // AUDIT: record exactly which fields the public transcript exposes.
    // Everything here is posted next to the proofs; nothing else is.
    // Hidden by commitments/blinds: record contents (identities, validity
    // flags, positions, candidates), sorted order, per-run partial
    // tallies, running grand products, R / R_EA, and all blinds. Public:
    // board-chain snapshots (recomputable from BB_adm), HIDING
    // commitments only, and the FS challenges. No product value or
    // per-chunk product ratio is public (see CHUNKED_TALLY_DESIGN.md,
    // "Public values and leakage").
    let f = build(212);
    let tr = f.ct.transcript();
    let v = serde_json::to_value(&tr).unwrap();
    let mut fields: Vec<&str> = v.as_object().unwrap().keys().map(|s| s.as_str()).collect();
    fields.sort_unstable();
    assert_eq!(
        fields,
        vec![
            "acc_p_cm", "acc_q_cm", "bb", "boundary_cm", "chunk_size", "delta", "gamma", "rc",
            "sc", "tc"
        ],
        "public transcript field set changed — re-audit leakage"
    );
    eprintln!("public chunked transcript ({} chunks):", f.ct.k_chunks);
    eprintln!("{}", serde_json::to_string_pretty(&v).unwrap());
}
