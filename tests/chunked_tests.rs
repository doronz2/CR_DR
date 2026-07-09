//! Native tests for the CHUNKED FilterAndTally pipeline: the chunked
//! relation accepts honestly built instances (matching the monolithic
//! tally), and every aggregator/chunk check rejects tampering.

mod common;

use cr_dr::protocol::admission::admitted_from_ballots;
use cr_dr::protocol::chaff::chaff_ballot;
use cr_dr::protocol::fake_compliance::{build_fake_ballot, fake_compliance};
use cr_dr::protocol::filter_and_tally::filter_and_tally;
use cr_dr::protocol::preprocessing::{finalize_registration, preprocess_voter};
use cr_dr::protocol::setup::setup_election;
use cr_dr::protocol::vote::cast_vote;
use cr_dr::types::{DuplicateRule, ElectionConfig, F};
use cr_dr::zk::chunked::{
    build_chunked_tally, chunked_relation_check_native, ChunkedTally, CHUNK_SIZE,
};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

/// 40 voters (5 coerced), 500 ballots on a 512-slot (K=4) chunked board:
/// 5 fakes + 40 real + 455 chaff, shuffled through the anonymous channel.
fn build_instance(seed: u64, num_ballots: usize) -> (ChunkedTally, Vec<u64>) {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let config = ElectionConfig {
        eid: "chunked-test".into(),
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
    for id in 0..40u64 {
        let (vs, rec) = preprocess_voter(&pp, &mut authority, id, &mut rng).unwrap();
        voters.push(vs);
        records.push(rec);
    }
    let reg = finalize_registration(&pp, &records).unwrap();

    let mut ballots = Vec::new();
    for v in voters.iter().take(5) {
        let t = fake_compliance(&pp, v, 2, &mut rng).unwrap();
        ballots.push(build_fake_ballot(&pp, &t, &mut rng).unwrap());
        ballots.push(cast_vote(&pp, &reg, v, 0, &mut rng).unwrap());
    }
    for (i, v) in voters.iter().enumerate().skip(5) {
        ballots.push(cast_vote(&pp, &reg, v, 1 + (i as u64 % 2), &mut rng).unwrap());
    }
    let submitted = 5 + voters.len();
    for _ in submitted..num_ballots {
        ballots.push(chaff_ballot(&pp, &mut rng).unwrap());
    }
    // shuffled voter-side; the test models an already-admitted board
    use rand::seq::SliceRandom;
    ballots.shuffle(&mut rng);

    let (admitted, openings) = admitted_from_ballots(&ballots);
    let (tally, _) = filter_and_tally(&pp, &authority, &reg, &admitted, &openings).unwrap();
    let ct =
        build_chunked_tally(&pp, &authority, &reg, &admitted, &openings, CHUNK_SIZE, &mut rng)
            .unwrap();
    (ct, tally.counts)
}

#[test]
fn chunked_relation_accepts_and_matches_monolithic_tally() {
    let (ct, mono_tally) = build_instance(300, 500);
    assert_eq!(ct.k_chunks, 4);
    assert_eq!(ct.statement.num_ballots, 500);
    // The chunked pipeline attests exactly the monolithic FilterAndTally.
    assert_eq!(ct.statement.tally_counts, mono_tally);
    assert_eq!(
        ct.partial_tallies.iter().fold(vec![0u64; 3], |mut a, t| {
            for (i, x) in t.iter().enumerate() {
                a[i] += x;
            }
            a
        }),
        mono_tally
    );
    assert!(chunked_relation_check_native(&ct));
}

#[test]
fn chunked_rejects_wrong_tally() {
    let (mut ct, _) = build_instance(301, 500);
    ct.statement.tally_counts[0] += 1;
    assert!(!chunked_relation_check_native(&ct));
}

#[test]
fn chunked_rejects_tampered_sorted_records() {
    // Dropping a counted record from the sorted side (replacing it with a
    // duplicate of another) breaks the multiset grand product even if the
    // prover recomputes its own products and partial tallies consistently.
    let (mut ct, _) = build_instance(302, 500);
    let victim = ct
        .sorted
        .iter()
        .position(|r| r.valid)
        .expect("a valid sorted record exists");
    let replacement = ct.sorted[victim + 1];
    ct.sorted[victim] = replacement;
    // Recompute the prover-side artifacts consistently with the tamper.
    let mut rng = ChaCha20Rng::seed_from_u64(999);
    rebuild_phase2(&mut ct, &mut rng);
    assert!(!chunked_relation_check_native(&ct));
}

#[test]
fn chunked_rejects_partial_tally_shift() {
    // Moving one vote between candidates inside a chunk's partial tally
    // (with a consistent commitment) must fail the sorted-run re-check.
    let (mut ct, _) = build_instance(303, 500);
    let k = ct
        .partial_tallies
        .iter()
        .position(|t| t[0] > 0)
        .expect("some chunk counts candidate 0");
    ct.partial_tallies[k][0] -= 1;
    ct.partial_tallies[k][1] += 1;
    let mut inputs: Vec<F> = ct.partial_tallies[k].iter().map(|x| F::from(*x)).collect();
    inputs.push(ct.tally_blind[k]);
    ct.tc[k] = cr_dr::crypto::poseidon_native::poseidon(&inputs);
    assert!(!chunked_relation_check_native(&ct));
}

#[test]
fn chunked_rejects_wrong_challenge() {
    // A prover-chosen gamma (not the Fiat-Shamir output) must be rejected
    // by the aggregator's challenge recomputation.
    let (mut ct, _) = build_instance(304, 500);
    ct.gamma += F::from(1u64);
    let mut rng = ChaCha20Rng::seed_from_u64(998);
    rebuild_phase2(&mut ct, &mut rng);
    assert!(!chunked_relation_check_native(&ct));
}

#[test]
fn chunked_rejects_invalidated_record() {
    // Flipping a valid record to invalid in the record list (to undercount
    // it) breaks the phase-1 eval_row equality.
    let (mut ct, _) = build_instance(305, 500);
    let victim = ct.records.iter().position(|r| r.valid).unwrap();
    ct.records[victim].valid = false;
    ct.records[victim].id = 0;
    assert!(!chunked_relation_check_native(&ct));
}

/// Recompute all post-challenge prover artifacts (products, partial
/// tallies, boundary commitments, tc) consistently with the current
/// (possibly tampered) `sorted`/`gamma` — modelling a cheating prover that
/// keeps its own transcript self-consistent.
fn rebuild_phase2(ct: &mut ChunkedTally, rng: &mut ChaCha20Rng) {
    use ark_ff::UniformRand;
    use cr_dr::zk::chunked::{record_chain, record_commit};
    use cr_dr::zk::mock_backend::Rec;
    let c = ct.chunk_size;
    for k in 0..ct.k_chunks {
        let run: Vec<Rec> = ct.sorted[k * c..(k + 1) * c].to_vec();
        let orig: Vec<Rec> = ct.records[k * c..(k + 1) * c].to_vec();
        ct.sc[k] = record_chain(ct.sc_blind[k], &run);
        let bnd_in = if k == 0 { Rec::SENTINEL } else { ct.sorted[k * c - 1] };
        ct.boundary_cm[k + 1] = record_commit(&run[c - 1], ct.boundary_blind[k + 1]);
        let mut prev_id = bnd_in.id;
        let mut t = vec![0u64; ct.candidates.len()];
        for r in &run {
            if r.valid && r.id != prev_id {
                t[r.m as usize] += 1;
            }
            prev_id = r.id;
        }
        let mut inputs: Vec<F> = t.iter().map(|x| F::from(*x)).collect();
        inputs.push(ct.tally_blind[k]);
        ct.tc[k] = cr_dr::crypto::poseidon_native::poseidon(&inputs);
        ct.partial_tallies[k] = t;
        let rho = F::rand(rng);
        let d2 = ct.delta * ct.delta;
        let d3 = d2 * ct.delta;
        let encf = |r: &Rec| {
            F::from(r.valid as u64)
                + ct.delta * F::from(r.id)
                + d2 * F::from(r.pos)
                + d3 * F::from(r.m)
        };
        let mut p = rho;
        let mut q = rho;
        for (s, o) in run.iter().zip(&orig) {
            p *= ct.gamma - encf(s);
            q *= ct.gamma - encf(o);
        }
        ct.rho[k] = rho;
        ct.pp[k] = p;
        ct.qq[k] = q;
    }
}
