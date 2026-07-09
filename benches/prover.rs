//! End-to-end single-prover (Tier 1) benchmarks: `cargo bench --bench prover`
//!
//! Groups:
//!   * `e2e_small`  / `e2e_medium`  — every native pipeline stage: election
//!     setup, threshold-private preprocessing, registration finalization
//!     (indexed Merkle root), ballot/chaff generation, anonymous-channel
//!     flush, native FilterAndTally, witness construction, native relation
//!     check, statement build, circuit-input serialization.
//!   * `duplicates` — Strategy A (naive O(B^2)) vs Strategy B (sorted
//!     records) native duplicate handling at 16 / 128 / 1024 records.
//!   * `groth16_small` / `groth16_medium` — the real snarkjs stages
//!     (circuit witness generation, Groth16 prove, verify) for BOTH circuit
//!     strategies (default = Strategy B, `*_naive` = Strategy A). Each
//!     group skips with a notice if its artifacts are missing
//!     (scripts/compile_circuits.sh <variant> + scripts/setup_groth16.sh
//!     <variant>).
//!
//! These are SINGLE-PROVER numbers: one logical prover holds the full
//! witness (authorized >= t nonce reconstructions included) and runs
//! Groth16. No decentralized/threshold proving is benchmarked.
//!
//! Filter as usual, e.g. `cargo bench --bench prover -- groth16_small`.

use criterion::{criterion_group, criterion_main, Criterion};

use cr_dr::protocol::admission::admitted_from_ballots;
use cr_dr::protocol::admission::{AdmittedOpenings};
use cr_dr::protocol::bulletin_board::{AdmittedBoard, AnonymousChannel, BulletinBoard};
use cr_dr::protocol::chaff::chaff_ballot;
use cr_dr::protocol::duplicates::{counted_flags_naive, counted_flags_sorted, BallotRecord};
use cr_dr::protocol::fake_compliance::{build_fake_ballot, fake_compliance};
use cr_dr::protocol::filter_and_tally::filter_and_tally;
use cr_dr::protocol::preprocessing::{
    finalize_registration, preprocess_voter, RegistrationState,
};
use cr_dr::protocol::setup::setup_election;
use cr_dr::protocol::vote::cast_vote;
use cr_dr::types::{
    AuthoritySecretState, Ballot, DuplicateRule, ElectionConfig, PublicParams, TallyResult,
    VoterState,
};
use cr_dr::zk::circom_io::generate_witness_input;
use cr_dr::zk::groth16_backend::SnarkjsBackend;
use cr_dr::zk::mock_backend::relation_check_native;
use cr_dr::zk::statement::{build_tally_statement, TallyStatement};
use cr_dr::zk::witness::{build_tally_witness, TallyWitness};
use cr_dr::zk::{CircuitShape, MEDIUM_SHAPE, SMALL_SHAPE};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

/// A full provable instance at some board size.
struct Instance {
    label: &'static str,
    shape: CircuitShape,
    pp: PublicParams,
    authority: AuthoritySecretState,
    reg: RegistrationState,
    voters: Vec<VoterState>,
    ballots: Vec<Ballot>,
    admitted: AdmittedBoard,
    openings: AdmittedOpenings,
    tally: TallyResult,
    statement: TallyStatement,
    witness: TallyWitness,
    input: serde_json::Value,
    n_real: usize,
    n_fake: usize,
    n_chaff: usize,
    rng: ChaCha20Rng,
}

fn config(shape: &CircuitShape, max_voters: usize, eid: &str) -> ElectionConfig {
    ElectionConfig {
        eid: eid.into(),
        candidates: vec![0, 1, 2],
        max_voters,
        max_ballots: shape.num_ballots,
        merkle_depth: shape.merkle_depth,
        duplicate_rule: DuplicateRule::FirstValidCounts,
        threshold_params: Some(cr_dr::types::ThresholdParams { t: 2, k: 3 }),
    }
}

/// Build an instance: `n_voters` registered (dense ids), `n_fake` coerced
/// voters each submitting one fake-compliance ballot AND their real vote,
/// remaining voters one real vote each, chaff filling the board. Ballots go
/// through the anonymous channel (shuffled).
fn build_instance(
    label: &'static str,
    shape: CircuitShape,
    n_voters: usize,
    n_fake: usize,
    seed: u64,
) -> Instance {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let (pp, mut authority) =
        setup_election(config(&shape, n_voters, label), &mut rng).unwrap();
    let mut voters = Vec::new();
    let mut records = Vec::new();
    for id in 0..n_voters as u64 {
        let (vs, rec) = preprocess_voter(&pp, &mut authority, id, &mut rng).unwrap();
        voters.push(vs);
        records.push(rec);
    }
    let reg = finalize_registration(&pp, &records).unwrap();

    // Ballots shuffled voter-side; the tally benches model an ALREADY
    // ADMITTED board (BB_adm + EA openings) — admission-path costs are
    // benchmarked separately in the `cast` group (Path 1 per-voter).
    let _ = AnonymousChannel::new;
    let _ = BulletinBoard::new;
    let mut ballots: Vec<Ballot> = Vec::new();
    for v in voters.iter().take(n_fake) {
        let t = fake_compliance(&pp, v, 2, &mut rng).unwrap();
        ballots.push(build_fake_ballot(&pp, &t, &mut rng).unwrap());
        ballots.push(cast_vote(&pp, &reg, v, 0, &mut rng).unwrap());
    }
    for (i, v) in voters.iter().enumerate().skip(n_fake) {
        ballots.push(cast_vote(&pp, &reg, v, 1 + (i as u64 % 2), &mut rng).unwrap());
    }
    let n_real = voters.len();
    let n_chaff = shape.num_ballots - n_real - n_fake;
    for _ in 0..n_chaff {
        ballots.push(chaff_ballot(&pp, &mut rng).unwrap());
    }
    use rand::seq::SliceRandom;
    ballots.shuffle(&mut rng);

    let (admitted, openings) = admitted_from_ballots(&ballots);
    let (tally, _) = filter_and_tally(&pp, &authority, &reg, &admitted, &openings).unwrap();
    let statement = build_tally_statement(&pp, &admitted, &reg, &tally);
    let witness =
        build_tally_witness(&pp, &authority, &reg, &admitted, &openings).unwrap();
    assert!(relation_check_native(&statement, &witness, &shape));
    let input = generate_witness_input(&statement, &witness, &shape).unwrap();

    Instance {
        label,
        shape,
        pp,
        authority,
        reg,
        voters,
        ballots,
        admitted,
        openings,
        tally,
        statement,
        witness,
        input,
        n_real,
        n_fake,
        n_chaff,
        rng,
    }
}

fn small_instance(seed: u64) -> Instance {
    // 16 slots: 6 voters (1 coerced), 1 fake + 6 real + 9 chaff.
    build_instance("small", SMALL_SHAPE, 6, 1, seed)
}

fn medium_instance(seed: u64) -> Instance {
    // 128 slots: 40 voters (5 coerced), 5 fakes + 40 real + 83 chaff.
    build_instance("medium", MEDIUM_SHAPE, 40, 5, seed)
}

fn describe(inst: &Instance) {
    eprintln!(
        "instance '{}': circuit ({} ballot slots, {} candidates, merkle depth {}); \
         {} registered voters (threshold t=2,k=3); board full at {} ballots = \
         {} real + {} fake-compliance + {} chaff; tally {:?}",
        inst.label,
        inst.shape.num_ballots,
        inst.shape.num_candidates,
        inst.shape.merkle_depth,
        inst.voters.len(),
        inst.ballots.len(),
        inst.n_real,
        inst.n_fake,
        inst.n_chaff,
        inst.tally.counts,
    );
}

// ---------------------------------------------------------------------------
// Native end-to-end stages
// ---------------------------------------------------------------------------

fn bench_e2e(c: &mut Criterion, mut inst: Instance, group_name: &str) {
    describe(&inst);
    let shape = inst.shape;
    let n_voters = inst.voters.len();
    let mut g = c.benchmark_group(group_name);

    g.bench_function("setup_election", |b| {
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        b.iter(|| setup_election(config(&shape, n_voters, "bench-setup"), &mut rng).unwrap())
    });
    g.bench_function("preprocess_voter", |b| {
        // fresh authority each batch so ids stay free; per-iter cost is one
        // threshold-private registration (keygen + share + h/leaf hashes)
        let mut rng = ChaCha20Rng::seed_from_u64(2);
        let (pp, authority0) =
            setup_election(config(&shape, n_voters, "bench-prep"), &mut rng).unwrap();
        let mut id = 0u64;
        let mut authority = None;
        b.iter(|| {
            if id == 0 {
                authority = Some(clone_authority_empty(&authority0));
            }
            let a = authority.as_mut().unwrap();
            let out = preprocess_voter(&pp, a, id, &mut rng).unwrap();
            id = (id + 1) % n_voters as u64;
            out
        })
    });
    g.bench_function("finalize_registration_merkle_root", |b| {
        let records: Vec<_> = inst.reg.records.values().cloned().collect();
        b.iter(|| finalize_registration(&inst.pp, &records).unwrap())
    });
    g.bench_function("cast_vote", |b| {
        let v = inst.voters[0].clone();
        let (pp, reg) = (inst.pp.clone(), inst.reg.clone());
        let mut rng = ChaCha20Rng::seed_from_u64(3);
        b.iter(|| cast_vote(&pp, &reg, &v, 1, &mut rng).unwrap())
    });
    g.bench_function("fake_compliance_ballot", |b| {
        let v = inst.voters[0].clone();
        let pp = inst.pp.clone();
        let mut rng = ChaCha20Rng::seed_from_u64(4);
        b.iter(|| {
            let t = fake_compliance(&pp, &v, 2, &mut rng).unwrap();
            build_fake_ballot(&pp, &t, &mut rng).unwrap()
        })
    });
    g.bench_function("chaff_ballot", |b| {
        let pp = inst.pp.clone();
        let mut rng = ChaCha20Rng::seed_from_u64(5);
        b.iter(|| chaff_ballot(&pp, &mut rng).unwrap())
    });
    g.bench_function("anonymous_channel_flush", |b| {
        let entries: Vec<_> = inst.ballots.iter().map(|x| x.public()).collect();
        b.iter(|| {
            let mut ch = AnonymousChannel::new();
            for x in &entries {
                ch.submit(x.clone());
            }
            ch.flush_shuffled(&mut inst.rng)
        })
    });
    g.bench_function("filter_and_tally_native", |b| {
        b.iter(|| {
            filter_and_tally(&inst.pp, &inst.authority, &inst.reg, &inst.admitted, &inst.openings)
                .unwrap()
        })
    });
    g.bench_function("build_tally_statement", |b| {
        b.iter(|| build_tally_statement(&inst.pp, &inst.admitted, &inst.reg, &inst.tally))
    });
    g.bench_function("build_tally_witness", |b| {
        b.iter(|| {
            build_tally_witness(&inst.pp, &inst.authority, &inst.reg, &inst.admitted, &inst.openings)
                .unwrap()
        })
    });
    g.bench_function("relation_check_native", |b| {
        b.iter(|| assert!(relation_check_native(&inst.statement, &inst.witness, &shape)))
    });
    g.bench_function("generate_witness_input", |b| {
        b.iter(|| generate_witness_input(&inst.statement, &inst.witness, &shape).unwrap())
    });
    g.finish();
}

fn clone_authority_empty(a: &AuthoritySecretState) -> AuthoritySecretState {
    AuthoritySecretState {
        sk_ea: a.sk_ea.clone(),
        receipt_sk: a.receipt_sk.clone(),
        threshold: a.threshold,
        voter_secrets: Default::default(),
    }
}

fn bench_e2e_small(c: &mut Criterion) {
    bench_e2e(c, small_instance(1000), "e2e_small");
}

fn bench_e2e_medium(c: &mut Criterion) {
    bench_e2e(c, medium_instance(2000), "e2e_medium");
}

// ---------------------------------------------------------------------------
// Duplicate strategies (native)
// ---------------------------------------------------------------------------

fn bench_duplicates(c: &mut Criterion) {
    use rand::Rng;
    let mut g = c.benchmark_group("duplicates");
    for &n in &[16usize, 128, 1024] {
        let mut rng = ChaCha20Rng::seed_from_u64(n as u64);
        let records: Vec<BallotRecord> = (0..n)
            .map(|pos| BallotRecord {
                valid: rng.gen_bool(0.6),
                id: rng.gen_range(0..(n as u64 / 2).max(1)),
                pos: pos as u64,
                cand_index: rng.gen_range(0..3),
            })
            .collect();
        assert_eq!(counted_flags_naive(&records), counted_flags_sorted(&records));
        g.bench_function(format!("strategy_a_naive_{n}"), |b| {
            b.iter(|| counted_flags_naive(&records))
        });
        g.bench_function(format!("strategy_b_sorted_{n}"), |b| {
            b.iter(|| counted_flags_sorted(&records))
        });
    }
    g.finish();
}

// ---------------------------------------------------------------------------
// Groth16 (snarkjs) stages — single prover
// ---------------------------------------------------------------------------

fn backend(circuit: &str) -> SnarkjsBackend {
    SnarkjsBackend {
        root: SnarkjsBackend::crate_root(),
        circuit: circuit.to_string(),
    }
}

fn bench_groth16(c: &mut Criterion, inst: &Instance, group_name: &str, variant: &str) {
    let sorted = backend(&format!("filter_and_tally_{variant}"));
    let naive = backend(&format!("filter_and_tally_{variant}_naive"));
    if !sorted.toolchain_available() {
        eprintln!(
            "SKIP {group_name}: artifacts for {} not found \
             (scripts/compile_circuits.sh {variant} + scripts/setup_groth16.sh {variant})",
            sorted.circuit
        );
        return;
    }
    describe(inst);

    let mut g = c.benchmark_group(group_name);
    g.sample_size(10); // proves take seconds-to-minutes

    for (tag, be) in [("sorted", &sorted), ("naive", &naive)] {
        if !be.toolchain_available() {
            eprintln!("SKIP {group_name}/{tag}: artifacts for {} not found", be.circuit);
            continue;
        }
        // One proof up front: correctness + verify-bench input.
        let (proof, public) = be.prove(&inst.input).expect("proving must succeed");
        assert!(be.verify(&proof, &public).unwrap());
        eprintln!(
            "{}/{}: proof.json {} bytes, public.json {} bytes ({} public inputs)",
            group_name,
            tag,
            serde_json::to_vec(&proof).unwrap().len(),
            serde_json::to_vec(&public).unwrap().len(),
            public.as_array().map(|a| a.len()).unwrap_or(0),
        );

        g.bench_function(format!("witness_generation_wasm_{tag}"), |b| {
            b.iter(|| {
                let work = tempfile::tempdir().unwrap();
                be.generate_witness(&inst.input, work.path()).unwrap()
            })
        });
        g.bench_function(format!("prove_{tag}"), |b| b.iter(|| be.prove(&inst.input).unwrap()));
        g.bench_function(format!("verify_{tag}"), |b| {
            b.iter(|| assert!(be.verify(&proof, &public).unwrap()))
        });

        // rapidsnark NATIVE prover on the same .zkey (proving step only —
        // witness pre-generated once; snarkjs remains the verifier).
        if let Some(rapid) = cr_dr::zk::groth16_backend::RapidsnarkBackend::discover(be.clone())
        {
            let work = tempfile::tempdir().unwrap();
            let wtns = be.generate_witness(&inst.input, work.path()).unwrap();
            let (rp, rpub) = rapid.prove_witness(&wtns, work.path()).unwrap();
            assert!(rapid.verify(&rp, &rpub).unwrap(), "rapidsnark proof must verify");
            g.bench_function(format!("prove_rapidsnark_{tag}"), |b| {
                b.iter(|| rapid.prove_witness(&wtns, work.path()).unwrap())
            });
        } else {
            eprintln!("SKIP {group_name}/prove_rapidsnark_{tag}: rapidsnark prover not found");
        }
    }
    g.finish();
}

fn bench_groth16_small(c: &mut Criterion) {
    let inst = small_instance(1001);
    bench_groth16(c, &inst, "groth16_small", "small");
}

fn bench_groth16_medium(c: &mut Criterion) {
    let inst = medium_instance(2001);
    bench_groth16(c, &inst, "groth16_medium", "medium");
}


// ---------------------------------------------------------------------------
// Path-1 admission: per-voter cast-ZK costs (seal, prove, verify, Clean)
// ---------------------------------------------------------------------------

fn bench_cast(c: &mut Criterion) {
    use cr_dr::zk::cast::*;
    let root = SnarkjsBackend::crate_root();
    let be = SnarkjsBackend { root: root.clone(), circuit: CAST_CIRCUIT.into() };
    if !be.toolchain_available() {
        eprintln!("SKIP cast: cast circuit artifacts not found");
        return;
    }
    let mut rng = ChaCha20Rng::seed_from_u64(9000);
    let cfg = config(&SMALL_SHAPE, 6, "bench-cast");
    let (pp, mut authority) = setup_election(cfg, &mut rng).unwrap();
    let mut records = Vec::new();
    let mut voters = Vec::new();
    for id in 0..6u64 {
        let (vs, rec) = preprocess_voter(&pp, &mut authority, id, &mut rng).unwrap();
        voters.push(vs);
        records.push(rec);
    }
    let reg = finalize_registration(&pp, &records).unwrap();
    let ballot = cast_vote(&pp, &reg, &voters[0], 1, &mut rng).unwrap();
    let proof = prove_cast(&root, &pp.pk_ea, &ballot.public(), &ballot.secret).unwrap();
    assert!(verify_cast_entry(&root, &pp.pk_ea, &ballot.public(), &proof).unwrap());

    let mut g = c.benchmark_group("cast");
    g.sample_size(10);
    g.bench_function("seal_ballot", |b| {
        let pt = cr_dr::types::BallotPlaintext::from_fields(
            &ballot.secret.opening.plaintext_fields,
        )
        .unwrap();
        b.iter(|| cr_dr::protocol::vote::seal_ballot(&pp, &pt, &mut rng).unwrap())
    });
    g.bench_function("prove_cast", |b| {
        b.iter(|| prove_cast(&root, &pp.pk_ea, &ballot.public(), &ballot.secret).unwrap())
    });
    g.bench_function("verify_cast_entry", |b| {
        b.iter(|| assert!(verify_cast_entry(&root, &pp.pk_ea, &ballot.public(), &proof).unwrap()))
    });
    g.finish();
}

criterion_group!(
    benches,
    bench_e2e_small,
    bench_e2e_medium,
    bench_duplicates,
    bench_groth16_small,
    bench_groth16_medium,
    bench_chunked,
    bench_cast
);
criterion_main!(benches);

// ---------------------------------------------------------------------------
// Chunked pipeline (boards beyond one circuit) — single prover
// ---------------------------------------------------------------------------

fn build_chunked_instance(seed: u64, n_ballots: usize) -> cr_dr::zk::chunked::ChunkedTally {
    use cr_dr::zk::chunked::{build_chunked_tally, CHUNK_SIZE};
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let cfg = ElectionConfig {
        eid: format!("bench-chunked-{n_ballots}"),
        candidates: vec![0, 1, 2],
        max_voters: 64,
        max_ballots: 1 << 16,
        merkle_depth: 6,
        duplicate_rule: DuplicateRule::FirstValidCounts,
        threshold_params: Some(cr_dr::types::ThresholdParams { t: 2, k: 3 }),
    };
    let (pp, mut authority) = setup_election(cfg, &mut rng).unwrap();
    let (mut voters, mut records) = (Vec::new(), Vec::new());
    for id in 0..40u64 {
        let (vs, rec) = preprocess_voter(&pp, &mut authority, id, &mut rng).unwrap();
        voters.push(vs);
        records.push(rec);
    }
    let reg = finalize_registration(&pp, &records).unwrap();
    let mut ballots: Vec<Ballot> = Vec::new();
    for v in voters.iter().take(5) {
        let t = fake_compliance(&pp, v, 2, &mut rng).unwrap();
        ballots.push(build_fake_ballot(&pp, &t, &mut rng).unwrap());
        ballots.push(cast_vote(&pp, &reg, v, 0, &mut rng).unwrap());
    }
    for (i, v) in voters.iter().enumerate().skip(5) {
        ballots.push(cast_vote(&pp, &reg, v, 1 + (i as u64 % 2), &mut rng).unwrap());
    }
    for _ in (5 + voters.len())..n_ballots {
        ballots.push(chaff_ballot(&pp, &mut rng).unwrap());
    }
    // shuffled voter-side; the bench models an already-admitted board
    use rand::seq::SliceRandom;
    ballots.shuffle(&mut rng);
    let (admitted, openings) = admitted_from_ballots(&ballots);
    build_chunked_tally(&pp, &authority, &reg, &admitted, &openings, CHUNK_SIZE, &mut rng)
        .unwrap()
}

fn bench_chunked(c: &mut Criterion) {
    use cr_dr::zk::chunked::*;
    let vb = backend("filter_and_tally_vchunk128");
    let sb = backend("filter_and_tally_srun128");
    if !vb.toolchain_available() || !sb.toolchain_available() {
        eprintln!("SKIP chunked: chunk-circuit artifacts not found");
        return;
    }
    let Some(vr) = cr_dr::zk::groth16_backend::RapidsnarkBackend::discover(vb.clone()) else {
        eprintln!("SKIP chunked: rapidsnark prover not found");
        return;
    };
    let sr = cr_dr::zk::groth16_backend::RapidsnarkBackend::discover(sb.clone()).unwrap();

    let ct = build_chunked_instance(4000, 500);
    assert!(chunked_relation_check_native(&ct));
    eprintln!(
        "chunked instance: {} ballots on {} chunks x {} slots; tally {:?}",
        ct.statement.num_ballots, ct.k_chunks, ct.chunk_size, ct.statement.tally_counts
    );

    let mut g = c.benchmark_group("chunked");
    g.sample_size(10);

    // Per-circuit costs (chunk 0), rapidsnark prove from pre-generated witness.
    let vin = validity_chunk_input(&ct, 0);
    let vwork = tempfile::tempdir().unwrap();
    let vw = vb.generate_witness(&vin, vwork.path()).unwrap();
    let (vp, vpub) = vr.prove_witness(&vw, vwork.path()).unwrap();
    assert!(vr.verify(&vp, &vpub).unwrap());
    assert_eq!(
        vpub.as_array().unwrap().iter().map(|v| v.as_str().unwrap()).collect::<Vec<_>>(),
        validity_chunk_publics(&ct, 0).iter().map(|s| s.as_str()).collect::<Vec<_>>()
    );
    g.bench_function("validity_chunk_witness_wasm", |b| {
        b.iter(|| {
            let w = tempfile::tempdir().unwrap();
            vb.generate_witness(&vin, w.path()).unwrap()
        })
    });
    g.bench_function("validity_chunk_prove_rapidsnark", |b| {
        b.iter(|| vr.prove_witness(&vw, vwork.path()).unwrap())
    });

    let sin = sorted_run_input(&ct, 0);
    let swork = tempfile::tempdir().unwrap();
    let sw = sb.generate_witness(&sin, swork.path()).unwrap();
    let (sp, spub) = sr.prove_witness(&sw, swork.path()).unwrap();
    assert!(sr.verify(&sp, &spub).unwrap());
    assert_eq!(
        spub.as_array().unwrap().iter().map(|v| v.as_str().unwrap()).collect::<Vec<_>>(),
        sorted_run_publics(&ct, 0).iter().map(|s| s.as_str()).collect::<Vec<_>>()
    );
    g.bench_function("sorted_run_witness_wasm", |b| {
        b.iter(|| {
            let w = tempfile::tempdir().unwrap();
            sb.generate_witness(&sin, w.path()).unwrap()
        })
    });
    g.bench_function("sorted_run_prove_rapidsnark", |b| {
        b.iter(|| sr.prove_witness(&sw, swork.path()).unwrap())
    });
    g.finish();

    // End-to-end chunked prove (sequential, single machine), one timed run
    // per board size, plus full aggregate verification.
    for (seed, n_ballots, tsum) in [(4001u64, 500usize, "filter_and_tally_tsum4"),
                                    (4002, 1000, "filter_and_tally_tsum8")] {
        let tb = backend(tsum);
        if !tb.toolchain_available() {
            eprintln!("SKIP chunked e2e {n_ballots}: {tsum} artifacts missing");
            continue;
        }
        let tr = cr_dr::zk::groth16_backend::RapidsnarkBackend::discover(tb.clone()).unwrap();
        let ct = build_chunked_instance(seed, n_ballots);
        assert!(chunked_relation_check_native(&ct));
        let t0 = std::time::Instant::now();
        let mut proofs = Vec::new();
        for k in 0..ct.k_chunks {
            let w = tempfile::tempdir().unwrap();
            let wt = vb.generate_witness(&validity_chunk_input(&ct, k), w.path()).unwrap();
            proofs.push((vr.prove_witness(&wt, w.path()).unwrap(), "v", k));
            let w2 = tempfile::tempdir().unwrap();
            let wt2 = sb.generate_witness(&sorted_run_input(&ct, k), w2.path()).unwrap();
            proofs.push((sr.prove_witness(&wt2, w2.path()).unwrap(), "s", k));
        }
        let w3 = tempfile::tempdir().unwrap();
        let wt3 = tb.generate_witness(&tally_sum_input(&ct), w3.path()).unwrap();
        proofs.push((tr.prove_witness(&wt3, w3.path()).unwrap(), "t", 0));
        let prove_time = t0.elapsed();

        let t1 = std::time::Instant::now();
        let mut ok = true;
        for ((proof, public), kind, k) in &proofs {
            let (be, expected) = match *kind {
                "v" => (&vb, validity_chunk_publics(&ct, *k)),
                "s" => (&sb, sorted_run_publics(&ct, *k)),
                _ => (&tb, tally_sum_publics(&ct)),
            };
            ok &= be.verify(proof, public).unwrap();
            ok &= public.as_array().unwrap().iter().map(|v| v.as_str().unwrap()).eq(expected.iter().map(|s| s.as_str()));
        }
        let verify_time = t1.elapsed();
        assert!(ok, "aggregate verification failed");
        eprintln!(
            "chunked e2e: {} ballots, K={} -> {} proofs; sequential prove {:.1}s; \
             verify-all {:.1}s (per-proof snarkjs CLI, node startup dominated)",
            n_ballots, ct.k_chunks, proofs.len(), prove_time.as_secs_f64(), verify_time.as_secs_f64()
        );
    }
}
