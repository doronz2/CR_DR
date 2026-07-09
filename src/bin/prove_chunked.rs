//! Parallel single-machine driver for the CHUNKED tally pipeline: builds a
//! synthetic election at a target board size, proves all chunks in
//! parallel (rapidsnark), and verifies the aggregate.
//!
//!     cargo run --release --bin prove_chunked -- --ballots 20480 [--jobs J]
//!
//! Sizing: J concurrent chunk jobs, default max(1, cores/6) — rapidsnark
//! multithreads each prove (~6 effective cores), so cores/6 concurrent
//! proves saturate the machine without thrashing. Requires the chunk
//! circuit artifacts (vchunk128, srun128, tsum{K}) and the rapidsnark
//! prover (scripts/install_rapidsnark.sh).
//!
//! Registration uses the compiled depth-6 chunk circuits (<= 64 voters);
//! the BOARD size is the cost driver (K = B/128 chunk proofs). Deeper
//! registration trees for 10^4+ real voters add ~250 constraints per
//! extra Merkle level per slot (~+25% at depth 14) — see BENCHMARKS.md.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::Instant;

use clap::Parser;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

use cr_dr::protocol::admission::admitted_from_ballots;
use cr_dr::protocol::bulletin_board::AnonymousChannel;
use cr_dr::protocol::chaff::chaff_ballot;
use cr_dr::protocol::fake_compliance::{build_fake_ballot, fake_compliance};
use cr_dr::protocol::preprocessing::{finalize_registration, preprocess_voter};
use cr_dr::protocol::setup::setup_election;
use cr_dr::protocol::vote::cast_vote;
use cr_dr::types::{DuplicateRule, ElectionConfig, ThresholdParams};
use cr_dr::zk::chunked::*;
use cr_dr::zk::groth16_backend::{RapidsnarkBackend, SnarkjsBackend};

#[derive(Parser)]
#[command(about = "Parallel chunked-tally prover (single machine, Tier 1)")]
struct Args {
    /// Board size in ballots (K = ceil(ballots/128) chunks).
    #[arg(long, default_value_t = 20480)]
    ballots: usize,
    /// Registered voters (compiled chunk circuits support <= 64).
    #[arg(long, default_value_t = 64)]
    voters: usize,
    /// Concurrent chunk jobs (default: cores/6, rapidsnark is multithreaded).
    #[arg(long)]
    jobs: Option<usize>,
    /// RNG seed (instance is synthetic and deterministic given the seed).
    #[arg(long, default_value_t = 5000)]
    seed: u64,
    /// Skip proving; only build the instance and check it natively.
    #[arg(long, default_value_t = false)]
    dry_run: bool,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let cores = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(8);
    let jobs = args.jobs.unwrap_or_else(|| (cores / 6).max(1));

    // ---- instance construction (native pipeline) ----
    let t0 = Instant::now();
    let mut rng = ChaCha20Rng::seed_from_u64(args.seed);
    let config = ElectionConfig {
        eid: format!("chunked-{}", args.ballots),
        candidates: vec![0, 1, 2],
        max_voters: 64,
        max_ballots: 1 << 24,
        merkle_depth: 6,
        duplicate_rule: DuplicateRule::FirstValidCounts,
        threshold_params: Some(ThresholdParams { t: 2, k: 3 }),
    };
    let (pp, mut authority) = setup_election(config, &mut rng)?;
    let mut voters = Vec::new();
    let mut records = Vec::new();
    for id in 0..args.voters as u64 {
        let (vs, rec) = preprocess_voter(&pp, &mut authority, id, &mut rng)?;
        voters.push(vs);
        records.push(rec);
    }
    let reg = finalize_registration(&pp, &records)?;

    // Ballots shuffled voter-side (the driver models an already-admitted
    // board; admission-path costs are benchmarked separately).
    let _ = AnonymousChannel::new();
    let mut ballots = Vec::new();
    let n_fake = 5.min(voters.len());
    for v in voters.iter().take(n_fake) {
        let t = fake_compliance(&pp, v, 2, &mut rng)?;
        ballots.push(build_fake_ballot(&pp, &t, &mut rng)?);
        ballots.push(cast_vote(&pp, &reg, v, 0, &mut rng)?);
    }
    for (i, v) in voters.iter().enumerate().skip(n_fake) {
        ballots.push(cast_vote(&pp, &reg, v, 1 + (i as u64 % 2), &mut rng)?);
    }
    for _ in (n_fake + voters.len())..args.ballots {
        ballots.push(chaff_ballot(&pp, &mut rng)?);
    }
    use rand::seq::SliceRandom;
    ballots.shuffle(&mut rng);
    let gen_time = t0.elapsed();

    let t1 = Instant::now();
    let (admitted, openings) = admitted_from_ballots(&ballots);
    let ct = build_chunked_tally(&pp, &authority, &reg, &admitted, &openings, CHUNK_SIZE, &mut rng)?;
    anyhow::ensure!(chunked_relation_check_native(&ct), "native chunked relation must accept");
    let build_time = t1.elapsed();
    let k = ct.k_chunks;
    println!(
        "instance: {} ballots, {} voters, K={} chunks; tally {:?}",
        args.ballots, args.voters, k, ct.statement.tally_counts
    );
    println!(
        "ballot generation {:.1}s; witness+records+commitments {:.1}s; \
         native relation check OK; jobs={jobs} (of {cores} cores)",
        gen_time.as_secs_f64(),
        build_time.as_secs_f64()
    );
    if args.dry_run {
        return Ok(());
    }

    // ---- backends ----
    let root = SnarkjsBackend::crate_root();
    let mk = |name: &str| SnarkjsBackend { root: root.clone(), circuit: name.into() };
    let vb = mk("filter_and_tally_vchunk128");
    let sb = mk("filter_and_tally_srun128");
    let tb = mk(&format!("filter_and_tally_tsum{k}"));
    for b in [&vb, &sb, &tb] {
        anyhow::ensure!(b.toolchain_available(), "missing artifacts for {}", b.circuit);
    }
    let vr = RapidsnarkBackend::discover(vb.clone())
        .ok_or_else(|| anyhow::anyhow!("rapidsnark prover not found"))?;
    let sr = RapidsnarkBackend::discover(sb.clone()).unwrap();
    let tr = RapidsnarkBackend::discover(tb.clone()).unwrap();

    // ---- parallel proving: work items 0..K = validity, K..2K = sorted runs,
    //      2K = tally sum ----
    let t2 = Instant::now();
    let next = AtomicUsize::new(0);
    let done = AtomicUsize::new(0);
    let total = 2 * k + 1;
    let proofs: Mutex<Vec<Option<(serde_json::Value, serde_json::Value)>>> =
        Mutex::new(vec![None; total]);
    let errors: Mutex<Vec<String>> = Mutex::new(Vec::new());

    std::thread::scope(|scope| {
        for _ in 0..jobs {
            scope.spawn(|| loop {
                let i = next.fetch_add(1, Ordering::Relaxed);
                if i >= total {
                    return;
                }
                let run = || -> anyhow::Result<(serde_json::Value, serde_json::Value)> {
                    let work = tempfile::tempdir()?;
                    let (be, rp, input) = if i < k {
                        (&vb, &vr, validity_chunk_input(&ct, i))
                    } else if i < 2 * k {
                        (&sb, &sr, sorted_run_input(&ct, i - k))
                    } else {
                        (&tb, &tr, tally_sum_input(&ct))
                    };
                    let wtns = be.generate_witness(&input, work.path())?;
                    Ok(rp.prove_witness(&wtns, work.path())?)
                };
                match run() {
                    Ok(pv) => {
                        proofs.lock().unwrap()[i] = Some(pv);
                        let d = done.fetch_add(1, Ordering::Relaxed) + 1;
                        if d % 20 == 0 || d == total {
                            eprintln!("  proved {d}/{total} ({:.0}s)", t2.elapsed().as_secs_f64());
                        }
                    }
                    Err(e) => errors.lock().unwrap().push(format!("item {i}: {e}")),
                }
            });
        }
    });
    let errs = errors.into_inner().unwrap();
    anyhow::ensure!(errs.is_empty(), "proving failures: {errs:?}");
    let prove_time = t2.elapsed();
    let proofs = proofs.into_inner().unwrap();

    // ---- aggregate verification ----
    let t3 = Instant::now();
    let mut ok = true;
    for (i, pv) in proofs.iter().enumerate() {
        let (proof, public) = pv.as_ref().expect("all proved");
        let (be, expected) = if i < k {
            (&vb, validity_chunk_publics(&ct, i))
        } else if i < 2 * k {
            (&sb, sorted_run_publics(&ct, i - k))
        } else {
            (&tb, tally_sum_publics(&ct))
        };
        ok &= public
            .as_array()
            .map(|a| a.iter().map(|v| v.as_str().unwrap_or("")).eq(expected.iter().map(|s| s.as_str())))
            .unwrap_or(false);
        ok &= be.verify(proof, public)?;
    }
    let verify_time = t3.elapsed();
    anyhow::ensure!(ok, "aggregate verification failed");

    println!(
        "PROVED {} ballots (K={k}, {total} proofs): prove {:.1}s wall ({:.2}s/chunk-pair \
         amortized), verify-all {:.1}s (per-proof snarkjs CLI), total {:.1}s",
        args.ballots,
        prove_time.as_secs_f64(),
        prove_time.as_secs_f64() / k as f64,
        verify_time.as_secs_f64(),
        (gen_time + build_time + prove_time).as_secs_f64(),
    );
    Ok(())
}
