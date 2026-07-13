//! FULL Tier-3 driver: proves the ENTIRE tally relation (validity + sort +
//! duplicate counting + tally) in one 3-party REP3 MPC via co-circom, over
//! a secret-shared witness. No `build_chunked_tally`; no process or
//! provider ever constructs the full witness, the decrypted opening set,
//! the R_EA values, the private/sorted records, the duplicate structure,
//! the partial tallies, or grand-product values — all of those are internal
//! wires of the monolithic circuit, computed inside MPC. Only the final
//! tally is revealed (the circuit's public output).
//!
//!     cargo run --release --bin prove_tier3_full -- --voters 60
//!
//! Requires co-circom + the `filter_and_tally_medium_mpc` artifacts
//! (scripts/compile_circuits.sh medium_mpc + scripts/setup_groth16.sh
//! medium_mpc) + demo TLS assets. HONESTY: three localhost parties are
//! cryptographically real but architecturally simulated (see
//! TIER3_DESIGN.md). The monolithic circuit holds nb = 128 ballots; for
//! N up to ~10^3 see the projection in BENCHMARKS.md "Tier-3".

use std::path::PathBuf;
use std::time::Instant;

use clap::Parser;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

use cr_dr::protocol::admission::admitted_from_ballots;
use cr_dr::protocol::chaff::chaff_ballot;
use cr_dr::protocol::fake_compliance::{build_fake_ballot, fake_compliance};
use cr_dr::protocol::filter_and_tally::filter_and_tally;
use cr_dr::protocol::preprocessing::{finalize_registration, preprocess_voter};
use cr_dr::protocol::setup::setup_election;
use cr_dr::protocol::vote::cast_vote;
use cr_dr::types::{DuplicateRule, ElectionConfig, ThresholdParams};
use cr_dr::zk::groth16_backend::SnarkjsBackend;
use cr_dr::zk::tier3::{full_providers, provider_leaks_r_ea, CoCircomBackend};

const NB: usize = 128; // filter_and_tally_medium_mpc holds 128 ballots
const DEPTH: usize = 6;
const CIRCUIT: &str = "filter_and_tally_medium_mpc";

#[derive(Parser)]
#[command(about = "Full Tier-3: whole tally relation proven in 3-party REP3 MPC")]
struct Args {
    /// Registered voters (board is padded to nb=128 slots).
    #[arg(long, default_value_t = 60)]
    voters: usize,
    #[arg(long, default_value_t = 6000)]
    seed: u64,
    #[arg(long, default_value_t = false)]
    dry_run: bool,
    #[arg(long)]
    tls_src: Option<PathBuf>,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let root = SnarkjsBackend::crate_root();
    let mut rng = ChaCha20Rng::seed_from_u64(args.seed);
    anyhow::ensure!(args.voters <= 64, "medium_mpc holds nb=128 ballots (<= 64 voters + fakes/chaff)");

    let config = ElectionConfig {
        eid: format!("tier3full-{}", args.voters),
        candidates: vec![0, 1, 2],
        max_voters: 64,
        max_ballots: NB,
        merkle_depth: DEPTH,
        duplicate_rule: DuplicateRule::FirstValidCounts,
        threshold_params: Some(ThresholdParams { t: 2, k: 3 }),
    };
    let t0 = Instant::now();
    let (pp, mut authority) = setup_election(config, &mut rng)?;
    let (mut voters, mut records) = (Vec::new(), Vec::new());
    for id in 0..args.voters as u64 {
        let (vs, rec) = preprocess_voter(&pp, &mut authority, id, &mut rng)?;
        voters.push(vs);
        records.push(rec);
    }
    let reg = finalize_registration(&pp, &records)?;

    let mut ballots = Vec::new();
    let n_fake = 2.min(voters.len());
    for v in voters.iter().take(n_fake) {
        let t = fake_compliance(&pp, v, 2, &mut rng)?;
        ballots.push(build_fake_ballot(&pp, &t, &mut rng)?);
        ballots.push(cast_vote(&pp, &reg, v, 0, &mut rng)?);
    }
    for (i, v) in voters.iter().enumerate().skip(n_fake) {
        ballots.push(cast_vote(&pp, &reg, v, 1 + (i as u64 % 2), &mut rng)?);
    }
    while ballots.len() < NB.min(2 * args.voters + 4) {
        ballots.push(chaff_ballot(&pp, &mut rng)?);
    }
    use rand::seq::SliceRandom;
    ballots.shuffle(&mut rng);

    let (admitted, openings) = admitted_from_ballots(&ballots);
    // Expected tally for the post-hoc cross-check ONLY (the benchmark
    // harness may know it; the MPC parties never do — they reveal it).
    let (expected, _) = filter_and_tally(&pp, &authority, &reg, &admitted, &openings)?;
    println!(
        "instance: {} voters, {} ballots -> nb={NB}; expected tally {:?}; setup {:.1}s",
        args.voters, admitted.len(), expected.counts, t0.elapsed().as_secs_f64()
    );

    let providers = full_providers(&pp, &authority, &reg, &admitted, &openings, NB, DEPTH)?;
    for (name, v) in [("opening", &providers.opening), ("authority_a", &providers.authority_a), ("authority_b", &providers.authority_b)] {
        anyhow::ensure!(!provider_leaks_r_ea(v), "provider {name} leaks R_EA");
    }
    anyhow::ensure!(providers.opening.get("tally_counts").is_none(), "opening must not supply the tally");
    println!("provider partition OK: no R_EA and no tally in any provider file; tally is the MPC output");

    if args.dry_run {
        let out = root.join("build/tier3/full_dryrun");
        std::fs::create_dir_all(&out)?;
        for (n, v) in [("opening.json", &providers.opening), ("authority_a.json", &providers.authority_a), ("authority_b.json", &providers.authority_b)] {
            std::fs::write(out.join(n), serde_json::to_vec_pretty(v)?)?;
        }
        println!("dry-run: wrote provider inputs to {}", out.display());
        return Ok(());
    }

    let Some(be) = CoCircomBackend::discover_named(&root, CIRCUIT) else {
        anyhow::bail!("co-circom / {CIRCUIT} artifacts not found (compile_circuits.sh medium_mpc + setup_groth16.sh medium_mpc)");
    };
    std::fs::create_dir_all(&be.assets_dir)?;
    if let Some(src) = args.tls_src.or_else(default_tls_src) {
        for i in 0..3 {
            for kind in ["key", "cert"] {
                let f = format!("{kind}{i}.der");
                let dst = be.assets_dir.join(&f);
                if !dst.exists() {
                    std::fs::copy(src.join(&f), &dst).ok();
                }
            }
        }
    }
    anyhow::ensure!(be.assets_dir.join("key0.der").exists(), "TLS assets missing; pass --tls-src");

    let work = be.assets_dir.join("full");
    std::fs::create_dir_all(&work)?;
    let t = Instant::now();
    let (proof, public) = be.prove_chunk(&providers, &work)?;
    let dt = t.elapsed().as_secs_f64();
    anyhow::ensure!(be.verify(&proof, &public)?, "full MPC proof failed to verify");

    // The revealed public output tally_counts (first nC public signals:
    // circom lists outputs before public inputs) must equal the expected
    // tally — the MPC computed the right result without any party seeing
    // the records/sort/duplicates.
    let got: serde_json::Value = serde_json::from_slice(&std::fs::read(&public)?)?;
    let arr = got.as_array().cloned().unwrap_or_default();
    let revealed: Vec<u64> = arr.iter().take(pp.candidates.len())
        .filter_map(|v| v.as_str().and_then(|s| s.parse::<u64>().ok())).collect();
    anyhow::ensure!(
        revealed == expected.counts,
        "MPC-revealed tally {revealed:?} != expected {:?}", expected.counts
    );
    println!(
        "FULL TIER-3 MPC: whole relation (validity+sort+duplicates+tally) proven in 3-party REP3 \
         in {dt:.1}s, verified. Revealed tally {revealed:?} (== expected). No party ever held the \
         witness, R_EA, the records, the sorted records, the duplicate structure, or partial tallies."
    );
    Ok(())
}

fn default_tls_src() -> Option<PathBuf> {
    let home = std::env::var("HOME").ok()?;
    let base = PathBuf::from(home).join(".cargo/git/checkouts");
    let co = std::fs::read_dir(&base).ok()?.filter_map(|e| e.ok())
        .find(|e| e.file_name().to_string_lossy().starts_with("co-snarks"))?;
    for sub in std::fs::read_dir(co.path()).ok()?.filter_map(|e| e.ok()) {
        for cand in ["co-circom/co-circom/examples/data", "co-noir/co-noir/examples/data"] {
            let d = sub.path().join(cand);
            if d.join("key0.der").exists() {
                return Some(d);
            }
        }
    }
    None
}
