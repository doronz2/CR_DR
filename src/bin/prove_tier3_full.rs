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
use cr_dr::zk::tier3::{full_providers, merged_input, provider_leaks_r_ea, CoCircomBackend};

#[derive(Parser)]
#[command(about = "Full Tier-3: whole tally relation proven in 3-party REP3 MPC")]
struct Args {
    /// Registered voters (board is padded to nb slots).
    #[arg(long, default_value_t = 60)]
    voters: usize,
    /// Monolithic circuit variant.
    #[arg(long, default_value = "filter_and_tally_medium_mpc")]
    circuit: String,
    /// Board slots nb of the chosen circuit (medium_mpc=128, small_mpc=16).
    #[arg(long, default_value_t = 128)]
    nb: usize,
    /// Merkle depth of the chosen circuit (medium_mpc=6, small_mpc=4).
    #[arg(long, default_value_t = 6)]
    depth: usize,
    /// circom optimisation level for MPC witness extension.
    #[arg(long, default_value = "O2")]
    opt: String,
    /// "full-mpc" = decentralize BOTH witness extension and proving (the
    /// genuine Tier-3 path; currently blocked by a co-circom v0.10.0 bug in
    /// the duplicate/tally witness extension). "proving-mpc" = decentralize
    /// only PROVING over a centrally-computed witness (completes + verifies;
    /// see the honesty note it prints).
    #[arg(long, default_value = "full-mpc")]
    mode: String,
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
    anyhow::ensure!(2 * args.voters + 4 <= args.nb, "too many voters for nb slots");

    let config = ElectionConfig {
        eid: format!("tier3full-{}", args.voters),
        candidates: vec![0, 1, 2],
        max_voters: (1usize << args.depth).min(64),
        max_ballots: args.nb,
        merkle_depth: args.depth,
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
    while ballots.len() < args.nb.min(2 * args.voters + 4) {
        ballots.push(chaff_ballot(&pp, &mut rng)?);
    }
    use rand::seq::SliceRandom;
    ballots.shuffle(&mut rng);

    let (admitted, openings) = admitted_from_ballots(&ballots);
    // Expected tally for the post-hoc cross-check ONLY (the benchmark
    // harness may know it; the MPC parties never do — they reveal it).
    let (expected, _) = filter_and_tally(&pp, &authority, &reg, &admitted, &openings)?;
    println!(
        "instance: {} voters, {} ballots -> nb={}; expected tally {:?}; setup {:.1}s",
        args.voters, admitted.len(), args.nb, expected.counts, t0.elapsed().as_secs_f64()
    );

    let providers = full_providers(&pp, &authority, &reg, &admitted, &openings, args.nb, args.depth)?;
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

    let Some(mut be) = CoCircomBackend::discover_named(&root, &args.circuit) else {
        anyhow::bail!("co-circom / {} artifacts not found", args.circuit);
    };
    be.witext_opt = args.opt.clone();
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
    let (proof, public) = match args.mode.as_str() {
        "full-mpc" => {
            // Genuine Tier-3: decentralize witness extension AND proving.
            match be.prove_chunk(&providers, &work) {
                Ok(pp) => pp,
                Err(e) => {
                    eprintln!(
                        "\nFULL-MPC witness extension failed. co-circom v0.10.0 miscompiles the \n\
                         duplicate/tally stage of the monolithic circuit (the VALIDITY relation \n\
                         works fully in MPC — see `prove_tier3`). The circuit + provider partition \n\
                         are proven correct (snarkjs proves+verifies; co-circom collaborative \n\
                         proving on a split witness verifies). Re-run with `--mode proving-mpc` to \n\
                         decentralize PROVING over a centrally-computed witness. See TIER3_DESIGN.md.\n\
                         co-circom error: {e}"
                    );
                    return Err(anyhow::anyhow!("full-mpc witness extension blocked by co-circom v0.10.0"));
                }
            }
        }
        "proving-mpc" => {
            println!(
                "NOTE: --mode proving-mpc computes the extended witness with ONE snarkjs process \n\
                 (NOT decentralized) then runs 3-party MPC Groth16 proving over its shares. This \n\
                 demonstrates decentralized PROVING of the full relation; witness extension is \n\
                 central here due to a co-circom v0.10.0 limitation. Use `prove_tier3` for the \n\
                 fully-decentralized (incl. witness extension) VALIDITY relation."
            );
            be.prove_collaborative(&merged_input(&providers), &work)?
        }
        other => anyhow::bail!("unknown --mode {other} (full-mpc | proving-mpc)"),
    };
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
    match args.mode.as_str() {
        "full-mpc" => println!(
            "FULL TIER-3 MPC: whole relation (validity+sort+duplicates+tally) proven in 3-party \
             REP3 in {dt:.1}s, verified. Revealed tally {revealed:?} (== expected). No party ever \
             held the witness, R_EA, the records, sorted records, duplicate structure or partial \
             tallies — all internal to the MPC; only the tally was revealed."
        ),
        _ => println!(
            "FULL RELATION, MPC PROVING: whole relation (validity+sort+duplicates+tally) proven in \
             3-party REP3 in {dt:.1}s, verified; revealed tally {revealed:?} (== expected). \
             DECENTRALIZED: the Groth16 proving ran on witness SHARES. NOT decentralized here: the \
             extended witness was computed by one snarkjs process (co-circom v0.10.0 cannot yet \
             MPC-extend this circuit's duplicate/tally stage), so that step saw the records/tally. \
             The VALIDITY relation is fully decentralized incl. witness extension (`prove_tier3`)."
        ),
    }
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
