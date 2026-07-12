//! TIER-3 (decentralized / coSNARK) driver: proves validity chunk(s) of
//! the tally relation in real 3-party REP3 MPC via TACEO co-circom, so no
//! single party ever holds R_EA or the cleartext witness.
//!
//!     cargo run --release --bin prove_tier3 -- --voters 100 [--chunks-proven 1]
//!
//! Requires: `co-circom` on PATH or at ~/.cargo/bin (or $CO_CIRCOM), the
//! MPC-chunk artifacts (`scripts/compile_circuits.sh vchunkmpc128` +
//! `scripts/setup_groth16.sh vchunkmpc128`), and the demo TLS assets
//! (auto-copied from the co-circom example checkout, or point --tls-src).
//!
//! HONESTY: three localhost processes = cryptographically real sharing,
//! architecturally simulated trust domains. See TIER3_DESIGN.md.

use std::path::PathBuf;
use std::time::Instant;

use clap::Parser;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

use cr_dr::protocol::admission::admitted_from_ballots;
use cr_dr::protocol::chaff::chaff_ballot;
use cr_dr::protocol::fake_compliance::{build_fake_ballot, fake_compliance};
use cr_dr::protocol::preprocessing::{finalize_registration, preprocess_voter};
use cr_dr::protocol::setup::setup_election;
use cr_dr::protocol::vote::cast_vote;
use cr_dr::types::{DuplicateRule, ElectionConfig, ThresholdParams};
use cr_dr::zk::chunked::{build_chunked_tally, validity_chunk_publics};
use cr_dr::zk::groth16_backend::SnarkjsBackend;
use cr_dr::zk::tier3::{chunk_providers, provider_leaks_r_ea, CoCircomBackend};

#[derive(Parser)]
#[command(about = "Tier-3 decentralized (3-party REP3 coSNARK) tally-chunk prover")]
struct Args {
    /// Registered voters (<= 16,384; N <= 10^3 is the benchmarked regime).
    #[arg(long, default_value_t = 100)]
    voters: usize,
    /// Board size in ballots (default: pad voters to a whole number of C=128 chunks).
    #[arg(long)]
    ballots: Option<usize>,
    /// How many validity chunks to actually prove in MPC (default 1; the
    /// rest are identical cost).
    #[arg(long, default_value_t = 1)]
    chunks_proven: usize,
    /// MPC validity-chunk slot width: 128 = full pipeline chunk, 8 = fast
    /// demo of the SAME relation (needs the matching vchunkmpc{width} zkey).
    #[arg(long, default_value_t = 128)]
    width: usize,
    #[arg(long, default_value_t = 5000)]
    seed: u64,
    /// Only build the instance and write the provider input files; no MPC.
    #[arg(long, default_value_t = false)]
    dry_run: bool,
    /// Directory holding demo TLS DER key/cert files to copy into build/tier3.
    #[arg(long)]
    tls_src: Option<PathBuf>,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let root = SnarkjsBackend::crate_root();
    let mut rng = ChaCha20Rng::seed_from_u64(args.seed);

    let board = args.ballots.unwrap_or_else(|| args.voters.div_ceil(args.width).max(1) * args.width);
    let config = ElectionConfig {
        eid: format!("tier3-{}", args.voters),
        candidates: vec![0, 1, 2],
        max_voters: 1 << 14,
        max_ballots: 1 << 24,
        merkle_depth: 14,
        duplicate_rule: DuplicateRule::FirstValidCounts,
        threshold_params: Some(ThresholdParams { t: 2, k: 3 }),
    };
    let t0 = Instant::now();
    let (pp, mut authority) = setup_election(config, &mut rng)?;
    let mut voters = Vec::new();
    let mut records = Vec::new();
    for id in 0..args.voters as u64 {
        let (vs, rec) = preprocess_voter(&pp, &mut authority, id, &mut rng)?;
        voters.push(vs);
        records.push(rec);
    }
    let reg = finalize_registration(&pp, &records)?;

    let mut ballots = Vec::new();
    let n_fake = 3.min(voters.len());
    for v in voters.iter().take(n_fake) {
        let t = fake_compliance(&pp, v, 2, &mut rng)?;
        ballots.push(build_fake_ballot(&pp, &t, &mut rng)?);
        ballots.push(cast_vote(&pp, &reg, v, 0, &mut rng)?);
    }
    for (i, v) in voters.iter().enumerate().skip(n_fake) {
        ballots.push(cast_vote(&pp, &reg, v, 1 + (i as u64 % 2), &mut rng)?);
    }
    while ballots.len() < board {
        ballots.push(chaff_ballot(&pp, &mut rng)?);
    }
    ballots.truncate(board);
    use rand::seq::SliceRandom;
    ballots.shuffle(&mut rng);

    let (admitted, openings) = admitted_from_ballots(&ballots);
    let ct = build_chunked_tally(&pp, &authority, &reg, &admitted, &openings, args.width, &mut rng)?;
    let k = ct.k_chunks;
    let to_prove = args.chunks_proven.min(k);
    println!(
        "instance: {} voters, {board} board slots, K={k} chunks; tally {:?}; setup {:.1}s",
        args.voters, ct.statement.tally_counts, t0.elapsed().as_secs_f64()
    );

    // Provider partition sanity: no provider file contains R_EA.
    let prov0 = chunk_providers(&ct, &authority, 0)?;
    for (name, v) in [("opening", &prov0.opening), ("authority_a", &prov0.authority_a), ("authority_b", &prov0.authority_b)] {
        anyhow::ensure!(!provider_leaks_r_ea(v), "provider {name} leaks R_EA");
    }
    println!("provider partition OK: R_EA appears in NO provider file (only separate shares a/b)");

    if args.dry_run {
        let out = root.join("build/tier3/dryrun");
        std::fs::create_dir_all(&out)?;
        std::fs::write(out.join("opening.json"), serde_json::to_vec_pretty(&prov0.opening)?)?;
        std::fs::write(out.join("authority_a.json"), serde_json::to_vec_pretty(&prov0.authority_a)?)?;
        std::fs::write(out.join("authority_b.json"), serde_json::to_vec_pretty(&prov0.authority_b)?)?;
        println!("dry-run: wrote chunk-0 provider inputs to {}", out.display());
        return Ok(());
    }

    let Some(be) = CoCircomBackend::discover_width(&root, args.width) else {
        anyhow::bail!(
            "co-circom / MPC-chunk artifacts not found. Install co-circom (cargo install \
             --git https://github.com/TaceoLabs/co-snarks co-circom) and run \
             scripts/compile_circuits.sh vchunkmpc128 + scripts/setup_groth16.sh vchunkmpc128."
        );
    };
    // Stage demo TLS assets.
    std::fs::create_dir_all(&be.assets_dir)?;
    let tls_src = args.tls_src.or_else(default_tls_src);
    if let Some(src) = tls_src {
        for i in 0..3 {
            for kind in ["key", "cert"] {
                let f = format!("{kind}{i}.der");
                let dst = be.assets_dir.join(&f);
                if !dst.exists() {
                    std::fs::copy(src.join(&f), &dst).map_err(|e| {
                        anyhow::anyhow!("copy TLS {f} from {}: {e}", src.display())
                    })?;
                }
            }
        }
    }
    anyhow::ensure!(
        be.assets_dir.join("key0.der").exists(),
        "TLS assets missing in {}; pass --tls-src pointing at co-circom example `data/` dir",
        be.assets_dir.display()
    );

    let mut total = 0.0;
    for kc in 0..to_prove {
        let providers = chunk_providers(&ct, &authority, kc)?;
        let work = be.assets_dir.join(format!("chunk{kc}"));
        std::fs::create_dir_all(&work)?;
        let t = Instant::now();
        let (proof, public) = be.prove_chunk(&providers, &work)?;
        let dt = t.elapsed().as_secs_f64();
        total += dt;
        anyhow::ensure!(be.verify(&proof, &public)?, "MPC proof for chunk {kc} failed to verify");
        // Bind the MPC proof to the same statement as the Tier-1 pipeline.
        let got: serde_json::Value = serde_json::from_slice(&std::fs::read(&public)?)?;
        let expected = validity_chunk_publics(&ct, kc);
        let got_arr = got.as_array().map(|a| a.iter().map(|v| v.as_str().unwrap_or("").to_string()).collect::<Vec<_>>()).unwrap_or_default();
        anyhow::ensure!(
            got_arr == expected,
            "chunk {kc}: MPC proof public inputs != Tier-1 validity_chunk_publics\n got={got_arr:?}\n exp={expected:?}"
        );
        println!("chunk {kc}: 3-party REP3 MPC prove+verify OK in {dt:.1}s (publics bound to the Tier-1 statement)");
    }
    println!(
        "TIER-3 MPC: proved {to_prove}/{k} validity chunks (rep3, 3 localhost parties) in {total:.1}s \
         total ({:.1}s/chunk); no party ever held R_EA or the cleartext witness.",
        total / to_prove.max(1) as f64
    );
    Ok(())
}

fn default_tls_src() -> Option<PathBuf> {
    // The co-circom example ships TLS DER assets under examples/data.
    let home = std::env::var("HOME").ok()?;
    let base = PathBuf::from(home).join(".cargo/git/checkouts");
    let co = std::fs::read_dir(&base).ok()?.filter_map(|e| e.ok()).find(|e| {
        e.file_name().to_string_lossy().starts_with("co-snarks")
    })?;
    // find <hash>/co-circom/co-circom/examples/data
    for sub in std::fs::read_dir(co.path()).ok()?.filter_map(|e| e.ok()) {
        let d = sub.path().join("co-circom/co-circom/examples/data");
        if d.join("key0.der").exists() {
            return Some(d);
        }
    }
    None
}
