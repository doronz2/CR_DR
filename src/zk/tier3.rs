//! TIER-3 (decentralized / coSNARK) proving of the tally-relation validity
//! chunk via TACEO co-circom.
//!
//! ## What this module does
//!
//! It (a) emits the per-chunk circuit inputs PARTITIONED ACROSS PROVIDERS
//! so that no single provider file ever contains R_EA, and (b) drives the
//! `co-circom` binary as a subprocess through the full 3-party REP3 flow:
//! `split-input` (per provider) -> `merge-input-shares` (per party) ->
//! `generate-witness` (MPC, 3 parties) -> `generate-proof groth16` (MPC,
//! 3 parties) -> `verify`. It reuses the SAME snarkjs `.zkey` produced by
//! `scripts/setup_groth16.sh vchunkmpc128`, and the resulting Groth16 proof
//! verifies under the standard verification key — it drops into the exact
//! same chunked aggregate verifier as a Tier-1 proof.
//!
//! ## The provider partition (why R_EA never concentrates)
//!
//! The Tier-3 circuit `ValidityChunkMpc` takes the two Shamir shares of
//! each ballot's R_EA as SEPARATELY-NAMED inputs `r_ea_share_a` /
//! `r_ea_share_b` and reconstructs R_EA in-circuit (LagrangeCombineT2).
//! Three input providers:
//!
//!   * OPENING provider — supplies the public inputs plus the ballot
//!     openings (`ct`, `pt`, `rho`), registration rows and paths, and
//!     `rc_blind`. NO R_EA material.
//!   * AUTHORITY 1 — supplies ONLY `r_ea_share_a` (Shamir share at index 1).
//!   * AUTHORITY 2 — supplies ONLY `r_ea_share_b` (Shamir share at index 2).
//!
//! Each provider `split-input`s only its own file; `merge-input-shares`
//! combines the co-indexed shares by name WITHOUT reconstructing any
//! plaintext union. R_EA exists as a value only inside the MPC witness
//! extension, never in any provider file and never in any single party.
//!
//! ## Honesty boundary (READ THIS)
//!
//! Running the three parties as three processes on ONE machine is
//! **cryptographically real but architecturally simulated**: the secret
//! sharing genuinely keeps each party's share files uninformative and the
//! witness is never materialized, but a single OS operator can read all
//! three processes' memory, so the "no single party sees the witness"
//! guarantee is a property of a DEPLOYMENT on independent trust domains,
//! not of this localhost run. The co-circom library is itself experimental
//! and un-audited, and its REP3 backend is honest-majority / semi-honest.
//! See TIER3_DESIGN.md.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::{json, Value};

use crate::errors::{CrDrError, Result};
use crate::types::{f_to_dec, f_to_u64, AuthoritySecretState, F, PLAINTEXT_FIELD_LEN};
use crate::zk::chunked::ChunkedTally;

/// The three provider input files for one validity chunk. Each is a
/// partial circom input JSON; none contains R_EA.
#[derive(Debug, Clone)]
pub struct ChunkProviderInputs {
    /// Public inputs + openings + registration + rc_blind (no R_EA).
    pub opening: Value,
    /// `{ "r_ea_share_a": [...] }` — authority 1's Shamir share (index 1).
    pub authority_a: Value,
    /// `{ "r_ea_share_b": [...] }` — authority 2's Shamir share (index 2).
    pub authority_b: Value,
}

fn dec(f: &F) -> Value {
    Value::String(f_to_dec(f))
}

/// Per-slot R_EA shares (index 1, index 2) for chunk `k`, pulled from the
/// authority's stored Shamir shares — NEVER reconstructed. For inactive /
/// out-of-range / padding slots the shares are (0, 0), matching the
/// Tier-1 witness's `r_ea = 0` for those slots. Asserts the in-circuit
/// combine `2*a - b` equals the Tier-1 reconstructed `r_ea`, so the MPC
/// computes exactly the same witness.
fn chunk_shares(
    ct: &ChunkedTally,
    authority: &AuthoritySecretState,
    k: usize,
) -> Result<(Vec<F>, Vec<F>)> {
    let c = ct.chunk_size;
    let rows = &ct.rows[k * c..(k + 1) * c];
    let num_voters = ct.statement.num_voters;
    let (mut a, mut b) = (Vec::with_capacity(c), Vec::with_capacity(c));
    for row in rows {
        let (sa, sb) = match f_to_u64(&row.pt_fields[1]) {
            Some(id) if id < num_voters => match authority.voter_secrets.get(&id) {
                Some(sec) if sec.r_ea_shares.len() >= 2 => {
                    (sec.r_ea_shares[0].value, sec.r_ea_shares[1].value)
                }
                _ => (F::from(0u64), F::from(0u64)),
            },
            _ => (F::from(0u64), F::from(0u64)),
        };
        // In-circuit combine (LagrangeCombineT2) must equal the Tier-1 r_ea.
        let combined = F::from(2u64) * sa - sb;
        if combined != row.r_ea {
            return Err(CrDrError::ZkToolchain(
                "Tier-3 share combine does not match the Tier-1 reconstructed R_EA".into(),
            ));
        }
        a.push(sa);
        b.push(sb);
    }
    Ok((a, b))
}

/// Build the three provider input files for validity chunk `k`. The
/// opening file mirrors `chunked::validity_chunk_input` MINUS the `r_ea`
/// array; the two authority files carry only their own share arrays.
pub fn chunk_providers(
    ct: &ChunkedTally,
    authority: &AuthoritySecretState,
    k: usize,
) -> Result<ChunkProviderInputs> {
    let c = ct.chunk_size;
    let rows = &ct.rows[k * c..(k + 1) * c];
    let (share_a, share_b) = chunk_shares(ct, authority, k)?;

    let opening = json!({
        "eid_hash": dec(&ct.statement.eid_hash),
        "mr": dec(&ct.statement.mr),
        "candidate_set_commitment": dec(&ct.statement.candidate_set_commitment),
        "num_ballots": ct.statement.num_ballots.to_string(),
        "num_voters": ct.statement.num_voters.to_string(),
        "duplicate_rule_id": ct.statement.duplicate_rule_id.to_string(),
        "chunk_base": (k * c).to_string(),
        "bb_in": dec(&ct.bb[k]),
        "bb_out": dec(&ct.bb[k + 1]),
        "rc": dec(&ct.rc[k]),
        "candidates": ct.candidates.iter().map(|x| x.to_string()).collect::<Vec<_>>(),
        "ct": rows.iter().map(|r| dec(&r.ct)).collect::<Vec<_>>(),
        "pt": rows.iter().map(|r| Value::Array(r.pt_fields.iter().map(dec).collect())).collect::<Vec<_>>(),
        "rho": rows.iter().map(|r| dec(&r.rho)).collect::<Vec<_>>(),
        "reg_vkx": rows.iter().map(|r| dec(&r.reg_vkx)).collect::<Vec<_>>(),
        "reg_vky": rows.iter().map(|r| dec(&r.reg_vky)).collect::<Vec<_>>(),
        "reg_h": rows.iter().map(|r| dec(&r.reg_h)).collect::<Vec<_>>(),
        "path_elements": rows.iter().map(|r| Value::Array(r.merkle_path.iter().map(dec).collect())).collect::<Vec<_>>(),
        "rc_blind": dec(&ct.rc_blind[k]),
    });
    let authority_a = json!({ "r_ea_share_a": share_a.iter().map(dec).collect::<Vec<_>>() });
    let authority_b = json!({ "r_ea_share_b": share_b.iter().map(dec).collect::<Vec<_>>() });
    Ok(ChunkProviderInputs { opening, authority_a, authority_b })
}

/// Assert a provider input file contains no R_EA plaintext key. Used by
/// tests as a regression guard on the partition.
pub fn provider_leaks_r_ea(v: &Value) -> bool {
    v.get("r_ea").is_some()
}

// ---------------------------------------------------------------------------
// FULL Tier-3: the whole monolithic relation in one MPC circuit
// ---------------------------------------------------------------------------

/// Build the three provider inputs for the FULL monolithic MPC relation
/// (`filter_and_tally_medium_mpc`, `FilterAndTallyMpc(nb, nC, depth)`),
/// WITHOUT `build_chunked_tally` and WITHOUT reconstructing R_EA. The
/// opening provider derives its rows from the ballot openings and the
/// PUBLIC registration table (validity records, the sort, duplicate
/// counting and the tally are all computed later inside the MPC — never
/// here); the two authority providers supply only their own Shamir-share
/// arrays. `tally_counts` is NOT supplied — it is the circuit's public
/// OUTPUT, computed in MPC and revealed.
///
/// No records, sorted records, duplicate structure, partial tallies or
/// grand-product values are ever constructed by this function or any
/// single party.
pub fn full_providers(
    pp: &crate::types::PublicParams,
    authority: &AuthoritySecretState,
    reg: &crate::protocol::preprocessing::RegistrationState,
    admitted: &crate::protocol::bulletin_board::AdmittedBoard,
    openings: &crate::protocol::admission::AdmittedOpenings,
    nb: usize,
    depth: usize,
) -> Result<ChunkProviderInputs> {
    use crate::crypto::hash::{bb_commitment, candidate_set_commitment, pk_ea_commitment};
    let num_ballots = admitted.len();
    let num_voters = reg.records.len() as u64;
    if num_ballots > nb {
        return Err(CrDrError::ZkToolchain(format!(
            "board has {num_ballots} ballots but the MPC circuit holds {nb}"
        )));
    }

    let zero = F::from(0u64);
    let (mut ct, mut pt, mut rho) = (Vec::new(), Vec::new(), Vec::new());
    let (mut vkx, mut vky, mut hh, mut paths) = (Vec::new(), Vec::new(), Vec::new(), Vec::new());
    let (mut sa, mut sb) = (Vec::new(), Vec::new());

    for j in 0..nb {
        if j < num_ballots {
            let (pt_fields, r) = crate::protocol::filter_and_tally::opening_checked(admitted, openings, j)?;
            ct.push(admitted.coms[j]);
            pt.push(pt_fields.to_vec());
            rho.push(r);
            // Registration row + path (PUBLIC) and R_EA shares, by claimed id.
            let id = f_to_u64(&pt_fields[1]);
            let (rvx, rvy, rh, path, share_a, share_b) = match id {
                Some(id) if id < num_voters => {
                    let rec = reg.record(id);
                    let path = reg
                        .paths
                        .get(&id)
                        .map(|p| p.elements.clone())
                        .unwrap_or_else(|| vec![zero; depth]);
                    let (ssa, ssb) = match authority.voter_secrets.get(&id) {
                        Some(s) if s.r_ea_shares.len() >= 2 => {
                            (s.r_ea_shares[0].value, s.r_ea_shares[1].value)
                        }
                        _ => (zero, zero),
                    };
                    match rec {
                        Some(r) => (r.vk.x, r.vk.y, r.h, path, ssa, ssb),
                        None => (zero, zero, zero, vec![zero; depth], zero, zero),
                    }
                }
                _ => (zero, zero, zero, vec![zero; depth], zero, zero),
            };
            vkx.push(rvx);
            vky.push(rvy);
            hh.push(rh);
            paths.push(path);
            sa.push(share_a);
            sb.push(share_b);
        } else {
            // padding slot (circuit gates active = 0)
            ct.push(zero);
            pt.push(vec![zero; PLAINTEXT_FIELD_LEN]);
            rho.push(zero);
            vkx.push(zero);
            vky.push(zero);
            hh.push(zero);
            paths.push(vec![zero; depth]);
            sa.push(zero);
            sb.push(zero);
        }
    }

    let ct_fields: Vec<Vec<F>> = admitted.coms.iter().map(|c| vec![*c]).collect();
    let opening = json!({
        "eid_hash": dec(&pp.eid_hash),
        "mr": dec(&reg.root),
        "candidate_set_commitment": dec(&candidate_set_commitment(&pp.candidates)),
        "bb_commitment": dec(&bb_commitment(&ct_fields)),
        "num_ballots": num_ballots.to_string(),
        "num_voters": num_voters.to_string(),
        "duplicate_rule_id": pp.duplicate_rule.id().to_string(),
        "pk_ea_commitment": dec(&pk_ea_commitment(&pp.pk_ea)),
        "candidates": pp.candidates.iter().map(|x| x.to_string()).collect::<Vec<_>>(),
        "ct": ct.iter().map(dec).collect::<Vec<_>>(),
        "pt": pt.iter().map(|r| Value::Array(r.iter().map(dec).collect())).collect::<Vec<_>>(),
        "rho": rho.iter().map(dec).collect::<Vec<_>>(),
        "reg_vkx": vkx.iter().map(dec).collect::<Vec<_>>(),
        "reg_vky": vky.iter().map(dec).collect::<Vec<_>>(),
        "reg_h": hh.iter().map(dec).collect::<Vec<_>>(),
        "path_elements": paths.iter().map(|p| Value::Array(p.iter().map(dec).collect())).collect::<Vec<_>>(),
    });
    let authority_a = json!({ "r_ea_share_a": sa.iter().map(dec).collect::<Vec<_>>() });
    let authority_b = json!({ "r_ea_share_b": sb.iter().map(dec).collect::<Vec<_>>() });
    Ok(ChunkProviderInputs { opening, authority_a, authority_b })
}

// ---------------------------------------------------------------------------
// co-circom subprocess orchestration
// ---------------------------------------------------------------------------

/// Configuration for driving the `co-circom` binary in 3-party REP3 mode
/// on localhost. `assets_dir` holds the demo TLS DER key/cert files and is
/// where per-party network configs are written.
#[derive(Debug, Clone)]
pub struct CoCircomBackend {
    pub bin: PathBuf,          // co-circom binary
    pub circuit: PathBuf,      // .circom source (co-circom compiles it in its MPC-VM)
    pub zkey: PathBuf,         // snarkjs .zkey (reused unchanged)
    pub vk: PathBuf,           // verification_key.json
    pub link_library: PathBuf, // circomlib include root (node_modules)
    pub assets_dir: PathBuf,   // TLS certs/keys + generated party configs
    pub base_port: u16,
}

impl CoCircomBackend {
    /// Discover a co-circom install and the MPC validity-chunk artifacts
    /// of the given slot width (128 = full pipeline chunk, 8 = fast demo
    /// of the same relation) under `crate_root`. Returns None if the binary
    /// or the artifacts are absent (so callers/tests SKIP rather than fail).
    pub fn discover_width(crate_root: &Path, width: usize) -> Option<Self> {
        let bin = which_co_circom()?;
        let build = crate_root.join("build/circuits");
        let name = format!("filter_and_tally_vchunkmpc{width}");
        let zkey = build.join(format!("{name}.zkey"));
        let vk = build.join(format!("{name}_verification_key.json"));
        let circuit = crate_root.join(format!("circuits/main/{name}.circom"));
        if !zkey.exists() || !vk.exists() || !circuit.exists() {
            return None;
        }
        Some(CoCircomBackend {
            bin,
            circuit,
            zkey,
            vk,
            link_library: crate_root.join("node_modules"),
            assets_dir: crate_root.join("build/tier3"),
            base_port: 20000,
        })
    }

    /// The full-width (C=128) MPC chunk.
    pub fn discover(crate_root: &Path) -> Option<Self> {
        Self::discover_width(crate_root, 128)
    }

    /// Discover the co-circom install and the artifacts for an arbitrary
    /// MPC circuit `name` (e.g. `filter_and_tally_medium_mpc`, the full
    /// monolithic relation) under `crate_root`.
    pub fn discover_named(crate_root: &Path, name: &str) -> Option<Self> {
        let bin = which_co_circom()?;
        let build = crate_root.join("build/circuits");
        let zkey = build.join(format!("{name}.zkey"));
        let vk = build.join(format!("{name}_verification_key.json"));
        let circuit = crate_root.join(format!("circuits/main/{name}.circom"));
        if !zkey.exists() || !vk.exists() || !circuit.exists() {
            return None;
        }
        Some(CoCircomBackend {
            bin,
            circuit,
            zkey,
            vk,
            link_library: crate_root.join("node_modules"),
            assets_dir: crate_root.join("build/tier3"),
            base_port: 20000,
        })
    }

    pub fn available(&self) -> bool {
        self.bin.exists() && self.zkey.exists() && self.circuit.exists()
    }

    /// A minimal compiler-only config (used by split-input / merge).
    fn compiler_config(&self) -> String {
        format!(
            "[compiler]\nallow_leaky_loops = true\nlink_library = [{:?}]\n\n[vm]\nallow_leaky_logs = true\n",
            self.link_library.to_string_lossy()
        )
    }

    /// Per-party network config (compiler + vm + [network] with TLS).
    fn party_config(&self, my_id: usize) -> String {
        let mut parties = String::new();
        for id in 0..3 {
            parties.push_str(&format!(
                "\n[[network.parties]]\nid = {id}\ndns_name = \"127.0.0.1:{}\"\n",
                self.base_port + id as u16
            ));
        }
        let certs: Vec<String> = (0..3)
            .map(|i| format!("{:?}", self.assets_dir.join(format!("cert{i}.der")).to_string_lossy()))
            .collect();
        format!(
            "[compiler]\nallow_leaky_loops = true\nlink_library = [{:?}]\n\n\
             [vm]\nallow_leaky_logs = true\n\n\
             [network]\nmy_id = {my_id}\nbind_addr = \"0.0.0.0:{}\"\n{parties}\n\
             [network.tls]\nkey = {:?}\ncerts = [{}]\n",
            self.link_library.to_string_lossy(),
            self.base_port + my_id as u16,
            self.assets_dir.join(format!("key{my_id}.der")).to_string_lossy(),
            certs.join(", "),
        )
    }

    /// Write the compiler config and the three party network configs into
    /// `assets_dir`. TLS DER key/cert files must already be present there
    /// (copied from the co-circom example assets by `prove_tier3`).
    pub fn write_configs(&self) -> Result<(PathBuf, [PathBuf; 3])> {
        std::fs::create_dir_all(&self.assets_dir).map_err(io)?;
        let cc = self.assets_dir.join("compiler.toml");
        std::fs::write(&cc, self.compiler_config()).map_err(io)?;
        let parties = [
            self.assets_dir.join("party0.toml"),
            self.assets_dir.join("party1.toml"),
            self.assets_dir.join("party2.toml"),
        ];
        for (i, p) in parties.iter().enumerate() {
            std::fs::write(p, self.party_config(i)).map_err(io)?;
        }
        Ok((cc, parties))
    }

    fn run(&self, args: &[&str]) -> Result<()> {
        let out = Command::new(&self.bin)
            .args(args)
            .output()
            .map_err(|e| CrDrError::ZkToolchain(format!("co-circom spawn failed: {e}")))?;
        if !out.status.success() {
            return Err(CrDrError::ZkToolchain(format!(
                "co-circom {} failed:\n{}",
                args.first().copied().unwrap_or(""),
                String::from_utf8_lossy(&out.stderr)
            )));
        }
        Ok(())
    }

    /// Full 3-party REP3 proof of ONE validity chunk from its provider
    /// inputs. Steps, in `work` (must exist): each provider `split-input`s
    /// only its own file; per party the co-indexed shares are merged; the
    /// witness is extended in MPC (3 parties, parallel, over TLS); the
    /// Groth16 proof is produced in MPC (3 parties, parallel), reusing the
    /// snarkjs `.zkey`. Returns `(proof.json, public_input.json)` from
    /// party 0 (all parties emit the identical proof). No plaintext witness
    /// or R_EA is ever written.
    pub fn prove_chunk(
        &self,
        providers: &ChunkProviderInputs,
        work: &Path,
    ) -> Result<(PathBuf, PathBuf)> {
        let (compiler_cfg, party_cfgs) = self.write_configs()?;
        let circ = self.circuit.to_string_lossy().to_string();
        let cc = compiler_cfg.to_string_lossy().to_string();

        // Provider input files.
        let files = [
            ("opening.json", &providers.opening),
            ("authority_a.json", &providers.authority_a),
            ("authority_b.json", &providers.authority_b),
        ];
        for (name, v) in files {
            std::fs::write(work.join(name), serde_json::to_vec_pretty(v).unwrap()).map_err(io)?;
        }

        // 1. Each provider splits ONLY its own input into 3 shares.
        for (name, _) in files {
            let inp = work.join(name).to_string_lossy().to_string();
            self.run(&[
                "split-input", "--circuit", &circ, "--input", &inp, "--protocol", "REP3",
                "--curve", "BN254", "--out-dir", &work.to_string_lossy(), "--config", &cc,
            ])?;
        }

        // 2. Per party: merge the co-indexed provider shares (by name).
        for party in 0..3 {
            let sa = work.join(format!("opening.json.{party}.shared")).to_string_lossy().to_string();
            let sb = work.join(format!("authority_a.json.{party}.shared")).to_string_lossy().to_string();
            let scf = work.join(format!("authority_b.json.{party}.shared")).to_string_lossy().to_string();
            let out = work.join(format!("input.{party}.shared")).to_string_lossy().to_string();
            self.run(&[
                "merge-input-shares", "--circuit", &circ, "--inputs", &sa, "--inputs", &sb,
                "--inputs", &scf, "--protocol", "REP3", "--curve", "BN254", "--out", &out,
                "--config", &cc,
            ])?;
        }

        // 3. MPC witness extension — 3 parties in parallel over TLS.
        self.parallel_parties(&party_cfgs, |party, cfg| {
            let inp = work.join(format!("input.{party}.shared")).to_string_lossy().to_string();
            let out = work.join(format!("witness.{party}.shared")).to_string_lossy().to_string();
            vec![
                "generate-witness".into(), "-O2".into(), "--input".into(), inp,
                "--circuit".into(), circ.clone(), "--protocol".into(), "REP3".into(),
                "--curve".into(), "BN254".into(), "--config".into(), cfg, "--out".into(), out,
            ]
        })?;

        // 4. MPC Groth16 proving — 3 parties in parallel, reusing the zkey.
        let zkey = self.zkey.to_string_lossy().to_string();
        let proof0 = work.join("proof.0.json");
        let public0 = work.join("public_input.json");
        self.parallel_parties(&party_cfgs, |party, cfg| {
            let wit = work.join(format!("witness.{party}.shared")).to_string_lossy().to_string();
            let out = work.join(format!("proof.{party}.json")).to_string_lossy().to_string();
            let mut a: Vec<String> = vec![
                "generate-proof".into(), "groth16".into(), "--witness".into(), wit,
                "--zkey".into(), zkey.clone(), "--protocol".into(), "REP3".into(),
                "--curve".into(), "BN254".into(), "--config".into(), cfg, "--out".into(), out,
            ];
            if party == 0 {
                a.push("--public-input".into());
                a.push(public0.to_string_lossy().to_string());
            }
            a
        })?;
        Ok((proof0, public0))
    }

    /// Standard (non-MPC) Groth16 verification of a co-circom proof under
    /// the verification key — a plain Groth16 proof anyone can check.
    pub fn verify(&self, proof: &Path, public: &Path) -> Result<bool> {
        let out = Command::new(&self.bin)
            .args([
                "verify", "groth16", "--proof", &proof.to_string_lossy(), "--vk",
                &self.vk.to_string_lossy(), "--public-input", &public.to_string_lossy(),
                "--curve", "BN254",
            ])
            .output()
            .map_err(|e| CrDrError::ZkToolchain(format!("co-circom verify spawn failed: {e}")))?;
        Ok(out.status.success())
    }

    /// Run one co-circom invocation per party (party index + its config
    /// path) concurrently; fail if any party fails.
    fn parallel_parties<Fb>(&self, party_cfgs: &[PathBuf; 3], build_args: Fb) -> Result<()>
    where
        Fb: Fn(usize, String) -> Vec<String> + Sync,
    {
        let errs: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());
        std::thread::scope(|s| {
            for party in 0..3 {
                let cfg = party_cfgs[party].to_string_lossy().to_string();
                let args = build_args(party, cfg);
                let errs = &errs;
                let bin = &self.bin;
                s.spawn(move || {
                    let out = Command::new(bin).args(&args).output();
                    match out {
                        Ok(o) if o.status.success() => {}
                        Ok(o) => errs.lock().unwrap().push(format!(
                            "party {party}: {}",
                            String::from_utf8_lossy(&o.stderr)
                        )),
                        Err(e) => errs.lock().unwrap().push(format!("party {party}: spawn {e}")),
                    }
                });
            }
        });
        let errs = errs.into_inner().unwrap();
        if !errs.is_empty() {
            return Err(CrDrError::ZkToolchain(format!("MPC party failure:\n{}", errs.join("\n"))));
        }
        Ok(())
    }
}

fn io(e: std::io::Error) -> CrDrError {
    CrDrError::ZkToolchain(format!("tier3 io: {e}"))
}

fn which_co_circom() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("CO_CIRCOM") {
        let pb = PathBuf::from(p);
        if pb.exists() {
            return Some(pb);
        }
    }
    let home = std::env::var("HOME").ok()?;
    let cand = PathBuf::from(home).join(".cargo/bin/co-circom");
    cand.exists().then_some(cand)
}
