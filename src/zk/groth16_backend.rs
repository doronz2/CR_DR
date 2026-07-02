//! Groth16 proving/verification by shelling out to the snarkjs CLI (the
//! spec-permitted alternative to ark-circom; chosen for toolchain
//! stability). Artifacts are produced by scripts/compile_circuits.sh and
//! scripts/setup_groth16.sh:
//!
//!   build/circuits/<name>_js/<name>.wasm + generate_witness.js
//!   build/circuits/<name>.zkey
//!   build/circuits/<name>_verification_key.json
//!
//! DEV-ONLY trusted setup — see README.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

use crate::errors::{CrDrError, Result};

/// Default circuit name for the small checked-in variant.
pub const SMALL_CIRCUIT: &str = "filter_and_tally_small";

#[derive(Debug, Clone)]
pub struct SnarkjsBackend {
    /// Repo root (containing build/, node_modules/, scripts/).
    pub root: PathBuf,
    /// Circuit name, e.g. "filter_and_tally_small".
    pub circuit: String,
}

impl SnarkjsBackend {
    pub fn small(root: impl Into<PathBuf>) -> Self {
        SnarkjsBackend { root: root.into(), circuit: SMALL_CIRCUIT.to_string() }
    }

    /// Repo root when running from the crate itself (tests, demo binary).
    pub fn crate_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
    }

    fn build_dir(&self) -> PathBuf {
        self.root.join("build/circuits")
    }

    fn wasm(&self) -> PathBuf {
        self.build_dir().join(format!("{0}_js/{0}.wasm", self.circuit))
    }

    fn witness_js(&self) -> PathBuf {
        self.build_dir().join(format!("{}_js/generate_witness.js", self.circuit))
    }

    fn zkey(&self) -> PathBuf {
        self.build_dir().join(format!("{}.zkey", self.circuit))
    }

    fn vkey(&self) -> PathBuf {
        self.build_dir().join(format!("{}_verification_key.json", self.circuit))
    }

    fn snarkjs_cli(&self) -> PathBuf {
        self.root.join("node_modules/snarkjs/cli.js")
    }

    /// True iff every artifact needed to prove and verify is present.
    pub fn toolchain_available(&self) -> bool {
        self.wasm().exists()
            && self.witness_js().exists()
            && self.zkey().exists()
            && self.vkey().exists()
            && self.snarkjs_cli().exists()
            && which_node().is_some()
    }

    /// Generate a witness only (no proof). Errors if the input does not
    /// satisfy the circuit's hard constraints.
    pub fn generate_witness(&self, input: &Value, work: &Path) -> Result<PathBuf> {
        let input_path = work.join("input.json");
        std::fs::write(&input_path, serde_json::to_vec_pretty(input)?)?;
        let wtns = work.join("witness.wtns");
        run(Command::new(node())
            .arg(self.witness_js())
            .arg(self.wasm())
            .arg(&input_path)
            .arg(&wtns))?;
        Ok(wtns)
    }

    /// Full Groth16 prove: returns (proof.json, public.json) values.
    pub fn prove(&self, input: &Value) -> Result<(Value, Value)> {
        let work = tempdir()?;
        let wtns = self.generate_witness(input, &work)?;
        let proof_path = work.join("proof.json");
        let public_path = work.join("public.json");
        run(Command::new(node())
            .arg(self.snarkjs_cli())
            .arg("groth16")
            .arg("prove")
            .arg(self.zkey())
            .arg(&wtns)
            .arg(&proof_path)
            .arg(&public_path))?;
        let proof: Value = serde_json::from_slice(&std::fs::read(&proof_path)?)?;
        let public: Value = serde_json::from_slice(&std::fs::read(&public_path)?)?;
        std::fs::remove_dir_all(&work).ok();
        Ok((proof, public))
    }

    /// Verify a proof against public inputs. Returns Ok(false) on a proof or
    /// public-input mismatch (snarkjs "INVALID"), Err on toolchain failures.
    pub fn verify(&self, proof: &Value, public: &Value) -> Result<bool> {
        let work = tempdir()?;
        let proof_path = work.join("proof.json");
        let public_path = work.join("public.json");
        std::fs::write(&proof_path, serde_json::to_vec_pretty(proof)?)?;
        std::fs::write(&public_path, serde_json::to_vec_pretty(public)?)?;
        let out = Command::new(node())
            .arg(self.snarkjs_cli())
            .arg("groth16")
            .arg("verify")
            .arg(self.vkey())
            .arg(&public_path)
            .arg(&proof_path)
            .output()?;
        std::fs::remove_dir_all(&work).ok();
        let stdout = String::from_utf8_lossy(&out.stdout);
        if out.status.success() && stdout.contains("OK") {
            Ok(true)
        } else if stdout.contains("INVALID") || !out.status.success() {
            Ok(false)
        } else {
            Err(CrDrError::ZkToolchain(format!("unexpected snarkjs output: {stdout}")))
        }
    }
}

fn node() -> String {
    "node".to_string()
}

fn which_node() -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path).map(|p| p.join("node")).find(|p| p.exists())
}

fn tempdir() -> Result<PathBuf> {
    let dir = std::env::temp_dir().join(format!("cr_dr_zk_{}", std::process::id()))
        .join(format!("{}", nanos()));
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn nanos() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

fn run(cmd: &mut Command) -> Result<()> {
    let out = cmd.output()?;
    if !out.status.success() {
        return Err(CrDrError::ZkToolchain(format!(
            "command {:?} failed:\nstdout: {}\nstderr: {}",
            cmd,
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        )));
    }
    Ok(())
}
