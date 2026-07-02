//! `cr_dr` — CLI for the CR-DR reference implementation.
//!
//! Every protocol procedure is independently invocable; state is persisted
//! as JSON under an election directory (default `./election`):
//!
//! ```text
//! election/
//!   public/params.json           public parameters
//!   public/registration_records.json   appended by register-voter
//!   public/registration.json     Merkle tree state (after finalize)
//!   public/board.json            the bulletin board
//!   public/tally.json            public tally
//!   public/statement.json        public ZK statement
//!   authority/secret.json        EA SECRET state (R_EA,i live here)
//!   voters/<id>.json             per-voter SECRET state (sk_i, R_i)
//!   channel.json                 pending anonymous-channel submissions
//!   proofs/proof.json,public.json
//! ```
//!
//! The directory split mirrors the trust model: `public/` is what everyone
//! sees; `authority/` never leaves the EA; `voters/<id>.json` never leaves
//! voter i (and structurally cannot contain R_EA,i).

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};

use cr_dr::disputes::judge::JudgeReport;
use cr_dr::disputes::recorded_as_cast::{
    adjudicate_recorded_as_cast, check_direct, ea_issue_receipt, verify_receipt,
    SubmissionReceipt,
};
use cr_dr::disputes::tallied_as_recorded::{
    judge_tallied_as_recorded, AuthorityEvidence, NonceSource, TalliedAsRecordedComplaint,
};
use cr_dr::protocol::bulletin_board::{AnonymousChannel, BulletinBoard};
use cr_dr::protocol::chaff::chaff_ballot;
use cr_dr::protocol::fake_compliance::{
    build_fake_ballot, fake_compliance, FakeComplianceTranscript,
};
use cr_dr::protocol::filter_and_tally::filter_and_tally;
use cr_dr::protocol::preprocessing::{
    finalize_registration, preprocess_voter, preprocess_voter_cut_and_choose, RegistrationState,
};
use cr_dr::protocol::setup::setup_election;
use cr_dr::protocol::vote::cast_vote;
use cr_dr::types::{
    AuthoritySecretState, Ballot, DuplicateRule, ElectionConfig, PublicParams,
    PublicRegistrationRecord, TallyResult, ThresholdParams, VoterState,
};
use cr_dr::zk::circom_io::generate_witness_input;
use cr_dr::zk::groth16_backend::SnarkjsBackend;
use cr_dr::zk::mock_backend::relation_check_native;
use cr_dr::zk::statement::{build_tally_statement, TallyStatement};
use cr_dr::zk::witness::build_tally_witness;
use cr_dr::zk::SMALL_SHAPE;

#[derive(Parser)]
#[command(
    name = "cr_dr",
    about = "Coercion-Resistant Voting with Private Dispute Resolution — research prototype CLI",
    long_about = "Research prototype of the CR-DR construction. Each subcommand runs one \
                  protocol procedure independently; state lives in an election directory. \
                  NOT production cryptography."
)]
struct Cli {
    /// Election state directory.
    #[arg(long, global = true, default_value = "election")]
    dir: PathBuf,

    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// [EA] Create a new election: public parameters + authority secret state.
    Setup {
        #[arg(long, default_value = "cr-dr-election")]
        eid: String,
        /// Comma-separated candidate values, e.g. 0,1,2
        #[arg(long, default_value = "0,1,2", value_delimiter = ',')]
        candidates: Vec<u64>,
        #[arg(long, default_value_t = 8)]
        max_voters: usize,
        #[arg(long, default_value_t = 16)]
        max_ballots: usize,
        #[arg(long, default_value_t = 4)]
        merkle_depth: usize,
        /// Optional threshold parameters "t,k" for sharing the authority nonces.
        #[arg(long)]
        threshold: Option<String>,
    },

    /// [EA+voter] Preprocessing: register a voter. Writes the voter's secret
    /// state (sk_i, R_i — never R_EA,i) and the public registration record.
    RegisterVoter {
        #[arg(long)]
        id: u64,
        /// Run the cut-and-choose audit with q candidate pairs.
        #[arg(long)]
        cut_and_choose: Option<usize>,
    },

    /// [EA] Freeze registration: build the Merkle tree over all records.
    FinalizeRegistration,

    /// [voter] Cast a real vote: produces a ballot file (submit it with `submit`).
    Vote {
        #[arg(long)]
        voter: u64,
        #[arg(long)]
        candidate: u64,
        /// Output ballot file.
        #[arg(long, default_value = "ballot.json")]
        out: PathBuf,
    },

    /// [coerced voter] Fake compliance: produce the transcript surrendered to
    /// the coercer (real sk_i, FAKE nonce, valid signature on the demanded vote).
    FakeCompliance {
        #[arg(long)]
        voter: u64,
        /// The candidate the coercer demands.
        #[arg(long)]
        candidate: u64,
        #[arg(long, default_value = "coercer_transcript.json")]
        out: PathBuf,
    },

    /// [coercer] Build the fake ballot from a fake-compliance transcript.
    BuildFakeBallot {
        #[arg(long, default_value = "coercer_transcript.json")]
        transcript: PathBuf,
        #[arg(long, default_value = "fake_ballot.json")]
        out: PathBuf,
    },

    /// [anyone] Generate chaff ballots (rejected by tally, indistinguishable
    /// from fake-compliance ballots).
    Chaff {
        #[arg(long, default_value_t = 1)]
        count: usize,
        /// Output file (single) or prefix (multiple => <prefix>_<n>.json).
        #[arg(long, default_value = "chaff_ballot.json")]
        out: PathBuf,
    },

    /// [anyone] Submit a ballot file into the anonymous channel.
    Submit {
        #[arg(long)]
        ballot: PathBuf,
    },

    /// [channel] Flush the anonymous channel onto the bulletin board:
    /// sender identities dropped, order shuffled, bytes preserved.
    FlushChannel,

    /// [public] Show the bulletin board (public bytes only).
    ShowBoard,

    /// [EA] Run exact FilterAndTally; publish ONLY the tally + statement.
    Tally,

    /// [EA] Produce the Groth16 proof of the exact tally relation.
    Prove,

    /// [public] Verify the published tally proof against the statement.
    Verify {
        #[arg(long, default_value = "election/proofs/proof.json")]
        proof: PathBuf,
        #[arg(long, default_value = "election/proofs/public.json")]
        public: PathBuf,
    },

    /// [voter, private] Recorded-as-cast: check exact ballot bytes on the board.
    CheckRecorded {
        #[arg(long)]
        ballot: PathBuf,
    },

    /// [EA] Issue a submission receipt Sign_EA(eid, ballot_hash, timestamp).
    IssueReceipt {
        #[arg(long)]
        ballot: PathBuf,
        #[arg(long)]
        timestamp: u64,
        #[arg(long, default_value = "receipt.json")]
        out: PathBuf,
    },

    /// [judge, private] Adjudicate a recorded-as-cast complaint.
    DisputeRecorded {
        #[arg(long)]
        ballot: PathBuf,
        #[arg(long)]
        receipt: Option<PathBuf>,
    },

    /// [judge, private] Adjudicate a tallied-as-recorded complaint. The judge
    /// obtains R_EA,i from the EA (or reconstructs it from threshold shares
    /// with --use-threshold); the complainant NEVER sees it.
    DisputeTally {
        #[arg(long)]
        ballot: PathBuf,
        /// Reconstruct R_EA,i from t threshold shares instead of asking the
        /// EA directly (requires `share-nonces` to have run).
        #[arg(long)]
        use_threshold: bool,
    },

    /// [EA/dealer] Trusted-dealer Shamir: split every R_EA,i into k shares
    /// with threshold t.
    ShareNonces {
        #[arg(long)]
        t: usize,
        #[arg(long)]
        k: usize,
    },

    /// Run the full end-to-end demo in memory (no state directory needed).
    Demo,
}

// ---------------------------------------------------------------------------
// state I/O
// ---------------------------------------------------------------------------

struct Paths {
    dir: PathBuf,
}

impl Paths {
    fn public(&self) -> PathBuf {
        self.dir.join("public")
    }
    fn params(&self) -> PathBuf {
        self.public().join("params.json")
    }
    fn authority(&self) -> PathBuf {
        self.dir.join("authority/secret.json")
    }
    fn voter(&self, id: u64) -> PathBuf {
        self.dir.join(format!("voters/{id}.json"))
    }
    fn reg_records(&self) -> PathBuf {
        self.public().join("registration_records.json")
    }
    fn registration(&self) -> PathBuf {
        self.public().join("registration.json")
    }
    fn board(&self) -> PathBuf {
        self.public().join("board.json")
    }
    fn channel(&self) -> PathBuf {
        self.dir.join("channel.json")
    }
    fn tally(&self) -> PathBuf {
        self.public().join("tally.json")
    }
    fn statement(&self) -> PathBuf {
        self.public().join("statement.json")
    }
    fn proofs(&self) -> PathBuf {
        self.dir.join("proofs")
    }
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path, what: &str) -> Result<T> {
    let bytes = std::fs::read(path)
        .with_context(|| format!("missing {what} at {} (run the prerequisite step first)", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("failed to parse {what}"))
}

fn write_json<T: serde::Serialize>(path: &Path, value: &T) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, serde_json::to_vec_pretty(value)?)?;
    Ok(())
}

fn read_json_or_default<T: serde::de::DeserializeOwned + Default>(path: &Path) -> Result<T> {
    if path.exists() {
        Ok(serde_json::from_slice(&std::fs::read(path)?)?)
    } else {
        Ok(T::default())
    }
}

// ---------------------------------------------------------------------------

fn main() -> Result<()> {
    let cli = Cli::parse();
    let paths = Paths { dir: cli.dir.clone() };
    let mut rng = rand::rngs::OsRng;

    match cli.command {
        Cmd::Setup { eid, candidates, max_voters, max_ballots, merkle_depth, threshold } => {
            if paths.params().exists() {
                bail!("election already set up at {} (delete the directory to restart)", cli.dir.display());
            }
            let threshold_params = match threshold {
                Some(s) => {
                    let parts: Vec<usize> =
                        s.split(',').map(|p| p.trim().parse()).collect::<Result<_, _>>()?;
                    if parts.len() != 2 {
                        bail!("--threshold expects \"t,k\"");
                    }
                    Some(ThresholdParams { t: parts[0], k: parts[1] })
                }
                None => None,
            };
            let (pp, authority) = setup_election(
                ElectionConfig {
                    eid,
                    candidates,
                    max_voters,
                    max_ballots,
                    merkle_depth,
                    duplicate_rule: DuplicateRule::FirstValidCounts,
                    threshold_params,
                },
                &mut rng,
            )?;
            write_json(&paths.params(), &pp)?;
            write_json(&paths.authority(), &authority)?;
            write_json(&paths.reg_records(), &Vec::<PublicRegistrationRecord>::new())?;
            println!("election '{}' created in {}", pp.eid, cli.dir.display());
            println!("candidates: {:?}; duplicate rule: first-valid-counts", pp.candidates);
        }

        Cmd::RegisterVoter { id, cut_and_choose } => {
            let pp: PublicParams = read_json(&paths.params(), "public params")?;
            let mut authority: AuthoritySecretState =
                read_json(&paths.authority(), "authority secret state")?;
            if paths.registration().exists() {
                bail!("registration is already finalized");
            }
            let (voter, record) = match cut_and_choose {
                Some(q) => {
                    let (v, r, transcript) =
                        preprocess_voter_cut_and_choose(&pp, &mut authority, id, q, &mut rng)?;
                    println!(
                        "cut-and-choose: audited {} of {} candidate pairs, all consistent",
                        transcript.opened.len(),
                        transcript.q
                    );
                    (v, r)
                }
                None => preprocess_voter(&pp, &mut authority, id, &mut rng)?,
            };
            let mut records: Vec<PublicRegistrationRecord> =
                read_json(&paths.reg_records(), "registration records")?;
            records.push(record.clone());
            write_json(&paths.voter(id), &voter)?;
            write_json(&paths.authority(), &authority)?;
            write_json(&paths.reg_records(), &records)?;
            println!("voter {id} registered");
            println!("  voter secret  -> {} (sk_i, R_i; NO R_EA)", paths.voter(id).display());
            println!("  public record -> h_i = {}", cr_dr::types::f_to_dec(&record.h));
        }

        Cmd::FinalizeRegistration => {
            let pp: PublicParams = read_json(&paths.params(), "public params")?;
            let records: Vec<PublicRegistrationRecord> =
                read_json(&paths.reg_records(), "registration records")?;
            let reg = finalize_registration(&pp, &records)?;
            write_json(&paths.registration(), &reg)?;
            println!(
                "registration finalized: {} voters, Merkle root MR = {}",
                reg.records.len(),
                cr_dr::types::f_to_dec(&reg.root)
            );
        }

        Cmd::Vote { voter, candidate, out } => {
            let pp: PublicParams = read_json(&paths.params(), "public params")?;
            let reg: RegistrationState = read_json(&paths.registration(), "registration")?;
            let vs: VoterState = read_json(&paths.voter(voter), "voter secret state")?;
            let ballot = cast_vote(&pp, &reg, &vs, candidate, &mut rng)?;
            write_json(&out, &ballot)?;
            println!("real ballot for voter {voter} (candidate {candidate}) -> {}", out.display());
            println!("submit it anonymously with: cr_dr submit --ballot {}", out.display());
        }

        Cmd::FakeCompliance { voter, candidate, out } => {
            let pp: PublicParams = read_json(&paths.params(), "public params")?;
            let vs: VoterState = read_json(&paths.voter(voter), "voter secret state")?;
            let transcript = fake_compliance(&pp, &vs, candidate, &mut rng)?;
            write_json(&out, &transcript)?;
            println!("fake-compliance transcript -> {}", out.display());
            println!("  contains: REAL sk_{voter}, FAKE nonce R*, valid signature on candidate {candidate}");
            println!("  the coercer can verify the signature but cannot test R* (no R_EA,{voter})");
        }

        Cmd::BuildFakeBallot { transcript, out } => {
            let pp: PublicParams = read_json(&paths.params(), "public params")?;
            let t: FakeComplianceTranscript = read_json(&transcript, "fake-compliance transcript")?;
            let ballot = build_fake_ballot(&pp, &t, &mut rng)?;
            write_json(&out, &ballot)?;
            println!("fake ballot -> {} (will be rejected by FilterAndTally)", out.display());
        }

        Cmd::Chaff { count, out } => {
            let pp: PublicParams = read_json(&paths.params(), "public params")?;
            for n in 0..count {
                let ballot = chaff_ballot(&pp, &mut rng)?;
                let path = if count == 1 {
                    out.clone()
                } else {
                    let stem = out.file_stem().unwrap_or_default().to_string_lossy();
                    out.with_file_name(format!("{stem}_{n}.json"))
                };
                write_json(&path, &ballot)?;
                println!("chaff ballot -> {}", path.display());
            }
        }

        Cmd::Submit { ballot } => {
            let b: Ballot = read_json(&ballot, "ballot")?;
            let mut channel: AnonymousChannel = read_json_or_default(&paths.channel())?;
            channel.submit(b);
            write_json(&paths.channel(), &channel)?;
            println!("ballot queued in the anonymous channel (flush with `cr_dr flush-channel`)");
        }

        Cmd::FlushChannel => {
            let mut channel: AnonymousChannel = read_json_or_default(&paths.channel())?;
            let mut board: BulletinBoard = read_json_or_default(&paths.board())?;
            let ballots = channel.flush_shuffled(&mut rng);
            let n = ballots.len();
            for b in ballots {
                board.append(b);
            }
            write_json(&paths.board(), &board)?;
            write_json(&paths.channel(), &channel)?;
            println!("{n} ballot(s) posted to the board in shuffled order (bytes preserved)");
            println!("board now holds {} ballot(s)", board.len());
        }

        Cmd::ShowBoard => {
            let board: BulletinBoard = read_json_or_default(&paths.board())?;
            println!("bulletin board: {} ballot(s)", board.len());
            for (i, b) in board.list_public_ballots().iter().enumerate() {
                println!("  [{i}] {}", hex::encode(&b.bytes));
            }
        }

        Cmd::Tally => {
            let pp: PublicParams = read_json(&paths.params(), "public params")?;
            let authority: AuthoritySecretState =
                read_json(&paths.authority(), "authority secret state")?;
            let reg: RegistrationState = read_json(&paths.registration(), "registration")?;
            let board: BulletinBoard = read_json_or_default(&paths.board())?;
            let (tally, _internal) =
                filter_and_tally(&pp, &authority, &reg, board.list_public_ballots())?;
            let statement = build_tally_statement(&pp, &board, &reg, &tally);
            write_json(&paths.tally(), &tally)?;
            write_json(&paths.statement(), &statement)?;
            // ONLY public output is printed; the internal log is dropped.
            println!("FilterAndTally over {} posted ballot(s):", board.len());
            for (c, n) in pp.candidates.iter().zip(&tally.counts) {
                println!("  candidate {c}: {n}");
            }
            println!("counted ballots: {}", tally.counted_ballots);
            println!("public statement -> {}", paths.statement().display());
        }

        Cmd::Prove => {
            let pp: PublicParams = read_json(&paths.params(), "public params")?;
            let authority: AuthoritySecretState =
                read_json(&paths.authority(), "authority secret state")?;
            let reg: RegistrationState = read_json(&paths.registration(), "registration")?;
            let board: BulletinBoard = read_json_or_default(&paths.board())?;
            let statement: TallyStatement =
                read_json(&paths.statement(), "public statement (run `tally` first)")?;
            let witness = build_tally_witness(&pp, &authority, &reg, board.list_public_ballots())?;
            if !relation_check_native(&statement, &witness, &SMALL_SHAPE) {
                bail!("native relation check failed — statement and board disagree");
            }
            let backend = SnarkjsBackend::small(SnarkjsBackend::crate_root());
            if !backend.toolchain_available() {
                bail!(
                    "Groth16 artifacts missing. Run:\n  scripts/install_circom_deps.sh\n  \
                     scripts/compile_circuits.sh small\n  scripts/setup_groth16.sh small"
                );
            }
            let input = generate_witness_input(&statement, &witness, &SMALL_SHAPE)?;
            println!("native relation check: ACCEPT; generating Groth16 proof...");
            let (proof, public) = backend.prove(&input)?;
            write_json(&paths.proofs().join("proof.json"), &proof)?;
            write_json(&paths.proofs().join("public.json"), &public)?;
            println!("proof -> {}", paths.proofs().join("proof.json").display());
        }

        Cmd::Verify { proof, public } => {
            let backend = SnarkjsBackend::small(SnarkjsBackend::crate_root());
            if !backend.toolchain_available() {
                bail!("Groth16 artifacts missing (compile + setup first)");
            }
            let proof_v: serde_json::Value = read_json(&proof, "proof")?;
            let public_v: serde_json::Value = read_json(&public, "public inputs")?;
            if backend.verify(&proof_v, &public_v)? {
                println!("VERIFIED: the published tally is the exact FilterAndTally output");
            } else {
                println!("INVALID: proof does not verify against these public inputs");
                std::process::exit(1);
            }
        }

        Cmd::CheckRecorded { ballot } => {
            let board: BulletinBoard = read_json_or_default(&paths.board())?;
            let b: Ballot = read_json(&ballot, "ballot")?;
            if check_direct(&board, &b.bytes) {
                println!("RECORDED: exact ballot bytes are on the board");
                println!("(keep this result private — never show the real ballot to a coercer)");
            } else {
                println!("NOT RECORDED: ballot bytes not found on the board");
                std::process::exit(1);
            }
        }

        Cmd::IssueReceipt { ballot, timestamp, out } => {
            let pp: PublicParams = read_json(&paths.params(), "public params")?;
            let authority: AuthoritySecretState =
                read_json(&paths.authority(), "authority secret state")?;
            let b: Ballot = read_json(&ballot, "ballot")?;
            let receipt = ea_issue_receipt(&pp, &authority, &b, timestamp, &mut rng);
            write_json(&out, &receipt)?;
            println!("EA submission receipt -> {}", out.display());
        }

        Cmd::DisputeRecorded { ballot, receipt } => {
            let pp: PublicParams = read_json(&paths.params(), "public params")?;
            let board: BulletinBoard = read_json_or_default(&paths.board())?;
            let b: Ballot = read_json(&ballot, "ballot")?;
            let rc: Option<SubmissionReceipt> = match receipt {
                Some(p) => {
                    let r: SubmissionReceipt = read_json(&p, "receipt")?;
                    if !verify_receipt(&pp, &r) {
                        bail!("receipt signature is invalid");
                    }
                    Some(r)
                }
                None => None,
            };
            print_judge_report(&adjudicate_recorded_as_cast(&pp, &board, &b, rc.as_ref()));
        }

        Cmd::DisputeTally { ballot, use_threshold } => {
            let pp: PublicParams = read_json(&paths.params(), "public params")?;
            let authority: AuthoritySecretState =
                read_json(&paths.authority(), "authority secret state")?;
            let reg: RegistrationState = read_json(&paths.registration(), "registration")?;
            let board: BulletinBoard = read_json_or_default(&paths.board())?;
            let b: Ballot = read_json(&ballot, "ballot")?;

            // The complainant supplies the ballot + opening (here: the
            // opening travels inside the ballot's EA payload).
            let opening = cr_dr::crypto::encryption::commit_open(&b.ciphertext, &b.ea_payload)
                .map_err(|_| anyhow::anyhow!("ballot does not open; complaint malformed"))?;
            let pt = cr_dr::types::BallotPlaintext::from_fields(&opening.plaintext_fields)?;

            // Judge-private evidence from the authority side.
            let (_, evals) = filter_and_tally(&pp, &authority, &reg, board.list_public_ballots())?;
            let nonce_source = if use_threshold {
                let shares = authority
                    .threshold_nonce_shares
                    .as_ref()
                    .context("no threshold shares (run `share-nonces` first)")?
                    .get(&pt.id)
                    .context("no shares for this voter")?;
                let tp = pp.threshold_params.context("no threshold params in this election")?;
                NonceSource::ThresholdShares(shares[..tp.t].to_vec())
            } else {
                let secret = authority
                    .voter_secrets
                    .get(&pt.id)
                    .context("voter unknown to the authority")?;
                NonceSource::Direct(secret.r_ea)
            };
            let proof_path = paths.proofs().join("proof.json");
            let public_path = paths.proofs().join("public.json");
            let backend = SnarkjsBackend::small(SnarkjsBackend::crate_root());
            let tally_proof_valid = if proof_path.exists() && backend.toolchain_available() {
                let proof: serde_json::Value = read_json(&proof_path, "proof")?;
                let public: serde_json::Value = read_json(&public_path, "public inputs")?;
                backend.verify(&proof, &public)?
            } else {
                println!("(no tally proof found/verifiable; assuming it verifies)");
                true
            };

            let complaint = TalliedAsRecordedComplaint { ballot: b, opening };
            let evidence = AuthorityEvidence {
                nonce_source,
                prior_evaluations: &evals,
                tally_proof_valid,
            };
            print_judge_report(&judge_tallied_as_recorded(&pp, &reg, &board, &complaint, &evidence));
        }

        Cmd::ShareNonces { t, k } => {
            let mut authority: AuthoritySecretState =
                read_json(&paths.authority(), "authority secret state")?;
            cr_dr::threshold::trusted_dealer::share_all_nonces(
                &mut authority,
                ThresholdParams { t, k },
                &mut rng,
            )?;
            // Record the params in public params if absent.
            let mut pp: PublicParams = read_json(&paths.params(), "public params")?;
            pp.threshold_params = Some(ThresholdParams { t, k });
            write_json(&paths.params(), &pp)?;
            write_json(&paths.authority(), &authority)?;
            println!("all authority nonces R_EA,i Shamir-shared with t={t}, k={k}");
            println!("(any {t} shares reconstruct; {} shares reveal nothing)", t - 1);
        }

        Cmd::Demo => demo()?,
    }
    Ok(())
}

fn print_judge_report(report: &JudgeReport) {
    println!("JUDGE-PRIVATE verdict: {:?}", report.verdict);
    println!("  detail (judge eyes only, see README on verdict leakage): {}", report.detail);
}

// ---------------------------------------------------------------------------
// end-to-end in-memory demo
// ---------------------------------------------------------------------------

fn demo() -> Result<()> {
    use rand::SeedableRng;
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(2026);

    println!("=== CR-DR end-to-end demo (in memory) ===\n");
    let (pp, mut authority) = setup_election(
        ElectionConfig {
            eid: "demo-election-2026".into(),
            candidates: vec![0, 1, 2],
            max_voters: 8,
            max_ballots: 16,
            merkle_depth: 4,
            duplicate_rule: DuplicateRule::FirstValidCounts,
            threshold_params: None,
        },
        &mut rng,
    )?;

    let mut voters = Vec::new();
    let mut records = Vec::new();
    for id in 0..6u64 {
        let (vs, rec) = preprocess_voter(&pp, &mut authority, id, &mut rng)?;
        voters.push(vs);
        records.push(rec);
    }
    let reg = finalize_registration(&pp, &records)?;
    println!("6 voters registered; MR = {}\n", cr_dr::types::f_to_dec(&reg.root));

    println!("voter 0 is coerced: surrenders real sk_0 + FAKE nonce, coercer demands candidate 2");
    let mut channel = AnonymousChannel::new();
    let coerced = &voters[0];
    let transcript = fake_compliance(&pp, coerced, 2, &mut rng)?;
    channel.submit(build_fake_ballot(&pp, &transcript, &mut rng)?);
    println!("voter 0 then casts the REAL vote (candidate 0) through the anonymous channel");
    channel.submit(cast_vote(&pp, &reg, coerced, 0, &mut rng)?);
    for (voter, cand) in voters[1..].iter().zip([0u64, 1, 1, 2, 0]) {
        channel.submit(cast_vote(&pp, &reg, voter, cand, &mut rng)?);
    }
    for _ in 0..3 {
        channel.submit(chaff_ballot(&pp, &mut rng)?);
    }

    let mut bb = BulletinBoard::new();
    for ballot in channel.flush_shuffled(&mut rng) {
        bb.append(ballot);
    }
    println!("\nbulletin board: {} ballots (6 real + 1 fake + 3 chaff, shuffled)\n", bb.len());

    let (tally, _internal): (TallyResult, _) =
        filter_and_tally(&pp, &authority, &reg, bb.list_public_ballots())?;
    println!("public tally: candidates {:?} -> {:?} ({} counted)", pp.candidates, tally.counts, tally.counted_ballots);
    println!("  (fake + chaff rejected silently; voter 0's REAL vote counted)\n");

    let statement = build_tally_statement(&pp, &bb, &reg, &tally);
    let witness = build_tally_witness(&pp, &authority, &reg, bb.list_public_ballots())?;
    let ok = relation_check_native(&statement, &witness, &SMALL_SHAPE);
    println!("native FilterAndTally relation check: {}", if ok { "ACCEPT" } else { "REJECT" });

    let backend = SnarkjsBackend::small(SnarkjsBackend::crate_root());
    if backend.toolchain_available() {
        let input = generate_witness_input(&statement, &witness, &SMALL_SHAPE)?;
        println!("generating Groth16 proof (snarkjs)...");
        let (proof, public) = backend.prove(&input)?;
        println!("groth16 proof verified: {}", backend.verify(&proof, &public)?);
    } else {
        println!("(groth16 artifacts not found; run scripts/compile_circuits.sh + setup_groth16.sh)");
    }
    Ok(())
}
