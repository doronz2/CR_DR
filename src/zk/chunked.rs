//! CHUNKED FilterAndTally pipeline (CHUNKED_TALLY_DESIGN.md): prover-side
//! construction, native relation checks, circom input serialization and
//! aggregate verification for boards larger than one circuit.
//!
//! Pipeline (K chunks of C slots; board padded to K*C, activity gated by
//! the global public num_ballots):
//!
//!   phase 1  K x ValidityChunk    — per-slot validity (identical semantics
//!            to the monolithic circuit via `mock_backend::eval_row`),
//!            bb_in/bb_out board-chain segment, blinded record commitment
//!            rc_k; the prover also commits the SORTED runs sc_k here
//!            (both commitments precede the challenge);
//!   FS       (gamma, delta) = H(statement, rc_1..K, sc_1..K);
//!   phase 2  K x SortedRunChunk   — re-opens rc_k and sc_k, hiding
//!            boundary-record chain, in-run + cross-run sortedness,
//!            first-valid counting, hiding partial-tally commitment tc_k,
//!            hiding RUNNING grand-product chain (acc_p sorted side /
//!            acc_q original side, commitments only);
//!   final    1 x TallySum         — opens tc_1..K, constrains the SUM to
//!            the public tally_counts, opens the two final product
//!            accumulators and constrains them EQUAL (the permutation
//!            check, without revealing any product value);
//!   aggregate: verify all proofs; bb chain 0 -> bb_commitment; rc/sc
//!            consistency; boundary chain from the sentinel; product
//!            chains from commit(1,0); recompute (gamma, delta);
//!            tally_counts.
//!
//! Nothing private crosses a chunk boundary in the clear: rc/sc/tc, the
//! boundary records and the running products are hiding commitments — no
//! product value or per-chunk product ratio is ever public.

use ark_ff::{UniformRand, Zero};
use rand::{CryptoRng, RngCore};
use serde_json::{json, Value};

use crate::crypto::poseidon_native::poseidon;
use crate::errors::{CrDrError, Result};
use crate::protocol::admission::AdmittedOpenings;
use crate::protocol::bulletin_board::AdmittedBoard;
use crate::protocol::preprocessing::RegistrationState;
use crate::types::{f_to_dec, AuthoritySecretState, F, PublicParams};
use crate::zk::mock_backend::{eval_row, Rec};
use crate::zk::statement::{build_tally_statement, TallyStatement};
use crate::zk::witness::{build_tally_witness, padding_row, BallotWitnessRow};

/// Chunk size of the compiled chunk circuits (C).
pub const CHUNK_SIZE: usize = 128;

/// The full prover-side state of a chunked tally (witnesses + all public
/// values of every chunk proof).
#[derive(Debug, Clone)]
pub struct ChunkedTally {
    pub chunk_size: usize,
    pub k_chunks: usize,
    pub merkle_depth: usize,
    pub statement: TallyStatement,
    pub candidates: Vec<u64>,
    /// Rows padded to k_chunks * chunk_size, board order.
    pub rows: Vec<BallotWitnessRow>,
    /// Records per padded slot, board order (r_j = (valid, id, pos, m)).
    pub records: Vec<Rec>,
    /// Globally sorted records (runs of chunk_size).
    pub sorted: Vec<Rec>,
    /// Board-chain values bb_0..bb_K (bb_0 = 0, bb_K = bb_commitment).
    pub bb: Vec<F>,
    pub rc_blind: Vec<F>,
    pub rc: Vec<F>,
    pub sc_blind: Vec<F>,
    pub sc: Vec<F>,
    /// Boundary commitments cm_0..cm_K (cm_0 = sentinel with blind 0);
    /// run k has boundary_in = cm_k, boundary_out = cm_{k+1}.
    pub boundary_cm: Vec<F>,
    pub boundary_blind: Vec<F>,
    pub gamma: F,
    pub delta: F,
    /// Running grand-product VALUES p_0..p_K / q_0..q_K (p_0 = q_0 = 1) —
    /// private; they cross chunk boundaries only as the hiding commitments
    /// below.
    pub acc_p: Vec<F>,
    pub acc_q: Vec<F>,
    /// Blinds b_0..b_K (b_0 = 0: the chain start is public).
    pub acc_p_blind: Vec<F>,
    pub acc_q_blind: Vec<F>,
    /// Hiding running-product commitments cp_0..cp_K / cq_0..cq_K.
    pub acc_p_cm: Vec<F>,
    pub acc_q_cm: Vec<F>,
    pub partial_tallies: Vec<Vec<u64>>,
    pub tally_blind: Vec<F>,
    pub tc: Vec<F>,
}

fn f_rec(r: &Rec) -> [F; 4] {
    [F::from(r.valid as u64), F::from(r.id), F::from(r.pos), F::from(r.m)]
}

/// Blinded Poseidon chain over records (mirrors RecordChain).
pub fn record_chain(blind: F, records: &[Rec]) -> F {
    let mut acc = blind;
    for r in records {
        let f = f_rec(r);
        acc = poseidon(&[acc, f[0], f[1], f[2], f[3]]);
    }
    acc
}

/// Hiding commitment to one record (mirrors RecordCommit).
pub fn record_commit(r: &Rec, blind: F) -> F {
    let f = f_rec(r);
    poseidon(&[f[0], f[1], f[2], f[3], blind])
}

/// The public sentinel boundary commitment (blind 0, known to everyone).
pub fn sentinel_commitment() -> F {
    record_commit(&Rec::SENTINEL, F::zero())
}

/// The public start of both running-product commitment chains:
/// commit(value 1, blind 0), known to everyone (like the sentinel).
pub fn product_chain_start() -> F {
    poseidon(&[F::from(1u64), F::zero()])
}

/// enc(r) = valid + delta*id + delta^2*pos + delta^3*m
fn enc(r: &Rec, delta: F) -> F {
    let d2 = delta * delta;
    let d3 = d2 * delta;
    F::from(r.valid as u64) + delta * F::from(r.id) + d2 * F::from(r.pos) + d3 * F::from(r.m)
}

/// Fiat-Shamir challenges from the statement and ALL phase-1 commitments.
pub fn derive_challenges(statement: &TallyStatement, rc: &[F], sc: &[F]) -> (F, F) {
    let mut acc = poseidon(&[
        statement.eid_hash,
        statement.mr,
        statement.candidate_set_commitment,
        statement.bb_commitment,
        F::from(statement.num_ballots),
        F::from(statement.num_voters),
        F::from(statement.duplicate_rule_id),
    ]);
    for c in rc.iter().chain(sc.iter()) {
        acc = poseidon(&[acc, *c]);
    }
    (poseidon(&[acc, F::from(1u64)]), poseidon(&[acc, F::from(2u64)]))
}

/// Build the full chunked-tally state for the posted ballots.
pub fn build_chunked_tally<R: RngCore + CryptoRng>(
    pp: &PublicParams,
    authority_secret: &AuthoritySecretState,
    registration_state: &RegistrationState,
    admitted: &AdmittedBoard,
    openings: &AdmittedOpenings,
    chunk_size: usize,
    rng: &mut R,
) -> Result<ChunkedTally> {
    let c = chunk_size;
    let k_chunks = admitted.len().div_ceil(c).max(1);
    let padded = k_chunks * c;
    if admitted.len() > 1 << 24 {
        return Err(CrDrError::ZkToolchain("board exceeds 2^24 slots".into()));
    }

    let (tally, _) = crate::protocol::filter_and_tally::filter_and_tally(
        pp,
        authority_secret,
        registration_state,
        admitted,
        openings,
    )?;
    let statement = build_tally_statement(pp, admitted, registration_state, &tally);

    // Witness rows, padded to K*C.
    let witness =
        build_tally_witness(pp, authority_secret, registration_state, admitted, openings)?;
    let mut rows = witness.rows;
    while rows.len() < padded {
        rows.push(padding_row(pp.merkle_depth));
    }

    // Records via the SHARED circuit semantics.
    let cand_f: Vec<F> = pp.candidates.iter().map(|x| F::from(*x)).collect();
    let mut records = Vec::with_capacity(padded);
    for (j, row) in rows.iter().enumerate() {
        let active = (j as u64) < statement.num_ballots;
        let rec = eval_row(
            statement.eid_hash,
            statement.mr,
            statement.num_voters,
            &cand_f,
            active,
            row,
            j as u64,
        )
        .map_err(|_| CrDrError::ZkToolchain("hard-unsatisfiable row".into()))?;
        records.push(rec);
    }

    // Board chain per chunk.
    let mut bb = vec![F::zero()];
    let mut acc = F::zero();
    for (j, row) in rows.iter().enumerate() {
        if (j as u64) < statement.num_ballots {
            acc = poseidon(&[acc, row.ct]);
        }
        if (j + 1) % c == 0 {
            bb.push(acc);
        }
    }
    debug_assert_eq!(*bb.last().unwrap(), statement.bb_commitment);

    // Global sort + phase-1 commitments (both sides, pre-challenge).
    let mut sorted = records.clone();
    sorted.sort_by_key(Rec::key_wide);

    let mut rc_blind = Vec::new();
    let mut rc = Vec::new();
    let mut sc_blind = Vec::new();
    let mut sc = Vec::new();
    for k in 0..k_chunks {
        let rb = F::rand(rng);
        rc.push(record_chain(rb, &records[k * c..(k + 1) * c]));
        rc_blind.push(rb);
        let sb = F::rand(rng);
        sc.push(record_chain(sb, &sorted[k * c..(k + 1) * c]));
        sc_blind.push(sb);
    }

    let (gamma, delta) = derive_challenges(&statement, &rc, &sc);

    // Boundary commitments cm_0..cm_K.
    let mut boundary_cm = vec![sentinel_commitment()];
    let mut boundary_blind = vec![F::zero()];
    for k in 0..k_chunks {
        let b = F::rand(rng);
        boundary_cm.push(record_commit(&sorted[(k + 1) * c - 1], b));
        boundary_blind.push(b);
    }

    // Per-run counting, partial tallies, hiding running-product chains.
    let n_cand = pp.candidates.len();
    let mut acc_p = vec![F::from(1u64)];
    let mut acc_q = vec![F::from(1u64)];
    let mut acc_p_blind = vec![F::zero()];
    let mut acc_q_blind = vec![F::zero()];
    let mut acc_p_cm = vec![product_chain_start()];
    let mut acc_q_cm = vec![product_chain_start()];
    let mut partial_tallies = Vec::new();
    let mut tally_blind = Vec::new();
    let mut tc = Vec::new();
    for k in 0..k_chunks {
        let run = &sorted[k * c..(k + 1) * c];
        let orig = &records[k * c..(k + 1) * c];
        let mut prev = if k == 0 { Rec::SENTINEL } else { sorted[k * c - 1] };
        let mut t = vec![0u64; n_cand];
        for r in run {
            if r.valid && r.id != prev.id {
                t[r.m as usize] += 1;
            }
            prev = *r;
        }
        let mut p = acc_p[k];
        let mut q = acc_q[k];
        for (s, o) in run.iter().zip(orig) {
            p *= gamma - enc(s, delta);
            q *= gamma - enc(o, delta);
        }
        let pb = F::rand(rng);
        let qb = F::rand(rng);
        acc_p_cm.push(poseidon(&[p, pb]));
        acc_q_cm.push(poseidon(&[q, qb]));
        acc_p.push(p);
        acc_q.push(q);
        acc_p_blind.push(pb);
        acc_q_blind.push(qb);
        let tb = F::rand(rng);
        let mut inputs: Vec<F> = t.iter().map(|x| F::from(*x)).collect();
        inputs.push(tb);
        tc.push(poseidon(&inputs));
        tally_blind.push(tb);
        partial_tallies.push(t);
    }

    Ok(ChunkedTally {
        chunk_size: c,
        k_chunks,
        merkle_depth: pp.merkle_depth,
        statement,
        candidates: pp.candidates.clone(),
        rows,
        records,
        sorted,
        bb,
        rc_blind,
        rc,
        sc_blind,
        sc,
        boundary_cm,
        boundary_blind,
        gamma,
        delta,
        acc_p,
        acc_q,
        acc_p_blind,
        acc_q_blind,
        acc_p_cm,
        acc_q_cm,
        partial_tallies,
        tally_blind,
        tc,
    })
}

/// Native check of the ENTIRE chunked pipeline: every constraint of every
/// chunk circuit plus every aggregator check. The chunked analogue of
/// `relation_check_native`.
pub fn chunked_relation_check_native(ct: &ChunkedTally) -> bool {
    let c = ct.chunk_size;
    let k_chunks = ct.k_chunks;
    let st = &ct.statement;
    if ct.rows.len() != k_chunks * c || ct.records.len() != k_chunks * c {
        return false;
    }
    if st.duplicate_rule_id != 1 || st.num_voters >= 256 {
        return false;
    }
    if ct.merkle_depth < 8 && st.num_voters > (1u64 << ct.merkle_depth) {
        return false;
    }
    if st.num_ballots as usize > k_chunks * c || st.num_ballots >= 1 << 24 {
        return false;
    }
    let cand_f: Vec<F> = ct.candidates.iter().map(|x| F::from(*x)).collect();
    if poseidon(&cand_f) != st.candidate_set_commitment {
        return false;
    }

    // ---- phase 1: validity chunks
    if ct.bb.len() != k_chunks + 1 || ct.bb[0] != F::zero() {
        return false;
    }
    for k in 0..k_chunks {
        let mut acc = ct.bb[k];
        for j in k * c..(k + 1) * c {
            let active = (j as u64) < st.num_ballots;
            let row = &ct.rows[j];
            if row.merkle_path.len() != ct.merkle_depth {
                return false;
            }
            match eval_row(st.eid_hash, st.mr, st.num_voters, &cand_f, active, row, j as u64) {
                Ok(rec) => {
                    if rec != ct.records[j] {
                        return false;
                    }
                }
                Err(()) => return false,
            }
            if active {
                acc = poseidon(&[acc, row.ct]);
            }
        }
        if acc != ct.bb[k + 1] {
            return false;
        }
        if record_chain(ct.rc_blind[k], &ct.records[k * c..(k + 1) * c]) != ct.rc[k] {
            return false;
        }
    }
    if ct.bb[k_chunks] != st.bb_commitment {
        return false;
    }

    // ---- Fiat-Shamir
    let (gamma, delta) = derive_challenges(st, &ct.rc, &ct.sc);
    if gamma != ct.gamma || delta != ct.delta {
        return false;
    }

    // ---- phase 2: sorted runs
    if ct.boundary_cm[0] != sentinel_commitment() {
        return false;
    }
    if ct.acc_p_cm.len() != k_chunks + 1
        || ct.acc_q_cm.len() != k_chunks + 1
        || ct.acc_p_cm[0] != product_chain_start()
        || ct.acc_q_cm[0] != product_chain_start()
        || ct.acc_p[0] != F::from(1u64)
        || ct.acc_q[0] != F::from(1u64)
    {
        return false;
    }
    let mut total = vec![0u64; ct.candidates.len()];
    for k in 0..k_chunks {
        let run = &ct.sorted[k * c..(k + 1) * c];
        let orig = &ct.records[k * c..(k + 1) * c];
        // commitments re-open
        if record_chain(ct.sc_blind[k], run) != ct.sc[k] {
            return false;
        }
        if record_chain(ct.rc_blind[k], orig) != ct.rc[k] {
            return false;
        }
        let bnd_in = if k == 0 { Rec::SENTINEL } else { ct.sorted[k * c - 1] };
        if record_commit(&bnd_in, ct.boundary_blind[k]) != ct.boundary_cm[k] {
            return false;
        }
        if record_commit(&run[c - 1], ct.boundary_blind[k + 1]) != ct.boundary_cm[k + 1] {
            return false;
        }
        // range + sortedness (boundary included; the run-0 sentinel's key
        // is zeroed, mirroring the circuit's is_sentinel gate)
        let sentinel_in = bnd_in.id == 256;
        let mut prev_key = if sentinel_in { 0 } else { bnd_in.key_wide() };
        for r in run {
            if r.id >= 512 || r.pos >= (1 << 24) {
                return false;
            }
            if prev_key > r.key_wide() {
                return false;
            }
            prev_key = r.key_wide();
        }
        // counting + partial tally commitment
        let mut prev_id = bnd_in.id;
        let mut t = vec![0u64; ct.candidates.len()];
        for r in run {
            if r.valid && r.id != prev_id {
                t[r.m as usize] += 1;
            }
            prev_id = r.id;
        }
        if t != ct.partial_tallies[k] {
            return false;
        }
        let mut inputs: Vec<F> = t.iter().map(|x| F::from(*x)).collect();
        inputs.push(ct.tally_blind[k]);
        if poseidon(&inputs) != ct.tc[k] {
            return false;
        }
        for (i, x) in t.iter().enumerate() {
            total[i] += x;
        }
        // running products: chain openings + per-run multiplication
        if poseidon(&[ct.acc_p[k], ct.acc_p_blind[k]]) != ct.acc_p_cm[k]
            || poseidon(&[ct.acc_q[k], ct.acc_q_blind[k]]) != ct.acc_q_cm[k]
        {
            return false;
        }
        let mut p = ct.acc_p[k];
        let mut q = ct.acc_q[k];
        for (s, o) in run.iter().zip(orig) {
            p *= gamma - enc(s, delta);
            q *= gamma - enc(o, delta);
        }
        if p != ct.acc_p[k + 1]
            || q != ct.acc_q[k + 1]
            || poseidon(&[p, ct.acc_p_blind[k + 1]]) != ct.acc_p_cm[k + 1]
            || poseidon(&[q, ct.acc_q_blind[k + 1]]) != ct.acc_q_cm[k + 1]
        {
            return false;
        }
    }

    // ---- aggregate checks: grand-product / permutation equality (proven
    //      by the tally-sum circuit over the FINAL accumulators) + tally
    if ct.acc_p[k_chunks] != ct.acc_q[k_chunks] {
        return false;
    }
    if total != st.tally_counts {
        return false;
    }
    true
}

// ---------------------------------------------------------------------------
// circom input serialization + expected public inputs per proof
// ---------------------------------------------------------------------------

fn dec(f: &F) -> Value {
    Value::String(f_to_dec(f))
}

fn recs_json(recs: &[Rec]) -> Value {
    Value::Array(
        recs.iter()
            .map(|r| {
                json!([
                    (r.valid as u64).to_string(),
                    r.id.to_string(),
                    r.pos.to_string(),
                    r.m.to_string()
                ])
            })
            .collect(),
    )
}

/// input.json for ValidityChunk k.
pub fn validity_chunk_input(ct: &ChunkedTally, k: usize) -> Value {
    let c = ct.chunk_size;
    let rows = &ct.rows[k * c..(k + 1) * c];
    json!({
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
        "r_ea": rows.iter().map(|r| dec(&r.r_ea)).collect::<Vec<_>>(),
        "reg_vkx": rows.iter().map(|r| dec(&r.reg_vkx)).collect::<Vec<_>>(),
        "reg_vky": rows.iter().map(|r| dec(&r.reg_vky)).collect::<Vec<_>>(),
        "reg_h": rows.iter().map(|r| dec(&r.reg_h)).collect::<Vec<_>>(),
        "path_elements": rows.iter().map(|r| Value::Array(r.merkle_path.iter().map(dec).collect())).collect::<Vec<_>>(),
        "rc_blind": dec(&ct.rc_blind[k]),
    })
}

/// input.json for SortedRunChunk k.
pub fn sorted_run_input(ct: &ChunkedTally, k: usize) -> Value {
    let c = ct.chunk_size;
    let bnd_in = if k == 0 { Rec::SENTINEL } else { ct.sorted[k * c - 1] };
    json!({
        "gamma": dec(&ct.gamma),
        "delta": dec(&ct.delta),
        "rc": dec(&ct.rc[k]),
        "sc": dec(&ct.sc[k]),
        "boundary_in_cm": dec(&ct.boundary_cm[k]),
        "boundary_out_cm": dec(&ct.boundary_cm[k + 1]),
        "tc": dec(&ct.tc[k]),
        "acc_p_in_cm": dec(&ct.acc_p_cm[k]),
        "acc_p_out_cm": dec(&ct.acc_p_cm[k + 1]),
        "acc_q_in_cm": dec(&ct.acc_q_cm[k]),
        "acc_q_out_cm": dec(&ct.acc_q_cm[k + 1]),
        "orig": recs_json(&ct.records[k * c..(k + 1) * c]),
        "rc_blind": dec(&ct.rc_blind[k]),
        "sorted": recs_json(&ct.sorted[k * c..(k + 1) * c]),
        "sc_blind": dec(&ct.sc_blind[k]),
        "bnd_in": json!([
            (bnd_in.valid as u64).to_string(),
            bnd_in.id.to_string(),
            bnd_in.pos.to_string(),
            bnd_in.m.to_string()
        ]),
        "bnd_in_blind": dec(&ct.boundary_blind[k]),
        "bnd_out_blind": dec(&ct.boundary_blind[k + 1]),
        "tally_blind": dec(&ct.tally_blind[k]),
        "acc_p_in": dec(&ct.acc_p[k]),
        "acc_p_in_blind": dec(&ct.acc_p_blind[k]),
        "acc_p_out_blind": dec(&ct.acc_p_blind[k + 1]),
        "acc_q_in": dec(&ct.acc_q[k]),
        "acc_q_in_blind": dec(&ct.acc_q_blind[k]),
        "acc_q_out_blind": dec(&ct.acc_q_blind[k + 1]),
    })
}

/// input.json for TallySum.
pub fn tally_sum_input(ct: &ChunkedTally) -> Value {
    let k = ct.k_chunks;
    json!({
        "tc": ct.tc.iter().map(dec).collect::<Vec<_>>(),
        "acc_p_cm": dec(&ct.acc_p_cm[k]),
        "acc_q_cm": dec(&ct.acc_q_cm[k]),
        "tally_counts": ct.statement.tally_counts.iter().map(|x| x.to_string()).collect::<Vec<_>>(),
        "t": ct.partial_tallies.iter().map(|t| Value::Array(t.iter().map(|x| Value::String(x.to_string())).collect())).collect::<Vec<_>>(),
        "blind": ct.tally_blind.iter().map(dec).collect::<Vec<_>>(),
        "acc_p": dec(&ct.acc_p[k]),
        "acc_p_blind": dec(&ct.acc_p_blind[k]),
        "acc_q": dec(&ct.acc_q[k]),
        "acc_q_blind": dec(&ct.acc_q_blind[k]),
    })
}

/// The exact snarkjs public.json a ValidityChunk-k proof must carry.
pub fn validity_chunk_publics(ct: &ChunkedTally, k: usize) -> Vec<String> {
    transcript_validity_publics(&ct.statement, &ct.transcript(), k)
}

/// The exact snarkjs public.json a SortedRunChunk-k proof must carry.
pub fn sorted_run_publics(ct: &ChunkedTally, k: usize) -> Vec<String> {
    transcript_sorted_run_publics(&ct.transcript(), k)
}

/// The exact snarkjs public.json the TallySum proof must carry.
pub fn tally_sum_publics(ct: &ChunkedTally) -> Vec<String> {
    transcript_tally_sum_publics(&ct.statement, &ct.transcript())
}

// ---------------------------------------------------------------------------
// PUBLIC transcript + public-data-only aggregate verification
// ---------------------------------------------------------------------------

/// The PUBLIC transcript of a chunked tally: exactly the values that appear
/// in the 2K+1 proofs' public inputs, and nothing else. Contains NO witness
/// objects — every field is posted alongside the proofs.
///
/// What each public value is, and what stays hidden:
///   * `bb[0..=K]`  — board-chain snapshots at chunk boundaries. PUBLICLY
///     RECOMPUTABLE from BB_adm alone (fold of Poseidon over the admitted
///     commitments), so they reveal nothing beyond BB_adm itself.
///   * `rc[k]`, `sc[k]` — HIDING (blinded) Poseidon chain commitments to
///     the chunk's board-order records and to the k-th sorted run.
///   * `boundary_cm[0..=K]` — HIDING commitments to the record at each run
///     boundary (`boundary_cm[0]` is the public sentinel with blind 0).
///   * `tc[k]` — HIDING commitments to the per-run partial tallies.
///   * `gamma`, `delta` — Fiat-Shamir challenges, recomputable from the
///     statement and rc/sc.
///   * `acc_p_cm[0..=K]`, `acc_q_cm[0..=K]` — HIDING commitments to the
///     running grand products of `gamma - enc(record)` over the sorted
///     runs / board chunks. `acc_*_cm[0]` is the public chain start
///     (value 1, blind 0); no product VALUE or per-chunk ratio is ever
///     public — equality of the two final accumulators is proven inside
///     the tally-sum circuit.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ChunkedTranscript {
    pub chunk_size: usize,
    #[serde(with = "crate::types::fserde_vec")]
    pub bb: Vec<F>,
    #[serde(with = "crate::types::fserde_vec")]
    pub rc: Vec<F>,
    #[serde(with = "crate::types::fserde_vec")]
    pub sc: Vec<F>,
    #[serde(with = "crate::types::fserde_vec")]
    pub boundary_cm: Vec<F>,
    #[serde(with = "crate::types::fserde_vec")]
    pub tc: Vec<F>,
    #[serde(with = "crate::types::fserde_vec")]
    pub acc_p_cm: Vec<F>,
    #[serde(with = "crate::types::fserde_vec")]
    pub acc_q_cm: Vec<F>,
    #[serde(with = "crate::types::fserde")]
    pub gamma: F,
    #[serde(with = "crate::types::fserde")]
    pub delta: F,
}

impl ChunkedTally {
    /// Extract the public transcript (what the prover posts).
    pub fn transcript(&self) -> ChunkedTranscript {
        ChunkedTranscript {
            chunk_size: self.chunk_size,
            bb: self.bb.clone(),
            rc: self.rc.clone(),
            sc: self.sc.clone(),
            boundary_cm: self.boundary_cm.clone(),
            tc: self.tc.clone(),
            acc_p_cm: self.acc_p_cm.clone(),
            acc_q_cm: self.acc_q_cm.clone(),
            gamma: self.gamma,
            delta: self.delta,
        }
    }
}

/// The 2K+1 proof objects of a chunked tally, each with the public.json
/// the prover emitted for it.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ChunkedProofs {
    pub validity: Vec<(Value, Value)>,
    pub sorted_run: Vec<(Value, Value)>,
    pub tally_sum: (Value, Value),
}

/// Which chunk circuit a proof belongs to (selects the verification key).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChunkKind {
    Validity,
    SortedRun,
    TallySum,
}

/// Expected public inputs of ValidityChunk k, from PUBLIC data only.
pub fn transcript_validity_publics(
    st: &TallyStatement,
    tr: &ChunkedTranscript,
    k: usize,
) -> Vec<String> {
    vec![
        f_to_dec(&st.eid_hash),
        f_to_dec(&st.mr),
        f_to_dec(&st.candidate_set_commitment),
        st.num_ballots.to_string(),
        st.num_voters.to_string(),
        st.duplicate_rule_id.to_string(),
        (k * tr.chunk_size).to_string(),
        f_to_dec(&tr.bb[k]),
        f_to_dec(&tr.bb[k + 1]),
        f_to_dec(&tr.rc[k]),
    ]
}

/// Expected public inputs of SortedRunChunk k, from PUBLIC data only.
pub fn transcript_sorted_run_publics(tr: &ChunkedTranscript, k: usize) -> Vec<String> {
    vec![
        f_to_dec(&tr.gamma),
        f_to_dec(&tr.delta),
        f_to_dec(&tr.rc[k]),
        f_to_dec(&tr.sc[k]),
        f_to_dec(&tr.boundary_cm[k]),
        f_to_dec(&tr.boundary_cm[k + 1]),
        f_to_dec(&tr.tc[k]),
        f_to_dec(&tr.acc_p_cm[k]),
        f_to_dec(&tr.acc_p_cm[k + 1]),
        f_to_dec(&tr.acc_q_cm[k]),
        f_to_dec(&tr.acc_q_cm[k + 1]),
    ]
}

/// Expected public inputs of the TallySum proof, from PUBLIC data only.
pub fn transcript_tally_sum_publics(st: &TallyStatement, tr: &ChunkedTranscript) -> Vec<String> {
    let k = tr.rc.len();
    let mut v: Vec<String> = tr.tc.iter().map(f_to_dec).collect();
    v.push(f_to_dec(&tr.acc_p_cm[k]));
    v.push(f_to_dec(&tr.acc_q_cm[k]));
    v.extend(st.tally_counts.iter().map(|x| x.to_string()));
    v
}

/// STRUCTURAL public checks over (statement, admitted board, transcript) —
/// everything except the Groth16 proof verifications and the exact
/// per-proof publics binding (which `verify_chunked_public_transcript`
/// adds). Uses only public data:
///
///   * length/shape consistency of the transcript vectors;
///   * the board chain: bb[0] = 0, every bb[k] equals the Poseidon fold of
///     the admitted commitments up to slot k*C (recomputed from BB_adm —
///     this is what makes a dropped/duplicated admitted commitment
///     detectable), and bb[K] = statement.bb_commitment;
///   * boundary chain start: boundary_cm[0] is the public sentinel;
///   * product chain starts: acc_p_cm[0] = acc_q_cm[0] = the public
///     commitment to (1, blind 0) — the grand-product/permutation
///     equality itself is proven by the tally-sum circuit over the FINAL
///     accumulator commitments (bound via that proof's publics);
///   * Fiat-Shamir: (gamma, delta) re-derived from statement + rc + sc.
///
/// LEAKAGE: every per-chunk value that depends on private records is a
/// HIDING commitment; no product value or ratio is public (an earlier
/// design published same-blind product pairs whose ratio leaked — see
/// CHUNKED_TALLY_DESIGN.md, "Public values and leakage").
pub fn check_chunked_transcript(
    st: &TallyStatement,
    admitted: &AdmittedBoard,
    tr: &ChunkedTranscript,
) -> bool {
    let k_chunks = tr.rc.len();
    if k_chunks == 0
        || tr.chunk_size == 0
        || tr.bb.len() != k_chunks + 1
        || tr.sc.len() != k_chunks
        || tr.boundary_cm.len() != k_chunks + 1
        || tr.tc.len() != k_chunks
        || tr.acc_p_cm.len() != k_chunks + 1
        || tr.acc_q_cm.len() != k_chunks + 1
    {
        return false;
    }
    if st.num_ballots as usize != admitted.len()
        || admitted.len() > k_chunks * tr.chunk_size
        || st.num_ballots >= 1 << 24
    {
        return false;
    }

    // Board chain recomputed from the admitted board itself.
    if tr.bb[0] != F::zero() {
        return false;
    }
    let mut acc = F::zero();
    for (j, com) in admitted.coms.iter().enumerate() {
        acc = poseidon(&[acc, *com]);
        if (j + 1) % tr.chunk_size == 0 && tr.bb[(j + 1) / tr.chunk_size] != acc {
            return false;
        }
    }
    // Chunks past the last admitted commitment carry the final value.
    let full = admitted.len() / tr.chunk_size;
    for k in full + 1..=k_chunks {
        if tr.bb[k] != acc {
            return false;
        }
    }
    if tr.bb[k_chunks] != st.bb_commitment {
        return false;
    }

    // Boundary chain starts at the public sentinel; product chains start
    // at the public commitment to 1.
    if tr.boundary_cm[0] != sentinel_commitment()
        || tr.acc_p_cm[0] != product_chain_start()
        || tr.acc_q_cm[0] != product_chain_start()
    {
        return false;
    }

    // Fiat-Shamir challenges.
    let (gamma, delta) = derive_challenges(st, &tr.rc, &tr.sc);
    gamma == tr.gamma && delta == tr.delta
}

/// PUBLIC aggregate verification of a chunked tally:
///
///   1-3. every validity-chunk / sorted-run / tally-sum proof verifies
///        (via `verify`, which wraps the Groth16 verifier + the circuit's
///        verification key for `ChunkKind`);
///   4.   each proof's public inputs are EXACTLY the transcript-derived
///        expected publics (so chunk_base_k = k*chunk_size, board-chain
///        continuity bb_out(k) = bb_in(k+1), boundary-chain continuity
///        cm_out(k) = cm_in(k+1), and the challenge binding are all forced
///        — the expected publics are built from the single transcript
///        vectors);
///   5-11. the structural checks of `check_chunked_transcript` (board
///        chain from BB_adm, sentinel, product-chain starts, Fiat-Shamir
///        derivation) — the grand-product/permutation equality is proven
///        by the tally-sum circuit over the final accumulator commitments,
///        and the final tally binding comes from the tally-sum publics
///        which end in statement.tally_counts.
///
/// Uses ONLY public data and proof objects. The caller separately checks
/// `statement_matches_public_data(statement, ...)` to bind the statement
/// itself to the published election data.
pub fn verify_chunked_public_transcript<Fv>(
    st: &TallyStatement,
    admitted: &AdmittedBoard,
    tr: &ChunkedTranscript,
    proofs: &ChunkedProofs,
    mut verify: Fv,
) -> Result<bool>
where
    Fv: FnMut(ChunkKind, &Value, &Value) -> Result<bool>,
{
    if !check_chunked_transcript(st, admitted, tr) {
        return Ok(false);
    }
    let k_chunks = tr.rc.len();
    if proofs.validity.len() != k_chunks || proofs.sorted_run.len() != k_chunks {
        return Ok(false);
    }

    let publics_match = |carried: &Value, expected: &[String]| -> bool {
        carried
            .as_array()
            .map(|a| {
                a.len() == expected.len()
                    && a.iter()
                        .zip(expected)
                        .all(|(v, e)| v.as_str() == Some(e.as_str()))
            })
            .unwrap_or(false)
    };

    for (k, (proof, public)) in proofs.validity.iter().enumerate() {
        if !publics_match(public, &transcript_validity_publics(st, tr, k)) {
            return Ok(false);
        }
        if !verify(ChunkKind::Validity, proof, public)? {
            return Ok(false);
        }
    }
    for (k, (proof, public)) in proofs.sorted_run.iter().enumerate() {
        if !publics_match(public, &transcript_sorted_run_publics(tr, k)) {
            return Ok(false);
        }
        if !verify(ChunkKind::SortedRun, proof, public)? {
            return Ok(false);
        }
    }
    let (proof, public) = &proofs.tally_sum;
    if !publics_match(public, &transcript_tally_sum_publics(st, tr)) {
        return Ok(false);
    }
    if !verify(ChunkKind::TallySum, proof, public)? {
        return Ok(false);
    }
    Ok(true)
}
