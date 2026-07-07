//! Native relation checker that mirrors the Circom FilterAndTally circuit
//! constraint-for-constraint (including hard-constraint failures, which make
//! the relation unsatisfiable and are reported here as `false`).
//!
//! This is the "mock backend": tests use it as the authoritative native
//! semantics of the circuit, and the Groth16 integration tests check that
//! circom witness generation succeeds exactly when this checker accepts.
//!
//! Relation stages (same order as the circuit):
//!   1. per-slot: soft opening/eid/candidate/signature flags; deterministic
//!      in-range flag from the STRICT bit decomposition of the claimed id;
//!      HARD indexed registration-row fetch (path direction bits = id bits)
//!      for active in-range slots; soft vk-equality and hidden-nonce-
//!      relation flags against the fetched row; record r_j = (valid, id,
//!      pos, m).
//!   2. sorted-record duplicates (Strategy B): a Batcher odd-even mergesort
//!      network — sorted-by-construction, so permutation + sortedness hold
//!      unconditionally — then adjacent-row first-in-identity-block
//!      counting.
//!   3. tally accumulation equals the public counts.

use ark_ec::{CurveGroup, Group};
use ark_ff::{BigInteger, PrimeField, Zero};

use crate::crypto::hash::merkle_hash;
use crate::crypto::poseidon_native::poseidon;
use crate::crypto::signature::{base8, JubAffine, JubProjective};
use crate::types::F;
use crate::zk::statement::TallyStatement;
use crate::zk::witness::{padded_rows, TallyWitness};
use crate::zk::CircuitShape;

/// The comparator schedule of Batcher's odd-even mergesort network on n
/// elements, as (i, j) index pairs in application order. The SAME loop
/// structure generates the network in `circuits/components/sort_records.circom`
/// — the two must stay identical.
pub fn batcher_schedule(n: usize) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut p = 1;
    while p < n {
        let mut k = p;
        while k >= 1 {
            let mut j = k % p;
            while j + k < n {
                for i in 0..k.min(n - j - k) {
                    if (i + j) / (2 * p) == (i + j + k) / (2 * p) {
                        out.push((i + j, i + j + k));
                    }
                }
                j += 2 * k;
            }
            k /= 2;
        }
        p *= 2;
    }
    out
}

/// One private record as the circuit sees it (all values already
/// range-bounded by the relation: valid is 0/1, id < 2^8, pos < 2^8 in the
/// monolithic circuit; pos < 2^16 in the chunked pipeline).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rec {
    pub valid: bool,
    pub id: u64,
    pub pos: u64,
    pub m: u64,
}

impl Rec {
    /// key = (1-valid)*2^16 + id*2^8 + pos, exactly the monolithic
    /// circuit's packing.
    fn key(&self) -> u64 {
        ((!self.valid as u64) << 16) | (self.id << 8) | self.pos
    }

    /// key = (1-valid)*2^24 + id*2^16 + pos, the CHUNKED pipeline's wider
    /// packing (global 16-bit positions, 9-bit ids incl. the sentinel).
    pub fn key_wide(&self) -> u64 {
        ((!self.valid as u64) << 24) | (self.id << 16) | self.pos
    }

    /// The cross-run sentinel predecessor record: id = 256 collides with
    /// no real id (< 2^8) and no invalid-row id (0).
    pub const SENTINEL: Rec = Rec { valid: false, id: 256, pos: 0, m: 0 };
}

/// Per-row evaluation shared by the monolithic relation checker and the
/// chunked pipeline builder/checker — the EXACT circuit semantics of
/// `BallotValidity` (soft flags, deterministic strict-bits in-range flag,
/// HARD gated indexed-row fetch). `Err(())` = a hard constraint is
/// violated (the row makes the witness unsatisfiable).
pub fn eval_row(
    eid_hash: F,
    mr: F,
    num_voters: u64,
    cand_f: &[F],
    active: bool,
    row: &crate::zk::witness::BallotWitnessRow,
    pos: u64,
) -> Result<Rec, ()> {
    let pt = &row.pt_fields;

    // open_ok (soft)
    let mut inp = pt.to_vec();
    inp.push(row.rho);
    let open_ok = poseidon(&inp) == row.ct;

    // eid_ok (soft)
    let eid_ok = pt[0] == eid_hash;

    // candidate selector (soft); m = candidate INDEX (0 if no match)
    let mut cand_ok = false;
    let mut m = 0u64;
    for (c, cv) in cand_f.iter().enumerate() {
        if pt[4] == *cv {
            m = c as u64;
            cand_ok = true;
        }
    }

    // signature (hard sub-constraints)
    let sig_ok = circuit_sig_ok(pt[2], pt[3], pt[6], pt[7], pt[8], sig_msg(pt))?;

    // Deterministic in-range flag from the STRICT bit decomposition.
    let id_bits = pt[1].into_bigint().to_bits_le();
    let is_small = !id_bits.iter().skip(8).any(|b| *b);
    let id_low: u64 = id_bits
        .iter()
        .take(8)
        .enumerate()
        .map(|(d, b)| (*b as u64) << d)
        .sum();
    let in_range = is_small && id_low < num_voters;

    // HARD indexed registration-row fetch, gated by active && in_range.
    if active && in_range {
        let leaf = poseidon(&[eid_hash, pt[1], row.reg_vkx, row.reg_vky, row.reg_h]);
        let mut cur = leaf;
        for (d, sib) in row.merkle_path.iter().enumerate() {
            cur = if id_bits[d] { merkle_hash(*sib, cur) } else { merkle_hash(cur, *sib) };
        }
        if cur != mr {
            return Err(()); // hard: relation unsatisfiable
        }
    }

    // Soft row-consistency flags against the fetched row.
    let vk_match = pt[2] == row.reg_vkx && pt[3] == row.reg_vky;
    let h = poseidon(&[pt[0], pt[1], pt[2], pt[3], pt[5], row.r_ea]);
    let h_match = h == row.reg_h;

    let valid =
        open_ok && eid_ok && cand_ok && sig_ok && in_range && vk_match && h_match && active;

    Ok(Rec {
        valid,
        id: if valid { id_low } else { 0 },
        pos,
        m: if cand_ok { m } else { 0 },
    })
}

/// Check the exact FilterAndTally relation natively.
pub fn relation_check_native(
    statement: &TallyStatement,
    witness: &TallyWitness,
    shape: &CircuitShape,
) -> bool {
    // Shape / hard binding checks. Like the circuit, this checker does not
    // constrain statement.pk_ea_commitment — it is recomputed from public
    // data by statement_matches_public_data, which verifiers must run
    // alongside the proof check. num_voters IS constrained: it selects the
    // in-range window of the indexed registration table.
    if statement.duplicate_rule_id != 1 {
        return false;
    }
    if statement.tally_counts.len() != shape.num_candidates
        || witness.candidates.len() != shape.num_candidates
    {
        return false;
    }
    if statement.num_ballots as usize > shape.num_ballots {
        return false;
    }
    // num_voters: 8-bit (hard Num2Bits(8)) and at most the tree capacity.
    if statement.num_voters >= 256 {
        return false;
    }
    if shape.merkle_depth < 8 && statement.num_voters > (1u64 << shape.merkle_depth) {
        return false;
    }
    let Ok(rows) = padded_rows(witness, shape) else {
        return false;
    };
    if statement.num_ballots as usize != witness.rows.len() {
        return false;
    }

    // Candidate-set commitment.
    let cand_f: Vec<F> = witness.candidates.iter().map(|c| F::from(*c)).collect();
    if poseidon(&cand_f) != statement.candidate_set_commitment {
        return false;
    }

    let nb = shape.num_ballots;
    let mut records = Vec::with_capacity(nb);
    let mut bb_acc = F::zero();

    for (j, row) in rows.iter().enumerate() {
        let active = (j as u64) < statement.num_ballots;

        // Bulletin-board chain (active rows only).
        if active {
            bb_acc = poseidon(&[bb_acc, row.ct]);
        }

        if row.merkle_path.len() != shape.merkle_depth {
            return false;
        }

        // Shared per-row circuit semantics (soft flags, strict in-range,
        // HARD indexed-row fetch) — see eval_row.
        match eval_row(
            statement.eid_hash,
            statement.mr,
            statement.num_voters,
            &cand_f,
            active,
            row,
            j as u64,
        ) {
            Ok(rec) => records.push(rec),
            Err(()) => return false, // hard constraint violated
        }
    }

    if bb_acc != statement.bb_commitment {
        return false;
    }

    // Strategy B: Batcher odd-even mergesort network (identical schedule to
    // the circuit), then first-in-identity-block counting on adjacent rows.
    let mut sorted = records.clone();
    for (a, b) in batcher_schedule(nb) {
        if sorted[a].key() > sorted[b].key() {
            sorted.swap(a, b);
        }
    }

    let mut tally = vec![0u64; shape.num_candidates];
    for j in 0..nb {
        let first_in_block = j == 0 || sorted[j].id != sorted[j - 1].id;
        let counted = sorted[j].valid && first_in_block;
        if counted {
            tally[sorted[j].m as usize] += 1;
        }
    }
    for c in 0..shape.num_candidates {
        if tally[c] != statement.tally_counts[c] {
            return false;
        }
    }

    true
}

fn sig_msg(pt: &[F; crate::types::PLAINTEXT_FIELD_LEN]) -> F {
    poseidon(&[pt[0], pt[1], pt[4], pt[5]])
}

/// Little-endian bits of a field element, or None if it doesn't fit n bits.
fn f_bits_le(f: &F, n: usize) -> Option<Vec<bool>> {
    let bits = f.into_bigint().to_bits_le();
    if bits.iter().skip(n).any(|b| *b) {
        return None;
    }
    Some(bits.into_iter().take(n).collect())
}

/// Integer scalar multiplication by explicit bits (mirrors circomlib's
/// EscalarMulAny/EscalarMulFix, which multiply by the integer given by the
/// bit decomposition, not by a value mod l).
fn mul_bits(p: &JubAffine, bits: &[bool]) -> JubProjective {
    let mut acc = JubProjective::zero();
    let base = JubProjective::from(*p);
    for b in bits.iter().rev() {
        acc.double_in_place();
        if *b {
            acc += base;
        }
    }
    acc
}

/// Circuit semantics of the Schnorr verification component.
/// Err(()) = a hard constraint is violated (relation unsatisfiable):
/// off-curve points (BabyCheck), identity vk (Edwards2Montgomery), or
/// S >= 2^251 (Num2Bits).
fn circuit_sig_ok(ax: F, ay: F, rx: F, ry: F, s: F, msg: F) -> Result<bool, ()> {
    // Inputs are circomlib-form coordinates; map to ark form for arithmetic.
    let a = crate::crypto::signature::from_circom_point(ax, ay);
    let r = crate::crypto::signature::from_circom_point(rx, ry);
    if !a.is_on_curve() || !r.is_on_curve() {
        return Err(()); // BabyCheck is a hard constraint
    }
    if a.is_zero() {
        return Err(()); // Edwards2Montgomery(identity) is unsatisfiable
    }
    let Some(s_bits) = f_bits_le(&s, 251) else {
        return Err(()); // Num2Bits(251) is a hard constraint
    };
    let c = poseidon(&[rx, ry, ax, ay, msg]);
    let c_bits = f_bits_le(&c, 254).expect("field elements fit 254 bits");

    let lhs = mul_bits(&base8(), &s_bits);
    let rhs = JubProjective::from(r) + mul_bits(&a, &c_bits);
    Ok(lhs.into_affine() == rhs.into_affine())
}

#[cfg(test)]
mod tests {
    use super::batcher_schedule;

    #[test]
    fn batcher_network_sorts_everything() {
        use rand::{Rng, SeedableRng};
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(3);
        for &n in &[1usize, 2, 3, 4, 7, 8, 15, 16, 33, 128] {
            let schedule = batcher_schedule(n);
            for _ in 0..50 {
                let mut v: Vec<u64> = (0..n).map(|_| rng.gen_range(0..40)).collect();
                for &(a, b) in &schedule {
                    assert!(a < b && b < n);
                    if v[a] > v[b] {
                        v.swap(a, b);
                    }
                }
                assert!(v.windows(2).all(|w| w[0] <= w[1]), "n={n} not sorted: {v:?}");
            }
        }
    }

    #[test]
    fn batcher_comparator_counts() {
        assert_eq!(batcher_schedule(16).len(), 63);
        assert_eq!(batcher_schedule(128).len(), 1471);
    }
}
