//! Native relation checker that mirrors the Circom FilterAndTally circuit
//! constraint-for-constraint (including hard-constraint failures, which make
//! the relation unsatisfiable and are reported here as `false`).
//!
//! This is the "mock backend": tests use it as the authoritative native
//! semantics of the circuit, and the Groth16 integration tests check that
//! circom witness generation succeeds exactly when this checker accepts.

use ark_ec::{CurveGroup, Group};
use ark_ff::{BigInteger, PrimeField, Zero};

use crate::crypto::hash::merkle_hash;
use crate::crypto::poseidon_native::poseidon;
use crate::crypto::signature::{base8, JubAffine, JubProjective};
use crate::types::F;
use crate::zk::statement::TallyStatement;
use crate::zk::witness::{padded_rows, TallyWitness};
use crate::zk::CircuitShape;

/// Check the exact FilterAndTally relation natively.
pub fn relation_check_native(
    statement: &TallyStatement,
    witness: &TallyWitness,
    shape: &CircuitShape,
) -> bool {
    // Shape / hard binding checks.
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
    let mut valid = vec![false; nb];
    let mut sel = vec![vec![false; shape.num_candidates]; nb];
    let mut bb_acc = F::zero();

    for (j, row) in rows.iter().enumerate() {
        let active = (j as u64) < statement.num_ballots;

        // Bulletin-board chain (active rows only).
        if active {
            bb_acc = poseidon(&[bb_acc, row.ct]);
        }

        if row.merkle_path.len() != shape.merkle_depth
            || row.merkle_index.len() != shape.merkle_depth
        {
            return false;
        }

        let pt = &row.pt_fields;

        // open_ok (soft)
        let mut inp = pt.to_vec();
        inp.push(row.rho);
        let open_ok = poseidon(&inp) == row.ct;

        // eid_ok (soft)
        let eid_ok = pt[0] == statement.eid_hash;

        // candidate selector (soft)
        let mut cand_ok = false;
        for (c, cv) in cand_f.iter().enumerate() {
            if pt[4] == *cv {
                sel[j][c] = true;
                cand_ok = true;
            }
        }

        // signature (hard constraints may make the whole relation UNSAT)
        let sig_ok = match circuit_sig_ok(pt[2], pt[3], pt[6], pt[7], pt[8], sig_msg(pt)) {
            Ok(ok) => ok,
            Err(()) => return false, // hard constraint violated
        };

        // registration relation (soft)
        let h = poseidon(&[pt[0], pt[1], pt[2], pt[3], pt[5], row.r_ea]);
        let leaf = poseidon(&[pt[0], pt[1], pt[2], pt[3], h]);
        let mut cur = leaf;
        for (sib, is_right) in row.merkle_path.iter().zip(&row.merkle_index) {
            cur = if *is_right { merkle_hash(*sib, cur) } else { merkle_hash(cur, *sib) };
        }
        let root_ok = cur == statement.mr;

        valid[j] = open_ok && eid_ok && cand_ok && sig_ok && root_ok && active;
    }

    if bb_acc != statement.bb_commitment {
        return false;
    }

    // First-valid-counts duplicate rule (O(B^2), like the circuit).
    let mut counted = vec![false; nb];
    for j in 0..nb {
        let mut dup_before = false;
        for k in 0..j {
            if valid[k] && rows[k].pt_fields[1] == rows[j].pt_fields[1] {
                dup_before = true;
            }
        }
        counted[j] = valid[j] && !dup_before;
    }

    // Tally accumulation.
    for c in 0..shape.num_candidates {
        let mut total = 0u64;
        for j in 0..nb {
            if counted[j] && sel[j][c] {
                total += 1;
            }
        }
        if total != statement.tally_counts[c] {
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
