//! Shamir secret sharing over the BN254 scalar field, used by the
//! trusted-dealer threshold model for the authority nonces R_EA,i.

use ark_ff::{Field, UniformRand, Zero};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::errors::{CrDrError, Result};
use crate::types::{fserde, F};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Share {
    /// Evaluation point x = authority index + 1 (never 0).
    pub index: u64,
    #[serde(with = "fserde")]
    pub value: F,
}

/// Split `secret` into k shares with reconstruction threshold t
/// (polynomial degree t-1).
pub fn share<R: RngCore + CryptoRng>(
    secret: F,
    t: usize,
    k: usize,
    rng: &mut R,
) -> Result<Vec<Share>> {
    if t == 0 || t > k {
        return Err(CrDrError::Threshold(format!("invalid threshold t={t}, k={k}")));
    }
    // coeffs[0] = secret, degree t-1
    let mut coeffs = vec![secret];
    for _ in 1..t {
        coeffs.push(F::rand(rng));
    }
    Ok((1..=k as u64)
        .map(|x| {
            let xf = F::from(x);
            // Horner evaluation
            let mut v = F::zero();
            for c in coeffs.iter().rev() {
                v = v * xf + c;
            }
            Share { index: x, value: v }
        })
        .collect())
}

/// Lagrange-interpolate the provided shares at x = 0.
///
/// NOTE: this returns the correct secret only when at least t shares of the
/// original polynomial are provided; with fewer shares it interpolates a
/// lower-degree polynomial and yields an unrelated value (see tests).
pub fn reconstruct(shares: &[Share]) -> Result<F> {
    if shares.is_empty() {
        return Err(CrDrError::Threshold("no shares".into()));
    }
    let mut seen = std::collections::HashSet::new();
    for s in shares {
        if s.index == 0 || !seen.insert(s.index) {
            return Err(CrDrError::Threshold("duplicate or zero share index".into()));
        }
    }
    let mut acc = F::zero();
    for si in shares {
        let xi = F::from(si.index);
        let mut num = F::from(1u64);
        let mut den = F::from(1u64);
        for sj in shares {
            if sj.index == si.index {
                continue;
            }
            let xj = F::from(sj.index);
            num *= xj; // (0 - xj) sign cancels between num and den
            den *= xj - xi;
        }
        let li = num * den.inverse().ok_or_else(|| CrDrError::Threshold("singular".into()))?;
        acc += si.value * li;
    }
    Ok(acc)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn reconstructs_with_t_shares() {
        let mut rng = ChaCha20Rng::seed_from_u64(7);
        let secret = F::rand(&mut rng);
        let shares = share(secret, 3, 5, &mut rng).unwrap();
        assert_eq!(reconstruct(&shares[0..3]).unwrap(), secret);
        assert_eq!(reconstruct(&[shares[4], shares[1], shares[3]]).unwrap(), secret);
        assert_eq!(reconstruct(&shares).unwrap(), secret);
    }

    #[test]
    fn fewer_than_t_shares_do_not_reconstruct() {
        let mut rng = ChaCha20Rng::seed_from_u64(8);
        let secret = F::rand(&mut rng);
        let shares = share(secret, 3, 5, &mut rng).unwrap();
        let guess = reconstruct(&shares[0..2]).unwrap();
        assert_ne!(guess, secret);
    }
}
