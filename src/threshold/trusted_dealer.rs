//! MODEL 1 — Trusted-dealer Shamir sharing of the authority nonces R_EA,i.
//!
//! The dealer (the preprocessing authority) splits every R_EA,i into k
//! shares with threshold t. Any t shares reconstruct R_EA,i; any t-1 shares
//! are information-theoretically independent of it.

use std::collections::HashMap;

use rand::{CryptoRng, RngCore};

use crate::crypto::shamir::{reconstruct, share, Share};
use crate::errors::{CrDrError, Result};
use crate::types::{AuthoritySecretState, F, Nonce, ThresholdParams, VoterId};

/// Share one authority nonce.
pub fn share_nonce<R: RngCore + CryptoRng>(
    r_ea: Nonce,
    t: usize,
    k: usize,
    rng: &mut R,
) -> Result<Vec<Share>> {
    share(r_ea, t, k, rng)
}

/// Reconstruct an authority nonce from a subset of shares (>= t of them).
pub fn reconstruct_nonce(shares_subset: &[Share]) -> Result<F> {
    reconstruct(shares_subset)
}

/// Split every registered R_EA,i and store the shares in the authority
/// state. (In a deployment each authority would receive only its own share;
/// the dealer would then erase the plain nonces.)
pub fn share_all_nonces<R: RngCore + CryptoRng>(
    authority_secret: &mut AuthoritySecretState,
    params: ThresholdParams,
    rng: &mut R,
) -> Result<()> {
    let mut all: HashMap<VoterId, Vec<Share>> = HashMap::new();
    for (id, secret) in &authority_secret.voter_secrets {
        all.insert(*id, share_nonce(secret.r_ea, params.t, params.k, rng)?);
    }
    authority_secret.threshold_nonce_shares = Some(all);
    Ok(())
}

/// The share of authority `authority_index` (1-based) for voter `id`.
pub fn authority_share(
    authority_secret: &AuthoritySecretState,
    id: VoterId,
    authority_index: u64,
) -> Result<Share> {
    let shares = authority_secret
        .threshold_nonce_shares
        .as_ref()
        .ok_or_else(|| CrDrError::Threshold("nonces not shared".into()))?
        .get(&id)
        .ok_or(CrDrError::UnknownVoter(id))?;
    shares
        .iter()
        .find(|s| s.index == authority_index)
        .copied()
        .ok_or_else(|| CrDrError::Threshold(format!("no share for authority {authority_index}")))
}
