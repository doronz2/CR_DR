//! MODEL 1 — Trusted-dealer Shamir sharing of the authority nonces R_EA,i.
//!
//! Since threshold-private preprocessing, every R_EA,i is Shamir-shared
//! t-of-k AT GENERATION TIME (inside the idealized preprocessing
//! functionality) and the plain nonce is erased — the authority state never
//! stores it. Any t shares reconstruct R_EA,i; any t-1 shares are
//! information-theoretically independent of it.
//!
//! This module keeps the share-level helpers plus an authorized RE-share
//! operation (a >= t quorum reconstructs each nonce and re-splits it under
//! new parameters — e.g. to change t/k or rotate shares).

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

/// AUTHORIZED re-share of every registered R_EA,i under new threshold
/// parameters: a >= t quorum reconstructs each nonce, re-splits it, and the
/// plain value is erased again. (In a deployment each authority would
/// receive only its own new share.)
pub fn share_all_nonces<R: RngCore + CryptoRng>(
    authority_secret: &mut AuthoritySecretState,
    params: ThresholdParams,
    rng: &mut R,
) -> Result<()> {
    if params.t == 0 || params.t > params.k {
        return Err(CrDrError::Threshold(format!(
            "invalid threshold t={} k={}",
            params.t, params.k
        )));
    }
    let ids: Vec<VoterId> = authority_secret.voter_secrets.keys().copied().collect();
    let mut reshared = Vec::with_capacity(ids.len());
    for id in &ids {
        let r_ea = authority_secret.r_ea(*id)?; // authorized >= t reconstruction
        reshared.push((*id, share(r_ea, params.t, params.k, rng)?));
        // plain r_ea dropped here — only shares persist
    }
    for (id, shares) in reshared {
        authority_secret
            .voter_secrets
            .get_mut(&id)
            .expect("id came from the map")
            .r_ea_shares = shares;
    }
    authority_secret.threshold = params;
    Ok(())
}

/// The share of authority `authority_index` (1-based) for voter `id`.
pub fn authority_share(
    authority_secret: &AuthoritySecretState,
    id: VoterId,
    authority_index: u64,
) -> Result<Share> {
    let secret = authority_secret
        .voter_secrets
        .get(&id)
        .ok_or(CrDrError::UnknownVoter(id))?;
    secret
        .r_ea_shares
        .iter()
        .find(|s| s.index == authority_index)
        .copied()
        .ok_or_else(|| CrDrError::Threshold(format!("no share for authority {authority_index}")))
}
