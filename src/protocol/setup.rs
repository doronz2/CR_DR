//! Election setup: generates public parameters and the authority secret
//! state (EA decryption key, EA receipt-signing key).

use std::collections::{HashMap, HashSet};

use rand::{CryptoRng, RngCore};

use crate::crypto::encryption::ea_keygen;
use crate::crypto::hash::eid_to_field;
use crate::crypto::signature::keygen;
use crate::errors::{CrDrError, Result};
use crate::types::{AuthoritySecretState, ElectionConfig, PublicParams};

pub fn setup_election<R: RngCore + CryptoRng>(
    config: ElectionConfig,
    rng: &mut R,
) -> Result<(PublicParams, AuthoritySecretState)> {
    if config.candidates.is_empty() {
        return Err(CrDrError::InvalidConfig("empty candidate set".into()));
    }
    let distinct: HashSet<_> = config.candidates.iter().collect();
    if distinct.len() != config.candidates.len() {
        return Err(CrDrError::InvalidConfig("duplicate candidates".into()));
    }
    if config.max_voters == 0 || config.max_voters > (1usize << config.merkle_depth) {
        return Err(CrDrError::InvalidConfig(format!(
            "max_voters {} must be in 1..=2^{}",
            config.max_voters, config.merkle_depth
        )));
    }
    if config.max_ballots == 0 {
        return Err(CrDrError::InvalidConfig("max_ballots must be positive".into()));
    }
    if let Some(tp) = &config.threshold_params {
        if tp.t == 0 || tp.t > tp.k {
            return Err(CrDrError::InvalidConfig(format!(
                "threshold params t={} k={} invalid",
                tp.t, tp.k
            )));
        }
    }

    let (sk_ea, pk_ea) = ea_keygen(rng);
    let (receipt_sk, ea_receipt_vk) = keygen(rng);

    let pp = PublicParams {
        eid_hash: eid_to_field(&config.eid),
        eid: config.eid,
        candidates: config.candidates,
        pk_ea,
        ea_receipt_vk,
        duplicate_rule: config.duplicate_rule,
        max_ballots: config.max_ballots,
        max_voters: config.max_voters,
        merkle_depth: config.merkle_depth,
        threshold_params: config.threshold_params,
    };
    let authority = AuthoritySecretState {
        sk_ea,
        receipt_sk,
        voter_secrets: HashMap::new(),
        threshold_nonce_shares: None,
    };
    Ok((pp, authority))
}
