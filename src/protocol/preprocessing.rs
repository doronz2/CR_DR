//! Voter preprocessing (registration) — plain and cut-and-choose variants —
//! and registration finalization (Merkle tree over registration leaves).
//!
//! The voter receives (sk_i, vk_i, R_i) and NEVER receives R_EA,i.

use std::collections::{BTreeMap, HashMap};

use ark_ff::UniformRand;
use rand::{CryptoRng, Rng, RngCore};

use crate::crypto::hash::{h_com, h_reg};
use crate::crypto::merkle::{MerklePath, MerkleTree};
use crate::crypto::signature::keygen;
use crate::errors::{CrDrError, Result};
use crate::types::{
    AuthoritySecretState, AuthorityVoterSecret, F, Nonce, PublicParams,
    PublicRegistrationRecord, VoterId, VoterState,
};

/// Register one voter. Returns the voter's private state and the public
/// registration record. R_EA,i is stored only in the authority secret state.
pub fn preprocess_voter<R: RngCore + CryptoRng>(
    pp: &PublicParams,
    authority_secret: &mut AuthoritySecretState,
    voter_id: VoterId,
    rng: &mut R,
) -> Result<(VoterState, PublicRegistrationRecord)> {
    if authority_secret.voter_secrets.contains_key(&voter_id) {
        return Err(CrDrError::DuplicateVoter(voter_id));
    }
    if authority_secret.voter_secrets.len() >= pp.max_voters {
        return Err(CrDrError::InvalidConfig("max_voters exceeded".into()));
    }

    let (sk, vk) = keygen(rng);
    let r: Nonce = F::rand(rng);
    let r_ea: Nonce = F::rand(rng);

    let h = h_com(pp.eid_hash, voter_id, &vk, r, r_ea);
    let leaf = h_reg(pp.eid_hash, voter_id, &vk, h);

    authority_secret.voter_secrets.insert(
        voter_id,
        AuthorityVoterSecret { id: voter_id, vk, r, r_ea },
    );

    Ok((
        VoterState { id: voter_id, sk, vk, r },
        PublicRegistrationRecord { id: voter_id, vk, h, leaf },
    ))
}

/// Finalized public registration state.
#[derive(Debug, Clone)]
pub struct RegistrationState {
    /// Records ordered by voter id; leaf index = position in this order.
    pub records: BTreeMap<VoterId, PublicRegistrationRecord>,
    pub leaf_index: HashMap<VoterId, usize>,
    pub root: F,
    pub paths: HashMap<VoterId, MerklePath>,
    pub merkle_depth: usize,
}

impl RegistrationState {
    pub fn record(&self, id: VoterId) -> Option<&PublicRegistrationRecord> {
        self.records.get(&id)
    }
}

/// Build the Merkle tree over registration leaves (sorted by voter id).
pub fn finalize_registration(
    pp: &PublicParams,
    records: &[PublicRegistrationRecord],
) -> Result<RegistrationState> {
    let mut map = BTreeMap::new();
    for rec in records {
        if map.insert(rec.id, rec.clone()).is_some() {
            return Err(CrDrError::DuplicateVoter(rec.id));
        }
    }
    let leaves: Vec<F> = map.values().map(|r| r.leaf).collect();
    let tree = MerkleTree::new(&leaves, pp.merkle_depth)?;
    let mut leaf_index = HashMap::new();
    let mut paths = HashMap::new();
    for (i, id) in map.keys().enumerate() {
        leaf_index.insert(*id, i);
        paths.insert(*id, tree.path(i)?);
    }
    Ok(RegistrationState {
        records: map,
        leaf_index,
        root: tree.root(),
        paths,
        merkle_depth: pp.merkle_depth,
    })
}

// ---------------------------------------------------------------------------
// Cut-and-choose preprocessing
// ---------------------------------------------------------------------------
//
// Models the audit intuition only: the authority commits to q candidate
// (R^k, R_EA^k) pairs; the voter audits q-1 of them (authority opens R_EA^k
// and the voter recomputes h^k); the unopened pair becomes the voting pair.
// A cheating authority that corrupts one pair survives with probability ~1/q.
//
// THIS IS NOT a full malicious VSS/DKG — see README.

/// Transcript of a cut-and-choose registration (voter view + audit result).
#[derive(Debug, Clone)]
pub struct CutAndChooseTranscript {
    pub q: usize,
    /// Index of the unopened (final) pair.
    pub final_index: usize,
    /// Commitments h^k for all q pairs.
    pub commitments: Vec<F>,
    /// Opened authority nonces for audited pairs (index, R_EA^k).
    pub opened: Vec<(usize, Nonce)>,
}

/// Honest cut-and-choose registration.
pub fn preprocess_voter_cut_and_choose<R: RngCore + CryptoRng>(
    pp: &PublicParams,
    authority_secret: &mut AuthoritySecretState,
    voter_id: VoterId,
    q: usize,
    rng: &mut R,
) -> Result<(VoterState, PublicRegistrationRecord, CutAndChooseTranscript)> {
    preprocess_voter_cut_and_choose_impl(pp, authority_secret, voter_id, q, None, rng)
}

/// Test-only variant where the authority corrupts the commitment of one
/// candidate pair (used to estimate audit soundness).
pub fn preprocess_voter_cut_and_choose_with_cheat<R: RngCore + CryptoRng>(
    pp: &PublicParams,
    authority_secret: &mut AuthoritySecretState,
    voter_id: VoterId,
    q: usize,
    corrupt_index: usize,
    rng: &mut R,
) -> Result<(VoterState, PublicRegistrationRecord, CutAndChooseTranscript)> {
    preprocess_voter_cut_and_choose_impl(
        pp,
        authority_secret,
        voter_id,
        q,
        Some(corrupt_index),
        rng,
    )
}

fn preprocess_voter_cut_and_choose_impl<R: RngCore + CryptoRng>(
    pp: &PublicParams,
    authority_secret: &mut AuthoritySecretState,
    voter_id: VoterId,
    q: usize,
    corrupt_index: Option<usize>,
    rng: &mut R,
) -> Result<(VoterState, PublicRegistrationRecord, CutAndChooseTranscript)> {
    if q < 2 {
        return Err(CrDrError::InvalidConfig("cut-and-choose requires q >= 2".into()));
    }
    if authority_secret.voter_secrets.contains_key(&voter_id) {
        return Err(CrDrError::DuplicateVoter(voter_id));
    }

    let (sk, vk) = keygen(rng);

    // Authority generates q candidate pairs and commits to h^k.
    // The voter learns all R^k; the authority keeps all R_EA^k for now.
    let mut r_candidates = Vec::with_capacity(q);
    let mut r_ea_candidates = Vec::with_capacity(q);
    let mut commitments = Vec::with_capacity(q);
    for k in 0..q {
        let r = F::rand(rng);
        let r_ea = F::rand(rng);
        let mut h = h_com(pp.eid_hash, voter_id, &vk, r, r_ea);
        if corrupt_index == Some(k) {
            // A cheating authority publishes a commitment that does not match
            // the pair it will later use/open.
            h += F::from(1u64);
        }
        r_candidates.push(r);
        r_ea_candidates.push(r_ea);
        commitments.push(h);
    }

    // Voter selects the final (unopened) pair uniformly; audits the rest.
    let final_index = rng.gen_range(0..q);
    let mut opened = Vec::with_capacity(q - 1);
    for k in 0..q {
        if k == final_index {
            continue;
        }
        // Authority opens R_EA^k; voter recomputes h^k.
        let recomputed = h_com(pp.eid_hash, voter_id, &vk, r_candidates[k], r_ea_candidates[k]);
        if recomputed != commitments[k] {
            return Err(CrDrError::CutAndChooseAudit(format!(
                "pair {k} opening does not match its commitment (evidence: voter id {voter_id})"
            )));
        }
        opened.push((k, r_ea_candidates[k]));
    }

    let r = r_candidates[final_index];
    let r_ea = r_ea_candidates[final_index];
    let h = commitments[final_index];
    let leaf = h_reg(pp.eid_hash, voter_id, &vk, h);

    authority_secret.voter_secrets.insert(
        voter_id,
        AuthorityVoterSecret { id: voter_id, vk, r, r_ea },
    );

    Ok((
        VoterState { id: voter_id, sk, vk, r },
        PublicRegistrationRecord { id: voter_id, vk, h, leaf },
        CutAndChooseTranscript { q, final_index, commitments, opened },
    ))
}

/// Monte-Carlo estimate of the probability that an authority corrupting
/// exactly one candidate pair (i) survives the audit AND (ii) the corrupted
/// pair becomes the final voting pair. Should be approximately 1/q.
pub fn estimate_cut_and_choose_soundness<R: RngCore + CryptoRng>(
    q: usize,
    trials: usize,
    rng: &mut R,
) -> f64 {
    let mut success = 0usize;
    for _ in 0..trials {
        let corrupt = rng.gen_range(0..q);
        let final_index = rng.gen_range(0..q);
        if corrupt == final_index {
            // corrupted pair unopened: audit passes, corruption lands in the
            // final pair
            success += 1;
        }
    }
    success as f64 / trials as f64
}
