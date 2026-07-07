//! Threshold-private voter preprocessing (registration) — plain and
//! cut-and-choose variants — and registration finalization (indexed Merkle
//! tree over registration leaves).
//!
//! ## Trust model (single logical EA, threshold authorities)
//!
//! Preprocessing is modeled as an IDEALIZED private functionality F_prep
//! between the voter and the k threshold authorities:
//!
//!   * the VOTER samples and keeps (sk_i, vk_i, R_i) — `voter_registration_
//!     secrets`. R_i is never an input to any authority-side state.
//!   * the AUTHORITY side threshold-generates R_EA,i: F_prep samples it,
//!     immediately Shamir-shares it t-of-k, hands share j to authority j,
//!     and ERASES the plain value. No below-threshold coalition (< t
//!     authorities) learns anything about R_EA,i (< t Shamir shares are
//!     distributed independently of the secret) — and no authority ever
//!     sees R_i.
//!   * F_prep computes the public commitment
//!         h_i = H_com(eid, i, vk_i, R_i, R_EA,i)
//!     (only the functionality ever holds both nonces together) and outputs
//!     the public row (i, vk_i, h_i, leaf_i).
//!
//! This file implements F_prep directly (research prototype — not a full
//! MPC protocol); the STATE SEPARATION is the theorem-relevant part:
//! `VoterState` = (sk_i, vk_i, R_i) only, `AuthorityVoterSecret` = shares of
//! R_EA,i only, and the public table = (i, vk_i, h_i, leaf_i) only. The
//! below-threshold simulatability claim is exercised by
//! `threshold::malicious_view_model`.
//!
//! ## Indexed registration table
//!
//! Registration is an INDEXED public table: voter id i IS the Merkle leaf
//! index. `finalize_registration` therefore requires the registered ids to
//! be exactly 0..N-1, and
//!     Reg[i] = (i, vk_i, h_i),
//!     leaf_i = H_reg(eid, i, vk_i, h_i),
//!     MR     = MerkleRoot(leaf_0, ..., leaf_{N-1}).
//! A ballot claiming identity i is checked against row i and no other row —
//! the tally prover is not free to pick a different leaf/path for it.

use std::collections::{BTreeMap, HashMap};

use ark_ff::UniformRand;
use rand::{CryptoRng, Rng, RngCore};

use crate::crypto::hash::{h_com, h_reg};
use crate::crypto::merkle::{MerklePath, MerkleTree};
use crate::crypto::shamir::share;
use crate::crypto::signature::{keygen, SecretKey, VerificationKey};
use crate::errors::{CrDrError, Result};
use crate::types::{
    AuthoritySecretState, AuthorityVoterSecret, F, Nonce, PublicParams,
    PublicRegistrationRecord, ThresholdParams, VoterId, VoterState,
};

/// VOTER-SIDE registration secrets. The voter samples all three values
/// locally; none of them is an input to the authority side.
#[derive(Debug, Clone)]
pub struct VoterRegistrationSecrets {
    pub sk: SecretKey,
    pub vk: VerificationKey,
    pub r: Nonce,
}

/// Voter-side sampling of (sk_i, vk_i, R_i).
pub fn voter_registration_secrets<R: RngCore + CryptoRng>(
    rng: &mut R,
) -> VoterRegistrationSecrets {
    let (sk, vk) = keygen(rng);
    VoterRegistrationSecrets { sk, vk, r: F::rand(rng) }
}

/// Threshold parameters in effect for nonce sharing.
fn nonce_threshold(pp: &PublicParams) -> ThresholdParams {
    pp.threshold_params.unwrap_or(ThresholdParams::single())
}

/// Register one voter — the idealized functionality F_prep (see module
/// docs). Returns the voter's private state and the public registration
/// record. The authority state receives ONLY Shamir shares of R_EA,i; the
/// plain nonce is erased before this function returns, and R_i never enters
/// the authority state at all.
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
    if voter_id >= pp.max_voters as u64 {
        return Err(CrDrError::InvalidConfig(format!(
            "voter id {voter_id} out of the indexed range 0..{}",
            pp.max_voters
        )));
    }

    // Voter side: the voter samples and keeps (sk, vk, R_i).
    let voter = voter_registration_secrets(rng);

    // Authority side, inside F_prep: threshold-generate R_EA,i.
    let tp = nonce_threshold(pp);
    let r_ea: Nonce = F::rand(rng);
    let r_ea_shares = share(r_ea, tp.t, tp.k, rng)?;

    // Only F_prep holds R_i and R_EA,i together, exactly long enough to
    // compute the binding-and-hiding public commitment h_i.
    let h = h_com(pp.eid_hash, voter_id, &voter.vk, voter.r, r_ea);
    let leaf = h_reg(pp.eid_hash, voter_id, &voter.vk, h);
    let _ = r_ea; // erased: from here on only shares exist

    authority_secret.voter_secrets.insert(
        voter_id,
        AuthorityVoterSecret { id: voter_id, vk: voter.vk, r_ea_shares },
    );

    Ok((
        VoterState { id: voter_id, sk: voter.sk, vk: voter.vk, r: voter.r },
        PublicRegistrationRecord { id: voter_id, vk: voter.vk, h, leaf },
    ))
}

/// Finalized public registration state: the INDEXED table Reg[0..N-1] and
/// its Merkle tree. Contains only public data.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RegistrationState {
    /// Records ordered by voter id. Ids are dense: record i sits at Merkle
    /// leaf index i (the ballot identity determines the leaf index).
    pub records: BTreeMap<VoterId, PublicRegistrationRecord>,
    pub leaf_index: HashMap<VoterId, usize>,
    #[serde(with = "crate::types::fserde")]
    pub root: F,
    pub paths: HashMap<VoterId, MerklePath>,
    pub merkle_depth: usize,
}

impl RegistrationState {
    pub fn record(&self, id: VoterId) -> Option<&PublicRegistrationRecord> {
        self.records.get(&id)
    }

    /// Number of registered voters N (rows 0..N-1).
    pub fn num_voters(&self) -> usize {
        self.records.len()
    }
}

/// Build the Merkle tree over registration leaves. The registered ids must
/// be exactly 0..N-1: the table is INDEXED (leaf index = voter id), so a
/// ballot's claimed identity deterministically selects its registration row.
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
    for (expected, id) in map.keys().enumerate() {
        if *id != expected as u64 {
            return Err(CrDrError::InvalidConfig(format!(
                "registration ids must be dense 0..N-1 (indexed table); \
                 missing id {expected}, found {id}"
            )));
        }
    }
    let leaves: Vec<F> = map.values().map(|r| r.leaf).collect();
    let tree = MerkleTree::new(&leaves, pp.merkle_depth)?;
    let mut leaf_index = HashMap::new();
    let mut paths = HashMap::new();
    for (i, id) in map.keys().enumerate() {
        debug_assert_eq!(i as u64, *id);
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
// Models the audit intuition only: the authority side commits to q candidate
// R_EA^k values via h^k = H_com(eid, i, vk, R_i, R_EA^k) (computed inside
// F_prep — the voter's R_i is fixed across candidates and never given to the
// authorities); the voter audits q-1 of them (the authority opens R_EA^k and
// the voter recomputes h^k); the unopened pair becomes the voting pair and
// its R_EA is threshold-shared like in the plain flow. A cheating authority
// that corrupts one pair survives with probability ~1/q.
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
    if voter_id >= pp.max_voters as u64 {
        return Err(CrDrError::InvalidConfig(format!(
            "voter id {voter_id} out of the indexed range 0..{}",
            pp.max_voters
        )));
    }

    // Voter side: (sk, vk, R_i) — R_i fixed across all q candidates.
    let voter = voter_registration_secrets(rng);

    // Authority side generates q candidate R_EA^k; F_prep commits to each.
    let mut r_ea_candidates = Vec::with_capacity(q);
    let mut commitments = Vec::with_capacity(q);
    for k in 0..q {
        let r_ea = F::rand(rng);
        let mut h = h_com(pp.eid_hash, voter_id, &voter.vk, voter.r, r_ea);
        if corrupt_index == Some(k) {
            // A cheating authority publishes a commitment that does not match
            // the pair it will later use/open.
            h += F::from(1u64);
        }
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
        // Authority opens R_EA^k; the voter recomputes h^k with their R_i.
        let recomputed =
            h_com(pp.eid_hash, voter_id, &voter.vk, voter.r, r_ea_candidates[k]);
        if recomputed != commitments[k] {
            return Err(CrDrError::CutAndChooseAudit(format!(
                "pair {k} opening does not match its commitment (evidence: voter id {voter_id})"
            )));
        }
        opened.push((k, r_ea_candidates[k]));
    }

    let h = commitments[final_index];
    let leaf = h_reg(pp.eid_hash, voter_id, &voter.vk, h);

    // Threshold-share the final R_EA and erase the plain value.
    let tp = nonce_threshold(pp);
    let r_ea_shares = share(r_ea_candidates[final_index], tp.t, tp.k, rng)?;
    drop(r_ea_candidates);

    authority_secret.voter_secrets.insert(
        voter_id,
        AuthorityVoterSecret { id: voter_id, vk: voter.vk, r_ea_shares },
    );

    Ok((
        VoterState { id: voter_id, sk: voter.sk, vk: voter.vk, r: voter.r },
        PublicRegistrationRecord { id: voter_id, vk: voter.vk, h, leaf },
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
