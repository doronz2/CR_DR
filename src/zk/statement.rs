//! Public ZK statement for the FilterAndTally relation.
//!
//! Contains ONLY public data: it never mentions which ballots were valid,
//! who voted, rejection reasons, plaintexts, R_i or R_EA,i.

use serde::{Deserialize, Serialize};

use crate::crypto::hash::{bb_commitment, candidate_set_commitment, pk_ea_commitment};
use crate::protocol::bulletin_board::BulletinBoard;
use crate::protocol::preprocessing::RegistrationState;
use crate::types::{fserde, F, PublicParams, TallyResult};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TallyStatement {
    #[serde(with = "fserde")]
    pub eid_hash: F,
    #[serde(with = "fserde")]
    pub pk_ea_commitment: F,
    /// Merkle root over the registration leaves.
    #[serde(with = "fserde")]
    pub mr: F,
    #[serde(with = "fserde")]
    pub candidate_set_commitment: F,
    pub tally_counts: Vec<u64>,
    /// Poseidon chain over the ciphertext fields of the posted ballots.
    #[serde(with = "fserde")]
    pub bb_commitment: F,
    pub num_ballots: u64,
    pub num_voters: u64,
    pub duplicate_rule_id: u64,
}

/// Build the public statement from public data only.
pub fn build_tally_statement(
    pp: &PublicParams,
    bb: &BulletinBoard,
    registration_state: &RegistrationState,
    tally: &TallyResult,
) -> TallyStatement {
    let ct_fields: Vec<Vec<F>> = bb
        .list_public_ballots()
        .iter()
        .map(|b| b.ciphertext.fields.clone())
        .collect();
    TallyStatement {
        eid_hash: pp.eid_hash,
        pk_ea_commitment: pk_ea_commitment(&pp.pk_ea),
        mr: registration_state.root,
        candidate_set_commitment: candidate_set_commitment(&pp.candidates),
        tally_counts: tally.counts.clone(),
        bb_commitment: bb_commitment(&ct_fields),
        num_ballots: bb.len() as u64,
        num_voters: registration_state.records.len() as u64,
        duplicate_rule_id: pp.duplicate_rule.id(),
    }
}

/// Check that a claimed statement is THE statement determined by the public
/// election data (params, registration, board) — everything except the tally
/// counts, which are what the proof attests to.
///
/// Verifiers MUST run this alongside the Groth16 proof check. In particular
/// `pk_ea_commitment` is bound into the proof by the verification equation
/// but is not otherwise constrained by the circuit, so its meaning comes
/// from this native recomputation from public data. (`num_voters` IS
/// circuit-constrained since the indexed registration table: it selects the
/// in-range window of registration rows — this check additionally pins it
/// to the actual public table size.)
pub fn statement_matches_public_data(
    statement: &TallyStatement,
    pp: &PublicParams,
    bb: &BulletinBoard,
    registration_state: &RegistrationState,
) -> bool {
    let expected = build_tally_statement(
        pp,
        bb,
        registration_state,
        &TallyResult { counts: statement.tally_counts.clone(), counted_ballots: 0 },
    );
    *statement == expected && statement.tally_counts.len() == pp.candidates.len()
}
