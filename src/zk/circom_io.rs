//! Serialization of (statement, witness) into the circom input.json format
//! expected by `circuits/main/filter_and_tally*.circom`, and small helpers
//! for reading snarkjs artifacts.

use serde_json::{json, Value};

use crate::errors::Result;
use crate::types::{f_to_dec, F};
use crate::zk::statement::TallyStatement;
use crate::zk::witness::{padded_rows, TallyWitness};
use crate::zk::CircuitShape;

fn dec(f: &F) -> Value {
    Value::String(f_to_dec(f))
}

/// Build the full circom witness input (public inputs + private witness).
pub fn generate_witness_input(
    statement: &TallyStatement,
    witness: &TallyWitness,
    shape: &CircuitShape,
) -> Result<Value> {
    let rows = padded_rows(witness, shape)?;

    let ct: Vec<Value> = rows.iter().map(|r| dec(&r.ct)).collect();
    let pt: Vec<Value> = rows
        .iter()
        .map(|r| Value::Array(r.pt_fields.iter().map(dec).collect()))
        .collect();
    let rho: Vec<Value> = rows.iter().map(|r| dec(&r.rho)).collect();
    let r_ea: Vec<Value> = rows.iter().map(|r| dec(&r.r_ea)).collect();
    let path_elements: Vec<Value> = rows
        .iter()
        .map(|r| Value::Array(r.merkle_path.iter().map(dec).collect()))
        .collect();
    let path_index: Vec<Value> = rows
        .iter()
        .map(|r| {
            Value::Array(
                r.merkle_index
                    .iter()
                    .map(|b| Value::String(if *b { "1".into() } else { "0".into() }))
                    .collect(),
            )
        })
        .collect();

    Ok(json!({
        // public inputs
        "eid_hash": dec(&statement.eid_hash),
        "mr": dec(&statement.mr),
        "candidate_set_commitment": dec(&statement.candidate_set_commitment),
        "bb_commitment": dec(&statement.bb_commitment),
        "num_ballots": statement.num_ballots.to_string(),
        "num_voters": statement.num_voters.to_string(),
        "duplicate_rule_id": statement.duplicate_rule_id.to_string(),
        "pk_ea_commitment": dec(&statement.pk_ea_commitment),
        "tally_counts": statement.tally_counts.iter().map(|c| c.to_string()).collect::<Vec<_>>(),
        // private witness
        "candidates": witness.candidates.iter().map(|c| c.to_string()).collect::<Vec<_>>(),
        "ct": ct,
        "pt": pt,
        "rho": rho,
        "r_ea": r_ea,
        "path_elements": path_elements,
        "path_index": path_index,
    }))
}
