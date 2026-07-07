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
    let reg_vkx: Vec<Value> = rows.iter().map(|r| dec(&r.reg_vkx)).collect();
    let reg_vky: Vec<Value> = rows.iter().map(|r| dec(&r.reg_vky)).collect();
    let reg_h: Vec<Value> = rows.iter().map(|r| dec(&r.reg_h)).collect();
    let path_elements: Vec<Value> = rows
        .iter()
        .map(|r| Value::Array(r.merkle_path.iter().map(dec).collect()))
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
        "reg_vkx": reg_vkx,
        "reg_vky": reg_vky,
        "reg_h": reg_h,
        "path_elements": path_elements,
    }))
}

/// The snarkjs `public.json` a proof of `statement` must carry: the circuit's
/// public inputs as decimal strings, in the declaration order of
/// `FilterAndTally` (which is also the order of the `public [...]` list in
/// the main components).
pub fn statement_public_inputs(statement: &TallyStatement) -> Vec<String> {
    let mut v = vec![
        f_to_dec(&statement.eid_hash),
        f_to_dec(&statement.mr),
        f_to_dec(&statement.candidate_set_commitment),
        f_to_dec(&statement.bb_commitment),
        statement.num_ballots.to_string(),
        statement.num_voters.to_string(),
        statement.duplicate_rule_id.to_string(),
        f_to_dec(&statement.pk_ea_commitment),
    ];
    v.extend(statement.tally_counts.iter().map(|c| c.to_string()));
    v
}

/// True iff a snarkjs `public.json` value is exactly the public inputs of
/// `statement`. A proof that verifies against different public inputs proves
/// a different statement and must be rejected by anyone verifying THIS tally.
pub fn public_inputs_match(public: &Value, statement: &TallyStatement) -> bool {
    let Some(arr) = public.as_array() else {
        return false;
    };
    let expected = statement_public_inputs(statement);
    arr.len() == expected.len()
        && arr.iter().zip(&expected).all(|(v, e)| v.as_str() == Some(e.as_str()))
}
