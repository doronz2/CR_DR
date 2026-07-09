//! CAST-ZK ballot format tests: pi_cast acceptance/rejection, cast proofs
//! for fake-compliance and chaff ballots, and the public-leakage regression
//! over the full board entry bytes.
//!
//! Native checks always run; Groth16 checks skip if the cast-circuit
//! artifacts are absent (scripts/compile_circuits.sh cast +
//! scripts/setup_groth16.sh cast).

mod common;

use cr_dr::protocol::chaff::chaff_ballot;
use cr_dr::protocol::fake_compliance::{build_fake_ballot, fake_compliance};
use cr_dr::protocol::vote::cast_vote;
use cr_dr::types::{f_to_dec, Ballot, F};
use cr_dr::zk::cast::{
    cast_relation_check_native, prove_cast, verify_cast_entry, CastProof, CAST_CIRCUIT,
};
use cr_dr::zk::groth16_backend::SnarkjsBackend;

fn cast_toolchain() -> Option<std::path::PathBuf> {
    let root = SnarkjsBackend::crate_root();
    let be = SnarkjsBackend { root: root.clone(), circuit: CAST_CIRCUIT.into() };
    if be.toolchain_available() {
        Some(root)
    } else {
        eprintln!("SKIP: cast circuit artifacts not found");
        None
    }
}

#[test]
fn valid_cast_proof_accepted() {
    let mut env = common::small_election(400);
    let ballot = cast_vote(&env.pp, &env.reg, &env.voters[0], 1, &mut env.rng).unwrap();
    assert!(cast_relation_check_native(&env.pp.pk_ea, &ballot.public(), &ballot.secret));

    let Some(root) = cast_toolchain() else { return };
    let proof = prove_cast(&root, &env.pp.pk_ea, &ballot.public(), &ballot.secret).unwrap();
    assert!(verify_cast_entry(&root, &env.pp.pk_ea, &ballot.public(), &proof).unwrap());
}

#[test]
fn tampered_com_rejected_by_cast_verification() {
    let mut env = common::small_election(401);
    let ballot = cast_vote(&env.pp, &env.reg, &env.voters[0], 1, &mut env.rng).unwrap();
    let mut entry = ballot.public();
    entry.com += F::from(1u64);
    // Native relation rejects...
    assert!(!cast_relation_check_native(&env.pp.pk_ea, &entry, &ballot.secret));

    let Some(root) = cast_toolchain() else { return };
    // ...proving the tampered entry is impossible (hard constraints)...
    assert!(prove_cast(&root, &env.pp.pk_ea, &entry, &ballot.secret).is_err());
    // ...and a proof for the ORIGINAL entry does not verify for the
    // tampered one (public-input binding).
    let proof = prove_cast(&root, &env.pp.pk_ea, &ballot.public(), &ballot.secret).unwrap();
    assert!(!verify_cast_entry(&root, &env.pp.pk_ea, &entry, &proof).unwrap());
}

#[test]
fn tampered_ct_open_rejected_by_cast_verification() {
    let mut env = common::small_election(402);
    let ballot = cast_vote(&env.pp, &env.reg, &env.voters[0], 2, &mut env.rng).unwrap();
    let mut entry = ballot.public();
    entry.ct_open.masked[4] += F::from(1u64); // tamper the encrypted candidate
    assert!(!cast_relation_check_native(&env.pp.pk_ea, &entry, &ballot.secret));

    let Some(root) = cast_toolchain() else { return };
    assert!(prove_cast(&root, &env.pp.pk_ea, &entry, &ballot.secret).is_err());
    let proof = prove_cast(&root, &env.pp.pk_ea, &ballot.public(), &ballot.secret).unwrap();
    assert!(!verify_cast_entry(&root, &env.pp.pk_ea, &entry, &proof).unwrap());
}

#[test]
fn tampered_cast_proof_rejected() {
    let mut env = common::small_election(403);
    let Some(root) = cast_toolchain() else { return };
    let ballot = cast_vote(&env.pp, &env.reg, &env.voters[0], 0, &mut env.rng).unwrap();
    let proof = prove_cast(&root, &env.pp.pk_ea, &ballot.public(), &ballot.secret).unwrap();

    // Corrupt the proof itself: swap pi_a coordinates.
    let mut bad = proof.clone();
    let pa = bad.proof["pi_a"].clone();
    bad.proof["pi_a"] = serde_json::json!([pa[1], pa[0], pa[2]]);
    assert!(!verify_cast_entry(&root, &env.pp.pk_ea, &ballot.public(), &bad).unwrap());

    // Corrupt the bound public inputs: claims a different com.
    let mut bad2 = proof.clone();
    bad2.public[0] = serde_json::json!("12345");
    assert!(!verify_cast_entry(&root, &env.pp.pk_ea, &ballot.public(), &bad2).unwrap());

    // A proof from a DIFFERENT ballot must not transplant.
    let other = cast_vote(&env.pp, &env.reg, &env.voters[1], 1, &mut env.rng).unwrap();
    let other_proof = prove_cast(&root, &env.pp.pk_ea, &other.public(), &other.secret).unwrap();
    assert!(!verify_cast_entry(&root, &env.pp.pk_ea, &ballot.public(), &other_proof).unwrap());
}

#[test]
fn fake_compliance_ballot_has_valid_cast_proof() {
    // pi_cast attests casting well-formedness ONLY — a fake-compliance
    // ballot (real sk, fake nonce) casts perfectly validly and is publicly
    // indistinguishable; it fails only the HIDDEN nonce relation at tally.
    let mut env = common::small_election(404);
    let t = fake_compliance(&env.pp, &env.voters[0], 2, &mut env.rng).unwrap();
    let fake = build_fake_ballot(&env.pp, &t, &mut env.rng).unwrap();
    assert!(cast_relation_check_native(&env.pp.pk_ea, &fake.public(), &fake.secret));

    let Some(root) = cast_toolchain() else { return };
    let proof = prove_cast(&root, &env.pp.pk_ea, &fake.public(), &fake.secret).unwrap();
    assert!(verify_cast_entry(&root, &env.pp.pk_ea, &fake.public(), &proof).unwrap());
}

#[test]
fn chaff_ballot_has_valid_cast_proof() {
    let mut env = common::small_election(405);
    let chaff = chaff_ballot(&env.pp, &mut env.rng).unwrap();
    assert!(cast_relation_check_native(&env.pp.pk_ea, &chaff.public(), &chaff.secret));

    let Some(root) = cast_toolchain() else { return };
    let proof = prove_cast(&root, &env.pp.pk_ea, &chaff.public(), &chaff.secret).unwrap();
    assert!(verify_cast_entry(&root, &env.pp.pk_ea, &chaff.public(), &proof).unwrap());
}

#[test]
fn public_ballot_bytes_leak_nothing() {
    // The full public representation of a board (entry bytes + serialized
    // board JSON) must contain none of: the opening fields (incl. R and
    // the signature), r_com, rho_enc, R_EA,i, the candidate in the clear,
    // validity labels, or sorted-record data.
    let mut env = common::small_election(406);
    let coerced = env.voters[0].clone();
    let t = fake_compliance(&env.pp, &coerced, 2, &mut env.rng).unwrap();
    let ballots: Vec<Ballot> = vec![
        build_fake_ballot(&env.pp, &t, &mut env.rng).unwrap(),
        cast_vote(&env.pp, &env.reg, &coerced, 0, &mut env.rng).unwrap(),
        chaff_ballot(&env.pp, &mut env.rng).unwrap(),
    ];
    let mut board = cr_dr::protocol::bulletin_board::BulletinBoard::new();
    for b in &ballots {
        board.append(b.public());
    }
    let board_json = serde_json::to_string(&board).unwrap();
    let board_hex: String =
        ballots.iter().map(|b| hex::encode(b.bytes())).collect::<Vec<_>>().join("");

    let mut secrets: Vec<(String, String)> = Vec::new();
    for (i, b) in ballots.iter().enumerate() {
        for (j, f) in b.secret.opening.plaintext_fields.iter().enumerate() {
            secrets.push((format!("ballot {i} opening[{j}]"), f_to_dec(f)));
        }
        secrets.push((format!("ballot {i} r_com"), f_to_dec(&b.secret.opening.rho)));
        secrets.push((format!("ballot {i} rho_enc"), f_to_dec(&b.secret.rho_enc)));
    }
    // R_i and R_EA,i of the coerced voter.
    secrets.push(("voter R_i".into(), f_to_dec(&coerced.r)));
    secrets.push(("R_EA,i".into(), f_to_dec(&env.authority.r_ea(coerced.id).unwrap())));

    for (label, val) in &secrets {
        if val.len() <= 8 {
            continue; // short ids/candidates collide as substrings
        }
        assert!(!board_json.contains(val.as_str()), "board JSON leaks {label}");
        // hex form of the field bytes
        let hex_val = hex::encode(cr_dr::types::f_to_bytes_be(
            &cr_dr::types::f_from_dec(val).unwrap(),
        ));
        assert!(!board_hex.contains(&hex_val), "board bytes leak {label}");
    }

    // No validity labels or sorted-record structures in the public data.
    for key in ["valid", "counted", "sorted", "status", "Counted", "InvalidRegistration"] {
        assert!(!board_json.contains(key), "board JSON leaks label {key}");
    }
}

// ---------------------------------------------------------------------------
// Path 1 end-to-end: BB_adm = Clean(BB_raw)
// ---------------------------------------------------------------------------

#[test]
fn clean_admits_exactly_valid_cast_entries_and_tally_binds_admitted_board() {
    use cr_dr::protocol::admission::{clean, ea_open_admitted};
    use cr_dr::protocol::bulletin_board::BulletinBoard;
    use cr_dr::protocol::filter_and_tally::filter_and_tally;
    use cr_dr::zk::statement::{build_tally_statement, statement_matches_public_data};

    let Some(root) = cast_toolchain() else { return };
    let mut env = common::small_election(410);

    // real + fake-compliance + chaff (all with valid pi_cast), plus one
    // entry with a TAMPERED com (its proof cannot bind) and one with no
    // proof at all.
    let coerced = env.voters[0].clone();
    let t = fake_compliance(&env.pp, &coerced, 2, &mut env.rng).unwrap();
    let good: Vec<Ballot> = vec![
        build_fake_ballot(&env.pp, &t, &mut env.rng).unwrap(),
        cast_vote(&env.pp, &env.reg, &coerced, 0, &mut env.rng).unwrap(),
        cast_vote(&env.pp, &env.reg, &env.voters[1], 1, &mut env.rng).unwrap(),
        chaff_ballot(&env.pp, &mut env.rng).unwrap(),
    ];
    let mut raw = BulletinBoard::new();
    let mut proofs = Vec::new();
    for b in &good {
        raw.append(b.public());
        proofs.push(Some(prove_cast(&root, &env.pp.pk_ea, &b.public(), &b.secret).unwrap()));
    }
    // tampered entry: proof made for the true entry, com then changed
    let bad = cast_vote(&env.pp, &env.reg, &env.voters[2], 2, &mut env.rng).unwrap();
    let bad_proof = prove_cast(&root, &env.pp.pk_ea, &bad.public(), &bad.secret).unwrap();
    let mut bad_entry = bad.public();
    bad_entry.com += F::from(1u64);
    raw.append(bad_entry.clone());
    proofs.push(Some(bad_proof));
    // proofless entry
    let np = cast_vote(&env.pp, &env.reg, &env.voters[3], 1, &mut env.rng).unwrap();
    raw.append(np.public());
    proofs.push(None);

    // PUBLIC recomputation: BB_adm = Clean(BB_raw).
    let (admitted, indices) = clean(&raw, &proofs, |entry, proof| {
        cr_dr::zk::cast::verify_cast_entry(&root, &env.pp.pk_ea, entry, proof)
    })
    .unwrap();
    // Exactly the four valid-pi_cast entries — fake and chaff INCLUDED.
    assert_eq!(admitted.len(), 4);
    assert_eq!(indices, vec![0, 1, 2, 3]);
    assert!(admitted.contains(&good[0].com), "fake-compliance entry must be admitted");
    assert!(admitted.contains(&good[3].com), "chaff entry must be admitted");
    assert!(!admitted.contains(&bad_entry.com));
    assert!(!admitted.contains(&np.com));

    // EA decrypts the admitted openings and tallies; fake/chaff are
    // rejected ONLY here, inside the private tally relation.
    let openings = ea_open_admitted(&env.authority, &raw, &indices).unwrap();
    let (tally, _) =
        filter_and_tally(&env.pp, &env.authority, &env.reg, &admitted, &openings).unwrap();
    assert_eq!(tally.counts, vec![1, 1, 0]);

    // The tally statement binds the admitted-board commitment that any
    // public verifier recomputes from Clean(BB_raw).
    let statement = build_tally_statement(&env.pp, &admitted, &env.reg, &tally);
    assert!(statement_matches_public_data(&statement, &env.pp, &admitted, &env.reg));
    let (admitted2, _) = clean(&raw, &proofs, |entry, proof| {
        cr_dr::zk::cast::verify_cast_entry(&root, &env.pp.pk_ea, entry, proof)
    })
    .unwrap();
    assert_eq!(admitted, admitted2, "Clean is deterministic and publicly recomputable");
}
