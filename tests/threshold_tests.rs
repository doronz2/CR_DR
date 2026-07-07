mod common;

use ark_ff::UniformRand;
use cr_dr::threshold::malicious_view_model::{
    AdversaryAuxiliaryState, ThresholdViewSimulator, TrustedDealerShamirSimulator,
};
use cr_dr::threshold::trusted_dealer::{
    authority_share, reconstruct_nonce, share_all_nonces, share_nonce,
};
use cr_dr::types::{F, ThresholdParams};

#[test]
fn trusted_dealer_reconstructs_with_t_shares() {
    let mut rng = common::rng(100);
    let secret = F::rand(&mut rng);
    let shares = share_nonce(secret, 3, 5, &mut rng).unwrap();
    assert_eq!(reconstruct_nonce(&shares[0..3]).unwrap(), secret);
    assert_eq!(reconstruct_nonce(&[shares[4], shares[2], shares[0]]).unwrap(), secret);
}

#[test]
fn fewer_than_t_shares_cannot_reconstruct() {
    let mut rng = common::rng(101);
    let secret = F::rand(&mut rng);
    let shares = share_nonce(secret, 3, 5, &mut rng).unwrap();
    // Interpolating any 2 shares yields a value unrelated to the secret.
    assert_ne!(reconstruct_nonce(&shares[0..2]).unwrap(), secret);
    assert_ne!(reconstruct_nonce(&shares[3..5]).unwrap(), secret);

    // Stronger: two different secrets, same evaluation points — t-1 shares
    // are identically distributed (uniform), so equal share values for one
    // secret can be produced for the other. Sanity-check independence by
    // verifying a fresh sharing of a DIFFERENT secret can produce any
    // 2-share prefix pattern (statistically: values differ across runs).
    let other = F::rand(&mut rng);
    let shares2 = share_nonce(other, 3, 5, &mut rng).unwrap();
    assert_ne!(shares2[0].value, shares[0].value);
}

#[test]
fn share_all_nonces_covers_every_voter() {
    let mut env = common::small_election(102);
    share_all_nonces(&mut env.authority, ThresholdParams { t: 2, k: 3 }, &mut env.rng).unwrap();
    for id in 0..6u64 {
        let s1 = authority_share(&env.authority, id, 1).unwrap();
        let s2 = authority_share(&env.authority, id, 2).unwrap();
        let rec = reconstruct_nonce(&[s1, s2]).unwrap();
        assert_eq!(rec, env.authority.r_ea(id).unwrap());
    }
}

#[test]
fn simulator_does_not_receive_r_ea() {
    // Structural check: the simulator is constructed from PUBLIC data only
    // (threshold params, voter ids, public commitments, a seed). There is no
    // way to pass R_EA,i to it — this test documents and pins that API.
    let env = common::small_election(103);
    let sim = TrustedDealerShamirSimulator {
        params: ThresholdParams { t: 3, k: 5 },
        voter_ids: env.reg.records.keys().copied().collect(),
        public_commitments: env.reg.records.values().map(|r| r.h).collect(),
        seed: 7,
    };
    let aux = AdversaryAuxiliaryState::default();
    let view = sim.simulate_honest_generated_view(&env.pp, &[0, 1], &aux);
    // One simulated share vector per corrupted authority, one entry per voter.
    assert_eq!(view.honest_messages_to_corrupted.len(), 2);
    for shares in view.honest_messages_to_corrupted.values() {
        assert_eq!(shares.len(), 6);
    }
    // The public transcript is exactly the (already public) commitments.
    assert_eq!(view.honest_public_transcript.len(), 6);
}

#[test]
fn adversary_aux_is_context_not_simulated_output() {
    let env = common::small_election(104);
    let sim = TrustedDealerShamirSimulator {
        params: ThresholdParams { t: 3, k: 5 },
        voter_ids: env.reg.records.keys().copied().collect(),
        public_commitments: vec![],
        seed: 8,
    };
    let mut aux = AdversaryAuxiliaryState::default();
    aux.corrupted_inputs.insert(0, b"adversary chosen input".to_vec());
    aux.corrupted_messages.push(b"adversary sent message".to_vec());

    let view = sim.simulate_honest_generated_view(&env.pp, &[0], &aux);
    // The simulated view contains only honest-generated messages: shares and
    // public transcript entries. The adversary's own inputs/messages are not
    // echoed anywhere in the simulated output.
    let dump = format!("{view:?}");
    assert!(!dump.contains("adversary chosen input"));
    assert!(!dump.contains("adversary sent message"));
}

#[test]
#[should_panic(expected = "fewer than t")]
fn simulator_refuses_t_or_more_corruptions() {
    let env = common::small_election(105);
    let sim = TrustedDealerShamirSimulator {
        params: ThresholdParams { t: 2, k: 3 },
        voter_ids: vec![0],
        public_commitments: vec![],
        seed: 9,
    };
    let aux = AdversaryAuxiliaryState::default();
    let _ = sim.simulate_honest_generated_view(&env.pp, &[0, 1], &aux);
}

#[test]
fn simulated_shares_match_real_share_distribution_shape() {
    // Both real (< t) shares and simulated shares are uniform field elements;
    // this test checks the simulator produces the same TYPE of object the
    // adversary would see (share index + field value), for the right indices.
    let mut env = common::small_election(106);
    share_all_nonces(&mut env.authority, ThresholdParams { t: 3, k: 5 }, &mut env.rng).unwrap();
    let sim = TrustedDealerShamirSimulator {
        params: ThresholdParams { t: 3, k: 5 },
        voter_ids: env.reg.records.keys().copied().collect(),
        public_commitments: vec![],
        seed: 10,
    };
    let aux = AdversaryAuxiliaryState::default();
    let view = sim.simulate_honest_generated_view(&env.pp, &[1], &aux);
    let sim_shares = &view.honest_messages_to_corrupted[&1];
    for s in sim_shares {
        // Simulated share index matches the corrupted authority's index.
        assert_eq!(s.share_index, 2); // authority id 1 -> share index 2
    }
}
