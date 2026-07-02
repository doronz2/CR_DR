//! Native Poseidon over BN254, parameter-compatible with circomlib's
//! `Poseidon` template (same round constants / MDS as circomlibjs), via the
//! `light-poseidon` crate.
//!
//! Compatibility is asserted by unit tests against known circomlib vectors,
//! and by the Groth16 integration tests (the circuit recomputes every hash
//! the native code produces).

use light_poseidon::{Poseidon, PoseidonHasher};

use crate::types::F;

/// Poseidon hash of 1..=12 field elements, circomlib-compatible.
pub fn poseidon(inputs: &[F]) -> F {
    assert!(
        !inputs.is_empty() && inputs.len() <= 12,
        "poseidon supports 1..=12 inputs, got {}",
        inputs.len()
    );
    let mut hasher =
        Poseidon::<F>::new_circom(inputs.len()).expect("poseidon params for this arity");
    hasher.hash(inputs).expect("poseidon hash")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::f_from_dec;

    #[test]
    fn matches_circomlib_vector_two_inputs() {
        // circomlibjs: poseidon([1, 2])
        let expected = f_from_dec(
            "7853200120776062878684798364095072458815029376092732009249414926327459813530",
        )
        .unwrap();
        assert_eq!(poseidon(&[F::from(1u64), F::from(2u64)]), expected);
    }

    #[test]
    fn matches_circomlib_vector_four_inputs() {
        // circomlibjs: poseidon([1, 2, 3, 4])
        let expected = f_from_dec(
            "18821383157269793795438455681495246036402687001665670618754263018637548127333",
        )
        .unwrap();
        assert_eq!(
            poseidon(&[F::from(1u64), F::from(2u64), F::from(3u64), F::from(4u64)]),
            expected
        );
    }
}
