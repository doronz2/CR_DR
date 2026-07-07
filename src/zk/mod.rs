pub mod chunked;
pub mod circom_io;
pub mod groth16_backend;
pub mod mock_backend;
pub mod statement;
pub mod witness;

/// Compile-time shape of a circuit instantiation. Must match the parameters
/// of the compiled `FilterAndTally(NUM_BALLOTS, NUM_CANDIDATES, MERKLE_DEPTH)`
/// main component.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CircuitShape {
    pub num_ballots: usize,
    pub num_candidates: usize,
    pub merkle_depth: usize,
}

/// Shape of the checked-in "small" circuit variant.
pub const SMALL_SHAPE: CircuitShape =
    CircuitShape { num_ballots: 16, num_candidates: 3, merkle_depth: 4 };

/// Shape of the "medium" circuit variant.
pub const MEDIUM_SHAPE: CircuitShape =
    CircuitShape { num_ballots: 128, num_candidates: 3, merkle_depth: 6 };
