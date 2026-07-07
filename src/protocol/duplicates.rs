//! Duplicate handling over private per-ballot records.
//!
//! After validity evaluation (validity ALWAYS comes first — invalid ballots
//! never consume a voter's duplicate slot), each bulletin-board position j
//! yields a record
//!     r_j = (valid_j, id_j, pos_j, m_j)
//! with valid_j the soft 0/1 validity flag, id_j the canonical voter
//! identity / registration index (dummy 0 for invalid rows), pos_j = j the
//! public board position, and m_j the candidate INDEX in the public
//! candidate list (dummy 0 for invalid rows).
//!
//! Two strategies compute the counted flags for FirstValidCounts:
//!
//! * **Strategy A (naive)** — O(B^2) pairwise scan, the reference semantics.
//! * **Strategy B (sorted)** — the scalable relation: sort records by
//!   (-valid, id, pos), check the sorted list is a permutation of the input
//!   (multiset equality), then one linear pass counts the first valid
//!   record of each identity block. This is the strategy the ZK relation
//!   uses (the circuit realizes the permutation via an in-circuit sorting
//!   network; see `circuits/components/sort_records.circom`).
//!
//! Both strategies are pure functions of the records and always agree
//! (tested); records and sorted order are private — nothing here is output.

/// One private per-ballot record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BallotRecord {
    pub valid: bool,
    /// Canonical voter identity / registration index (dummy 0 if invalid).
    pub id: u64,
    /// Public bulletin-board position.
    pub pos: u64,
    /// Candidate index in the public candidate list (dummy 0 if invalid).
    pub cand_index: u64,
}

impl BallotRecord {
    /// Lexicographic sort key for (-valid, id, pos): valid records first,
    /// then increasing id, then increasing board position. (The circuit
    /// packs the same ordering into one field element as
    /// (1-valid)*2^16 + id*2^8 + pos, which is faithful there because the
    /// relation bounds id < 2^8 and pos < 2^8; natively the tuple form is
    /// used so the strategy works for any board size.)
    pub fn sort_key(&self) -> (bool, u64, u64) {
        (!self.valid, self.id, self.pos)
    }
}

/// Strategy A — naive O(B^2) first-valid-counts. counted[j] = valid_j AND no
/// earlier valid record with the same id.
pub fn counted_flags_naive(records: &[BallotRecord]) -> Vec<bool> {
    let mut counted = vec![false; records.len()];
    for j in 0..records.len() {
        if !records[j].valid {
            continue;
        }
        let dup_before = records[..j]
            .iter()
            .any(|r| r.valid && r.id == records[j].id);
        counted[j] = !dup_before;
    }
    counted
}

/// Strategy B — sorted-record first-valid-counts:
///   1. sort by (-valid, id, pos);
///   2. check multiset equality between sorted and original records (the
///      native form of the permutation proof);
///   3. counted_sorted_j = valid_sorted_j * is_first_in_identity_block_j.
/// Returns counted flags in ORIGINAL board order (mapped back via pos).
pub fn counted_flags_sorted(records: &[BallotRecord]) -> Vec<bool> {
    let mut sorted: Vec<BallotRecord> = records.to_vec();
    sorted.sort_by_key(BallotRecord::sort_key);

    // Permutation / multiset-equality check: sorting both sides by the full
    // record content must give identical lists.
    debug_assert!(multiset_equal(records, &sorted), "sorted records must be a permutation");

    let mut counted = vec![false; records.len()];
    for j in 0..sorted.len() {
        if !sorted[j].valid {
            continue; // sortedness puts all valid records first
        }
        let first_in_block = j == 0 || sorted[j - 1].id != sorted[j].id;
        // sorted[j-1] is valid whenever sorted[j] is (valid records sort
        // first), so a same-id predecessor is exactly an earlier valid
        // ballot of the same voter (earlier because pos ascends in-block).
        if first_in_block {
            counted[sorted[j].pos as usize] = true;
        }
    }
    counted
}

/// Multiset equality of two record lists (the native permutation check).
pub fn multiset_equal(a: &[BallotRecord], b: &[BallotRecord]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let canon = |rs: &[BallotRecord]| {
        let mut v: Vec<(bool, u64, u64, u64)> =
            rs.iter().map(|r| (r.valid, r.id, r.pos, r.cand_index)).collect();
        v.sort_unstable();
        v
    };
    canon(a) == canon(b)
}

/// Per-candidate tally T_c = sum_j counted_j * [m_j == c] over `num_cands`
/// candidate indices.
pub fn tally_from_counted(
    records: &[BallotRecord],
    counted: &[bool],
    num_cands: usize,
) -> Vec<u64> {
    let mut counts = vec![0u64; num_cands];
    for (r, c) in records.iter().zip(counted) {
        if *c {
            counts[r.cand_index as usize] += 1;
        }
    }
    counts
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(valid: bool, id: u64, pos: u64, cand: u64) -> BallotRecord {
        BallotRecord { valid, id, pos, cand_index: cand }
    }

    #[test]
    fn strategies_agree_and_first_valid_wins() {
        // fake(id0) before real(id0); dup for id1; invalid rows never block.
        let records = vec![
            rec(false, 0, 0, 2), // fake-compliance: invalid, must not consume slot
            rec(true, 0, 1, 0),  // real vote of voter 0: counts
            rec(true, 1, 2, 1),  // voter 1 first valid: counts
            rec(true, 1, 3, 2),  // voter 1 duplicate: not counted
            rec(false, 0, 4, 0), // chaff
        ];
        let a = counted_flags_naive(&records);
        let b = counted_flags_sorted(&records);
        assert_eq!(a, b);
        assert_eq!(a, vec![false, true, true, false, false]);
        assert_eq!(tally_from_counted(&records, &a, 3), vec![1, 1, 0]);
    }

    #[test]
    fn strategies_agree_on_random_inputs() {
        use rand::{Rng, SeedableRng};
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(17);
        for _ in 0..200 {
            let n = rng.gen_range(0..40);
            let records: Vec<BallotRecord> = (0..n)
                .map(|pos| BallotRecord {
                    valid: rng.gen_bool(0.6),
                    id: rng.gen_range(0..6),
                    pos: pos as u64,
                    cand_index: rng.gen_range(0..3),
                })
                .collect();
            assert_eq!(counted_flags_naive(&records), counted_flags_sorted(&records));
        }
    }
}
