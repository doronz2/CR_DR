//! Fixed-depth Poseidon Merkle tree over registration leaves.
//! Empty slots are padded with 0. Matches
//! `circuits/components/merkle_membership.circom` exactly.

use ark_ff::Zero;
use serde::{Deserialize, Serialize};

use crate::crypto::hash::merkle_hash;
use crate::errors::{CrDrError, Result};
use crate::types::{fserde_vec, F};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerklePath {
    /// Sibling hashes, leaf level first.
    #[serde(with = "fserde_vec")]
    pub elements: Vec<F>,
    /// Direction bits, leaf level first. false = current node is the left
    /// child, true = current node is the right child.
    pub indices: Vec<bool>,
}

#[derive(Debug, Clone)]
pub struct MerkleTree {
    pub depth: usize,
    /// levels[0] = padded leaves, levels[depth] = [root]
    levels: Vec<Vec<F>>,
}

impl MerkleTree {
    pub fn new(leaves: &[F], depth: usize) -> Result<Self> {
        let cap = 1usize << depth;
        if leaves.len() > cap {
            return Err(CrDrError::Merkle(format!(
                "{} leaves exceed capacity 2^{depth}",
                leaves.len()
            )));
        }
        let mut level0 = leaves.to_vec();
        level0.resize(cap, F::zero());
        let mut levels = vec![level0];
        for d in 0..depth {
            let prev = &levels[d];
            let next: Vec<F> = prev
                .chunks(2)
                .map(|pair| merkle_hash(pair[0], pair[1]))
                .collect();
            levels.push(next);
        }
        Ok(MerkleTree { depth, levels })
    }

    pub fn root(&self) -> F {
        self.levels[self.depth][0]
    }

    pub fn path(&self, index: usize) -> Result<MerklePath> {
        if index >= self.levels[0].len() {
            return Err(CrDrError::Merkle(format!("leaf index {index} out of range")));
        }
        let mut elements = Vec::with_capacity(self.depth);
        let mut indices = Vec::with_capacity(self.depth);
        let mut idx = index;
        for d in 0..self.depth {
            let sibling = idx ^ 1;
            elements.push(self.levels[d][sibling]);
            indices.push(idx & 1 == 1);
            idx >>= 1;
        }
        Ok(MerklePath { elements, indices })
    }
}

/// Recompute the root from a leaf and a path; true iff it matches `root`.
pub fn verify_path(root: F, leaf: F, path: &MerklePath) -> bool {
    if path.elements.len() != path.indices.len() {
        return false;
    }
    let mut cur = leaf;
    for (sib, is_right) in path.elements.iter().zip(&path.indices) {
        cur = if *is_right { merkle_hash(*sib, cur) } else { merkle_hash(cur, *sib) };
    }
    cur == root
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn membership_roundtrip() {
        let leaves: Vec<F> = (1..=5u64).map(F::from).collect();
        let tree = MerkleTree::new(&leaves, 4).unwrap();
        for (i, leaf) in leaves.iter().enumerate() {
            let path = tree.path(i).unwrap();
            assert!(verify_path(tree.root(), *leaf, &path));
        }
        // wrong leaf fails
        let path = tree.path(0).unwrap();
        assert!(!verify_path(tree.root(), F::from(99u64), &path));
        // wrong index fails
        let path1 = tree.path(1).unwrap();
        assert!(!verify_path(tree.root(), leaves[0], &path1));
    }

    #[test]
    fn overflow_rejected() {
        let leaves: Vec<F> = (0..17u64).map(F::from).collect();
        assert!(MerkleTree::new(&leaves, 4).is_err());
    }
}
