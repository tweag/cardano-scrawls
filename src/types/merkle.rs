//! Incremental Merkle tree implementation, with Blake2b-224 hashing.
//!
//! Implementation notes:
//! - The tree is unbalanced and rolled up by promoting shallow nodes until they can merge with
//!   their neighbours, iterating ultimately to obtain the Merkle root.
//! - Domain separators of `0x00` and `0x01`, for nodes and leaves, respectively, are used to
//!   prevent second pre-image attacks.

use crate::types::Digest;
use crate::types::digest::HASH_SIZE;

use blake2b_simd::Params;

/// Domain separators
pub const NODE_PREFIX: u8 = 0x00;
pub const LEAF_PREFIX: u8 = 0x01;

/// An incremental Merkle tree.
#[derive(Debug, PartialEq, Eq, Hash)]
pub struct MerkleTree {
    // A vector of (Digest, tree depth) tuples, where leaf nodes have a depth of 0
    data: Vec<(Digest, u8)>,
}

impl MerkleTree {
    /// Create an empty Merkle tree, ready for incremental construction.
    pub fn new() -> Self {
        Self { data: Vec::new() }
    }

    /// Add a leaf node to the Merkle tree.
    ///
    /// Note: The leaf digest is assumed to have already been prepended with the leaf domain
    /// separator; that is, `digest = H(LEAF_PREFIX || payload)`.
    pub fn update(&mut self, digest: Digest) {
        todo!()
    }

    /// Roll up the Merkle tree nodes to generate the Merkle root.
    pub fn finalise(self) -> Digest {
        todo!()
    }
}

impl Default for MerkleTree {
    fn default() -> Self {
        Self::new()
    }
}
