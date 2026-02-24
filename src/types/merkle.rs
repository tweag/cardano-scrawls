//! Incremental Merkle tree implementation, with Blake2b-224 hashing.
//!
//! Implementation notes:
//! - The tree is unbalanced and rolled up by promoting shallow nodes until they can merge with
//!   their neighbours, iterating ultimately to obtain the Merkle root.
//! - Domain separators of `0x00` and `0x01`, for nodes and leaves, respectively, are used to
//!   prevent second pre-image attacks.

use std::sync::LazyLock;

use crate::types::Digest;
use crate::types::digest::HASH_SIZE;

use blake2b_simd::Params;

/// Domain separators
pub const NODE_PREFIX: u8 = 0x00;
pub const LEAF_PREFIX: u8 = 0x01;

/// Empty hash for empty Merkle trees.
static EMPTY: LazyLock<Digest> = LazyLock::new(|| {
    let hash = Params::new().hash_length(HASH_SIZE).to_state().finalize();
    let bytes: [u8; HASH_SIZE] = hash.as_bytes().try_into().unwrap();
    Digest::new(bytes)
});

/// An incremental Merkle tree.
#[derive(Debug, PartialEq, Eq, Hash)]
pub struct MerkleTree {
    // A vector of (Digest, tree depth) tuples, where leaf nodes have a depth of 0
    // We don't expect trees to be deeper than 256 levels, so a u8 will suffice
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
    pub fn add_leaf(&mut self, digest: Digest) {
        self.add_node(digest, 0);
    }

    /// Roll up the Merkle tree nodes to generate the current Merkle root.
    pub fn root(self) -> Digest {
        Self::collapse(self.data)
    }

    /// Merge two digests to generate the node digest of `H(NODE_PREFIX || left || right)`.
    fn merge(left: &Digest, right: &Digest) -> Digest {
        let merged = Params::new()
            .hash_length(HASH_SIZE)
            .to_state()
            .update(&[NODE_PREFIX])
            .update(left.as_bytes())
            .update(right.as_bytes())
            .finalize();

        let merged_bytes: [u8; HASH_SIZE] = merged.as_bytes().try_into().unwrap();
        Digest::new(merged_bytes)
    }

    /// Add a node, at a specified depth, to the Merkle tree.
    fn add_node(&mut self, digest: Digest, depth: u8) {
        if let [.., (last_digest, last_depth)] = self.data.as_mut_slice()
            && *last_depth == depth
        {
            let new_digest = Self::merge(last_digest, &digest);
            let new_depth = depth + 1;

            self.data.pop();
            self.add_node(new_digest, new_depth);
        } else {
            let new_leaf = (digest, depth);
            self.data.push(new_leaf);
        }
    }

    /// Collapse the Merkle tree state to its root hash.
    ///
    /// The Merkle tree is unbalanced. When there are trailing leaves, their depth is promoted
    /// (without changing their digest) until they can be merged with their neighbour. This is done
    /// recursively until only the root remains.
    fn collapse(mut data: Vec<(Digest, u8)>) -> Digest {
        match data.as_mut_slice() {
            // If we have an empty tree, then return the empty hash
            [] => *EMPTY,

            // When there's only one node, that's the Merkle root and we don't need to do anything
            [(root, _)] => *root,

            // When trailing leaf depths match, merge the leaves and recur
            [.., (digest_m, depth_m), (digest_n, depth_n)] if *depth_m == *depth_n => {
                let new_digest = Self::merge(digest_m, digest_n);
                let new_depth = *depth_m + 1;
                let new_leaf = (new_digest, new_depth);

                data.truncate(data.len() - 2);
                data.push(new_leaf);

                Self::collapse(data)
            }

            // When trailing leaf depths don't match, promote the trailing leaf and recur
            [.., (_, depth_m), (_, depth_n)] if *depth_m > *depth_n => {
                // Promote the final leaf to the same depth as the one it follows
                *depth_n = *depth_m;

                Self::collapse(data)
            }

            // The case where depth_m < depth_n can never happen: leaves are appended at level 0
            // and only ever incremented or promoted to the same level. As such, depths should be
            // monotonically decreasing across the data vector.
            _ => unreachable!(),
        }
    }
}

impl Default for MerkleTree {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    // TODO
}
