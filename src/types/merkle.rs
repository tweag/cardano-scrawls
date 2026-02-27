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
    use super::*;

    use hex::FromHex;
    use proptest::prelude::*;

    /// Golden inputs and outputs
    ///
    /// These were generated with the `merkle-tree-incremental` Haskell library, per
    /// https://github.com/tweag/cardano-cls at commit 98d912a, using the following method:
    ///
    /// ```haskell
    /// import Crypto.Hash.Algorithms (Blake2b_224 (..))
    /// import Crypto.Hash.MerkleTree.Incremental (add, empty, finalize, merkleRootHash)
    /// import Data.ByteString (ByteString)
    /// import qualified Data.ByteString.Char8 as BC
    ///
    /// leaf :: ByteString
    /// leaf = BC.pack "Test"
    ///
    /// merkleRoot :: Int -> String
    /// merkleRoot n =
    ///   show $ merkleRootHash $ finalize $ foldl add (empty Blake2b_224) (replicate n leaf)
    ///
    /// main :: IO ()
    /// main = mapM_ printRow [2, 3, 4, 5, 7]
    ///   where
    ///     printRow n = putStrLn $ show n ++ " " ++ merkleRoot n
    /// ```
    #[rustfmt::skip]
    const GOLDEN: [(usize, &str); 5] = [
        (2, "d3af86eb3e383618180e9e5e67b458f351335462871682ee332e20f8"),
        (3, "37c91e733d32604abaf8ddff2b274f60e9b66a0311860ceddb5d43f4"),
        (4, "e291561d5aa6555c44991f28f70dccb86352a4cd505b894a7bf85c4c"),
        (5, "4aa703d6add1a49f1603328aa89db822122f174282c1637606c59f7c"),
        (7, "ff159b2b1d0c703bf65bb0ae36dac26420cab122cc09df37c28df3a5"),
    ];

    #[test]
    fn empty_merkle_tree() {
        let merkle = MerkleTree::new();
        assert_eq!(merkle.root(), *EMPTY);
    }

    #[test]
    fn golden() {
        let leaf = {
            let hash = Params::new()
                .hash_length(HASH_SIZE)
                .to_state()
                .update(&[LEAF_PREFIX])
                .update(b"Test")
                .finalize();

            let bytes: [u8; HASH_SIZE] = hash.as_bytes().try_into().unwrap();
            Digest::new(bytes)
        };

        for (leaves, golden_bytestring) in GOLDEN.iter() {
            let computed_root = {
                let mut merkle = MerkleTree::new();
                for _ in 0..*leaves {
                    merkle.add_leaf(leaf);
                }
                merkle.root()
            };

            let golden_root = {
                let golden_bytes = <[u8; HASH_SIZE]>::from_hex(golden_bytestring).unwrap();
                Digest::new(golden_bytes)
            };

            assert_eq!(computed_root, golden_root);
        }
    }

    // Strategy for generating a range of leaves
    prop_compose! {
        fn range_of_leaves(min: usize, max: usize)
            (leaf_bytes in prop::collection::vec(any::<[u8; HASH_SIZE]>(), min..=max))
        -> Vec<Digest> {
            leaf_bytes.into_iter().map(Digest::new).collect()
        }
    }

    // Strategy for generating n leaves
    fn n_leaves(count: usize) -> impl Strategy<Value = Vec<Digest>> {
        range_of_leaves(count, count)
    }

    proptest! {
        #[test]
        fn single_leaf_is_root(leaves in n_leaves(1)) {
            let mut merkle = MerkleTree::new();

            let leaf = leaves[0];
            merkle.add_leaf(leaf);

            prop_assert_eq!(merkle.root(), leaf);
        }

        #[test]
        fn deterministic_root(leaves in range_of_leaves(1, 16)) {
            let mut merkle_1 = MerkleTree::new();
            let mut merkle_2 = MerkleTree::new();

            for leaf in leaves {
                merkle_1.add_leaf(leaf);
                merkle_2.add_leaf(leaf);
            }

            prop_assert_eq!(merkle_1.root(), merkle_2.root());
        }

        #[test]
        fn non_commutativity(leaves in n_leaves(2)) {
            prop_assume!(leaves[0] != leaves[1]);

            let mut merkle_1 = MerkleTree::new();
            merkle_1.add_leaf(leaves[0]);
            merkle_1.add_leaf(leaves[1]);

            let mut merkle_2 = MerkleTree::new();
            merkle_2.add_leaf(leaves[1]);
            merkle_2.add_leaf(leaves[0]);

            prop_assert_ne!(merkle_1.root(), merkle_2.root());
        }

        #[test]
        fn adding_leaf_changes_root(leaves in n_leaves(2)) {
            let before = {
                let mut merkle = MerkleTree::new();
                merkle.add_leaf(leaves[0]);
                merkle.root()
            };

            let after = {
                let mut merkle = MerkleTree::new();
                merkle.add_leaf(leaves[0]);
                merkle.add_leaf(leaves[1]);
                merkle.root()
            };

            prop_assert_ne!(before, after);
        }
    }
}
