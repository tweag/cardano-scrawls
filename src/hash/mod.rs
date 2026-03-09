//! Module for all hashing needs:
//! - Blake2b-224 digest container type;
//! - Blake2b-224 hash constructor;
//! - Incremental Merkle tree with Blake2b-224 hashing.

mod merkle;

use std::fmt::Display;
use std::ops::{Index, IndexMut};

pub use merkle::MerkleTree;

use blake2b_simd::{Params, State};

/// Hash length, in bytes.
pub const HASH_SIZE: usize = 28;

/// A HASH_SIZE byte Blake2b digest.
///
/// Used for entry digests, chunk hashes and Merkle tree roots in SCLS files.
///
/// Note: This is just a container type, containing the raw hash bytes. See [`Blake2b`] for an
/// interface for hash construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Digest([u8; HASH_SIZE]);

impl Digest {
    /// Creates a new digest from a HASH_SIZE byte array.
    pub const fn new(bytes: [u8; HASH_SIZE]) -> Self {
        Self(bytes)
    }

    /// Returns the digest as a byte slice.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Display for Digest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for byte in &self.0 {
            write!(f, "{:02x}", byte)?;
        }

        Ok(())
    }
}

impl From<[u8; HASH_SIZE]> for Digest {
    fn from(value: [u8; HASH_SIZE]) -> Self {
        Self(value)
    }
}

impl Index<usize> for Digest {
    type Output = u8;

    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index]
    }
}

impl IndexMut<usize> for Digest {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.0[index]
    }
}

/// A Blake2b hasher.
///
/// Build Blake2b hashes incrementally, with convenience functions for constructing Merkle tree
/// leaf and non-leaf nodes (see [`MerkleTree`]).
#[derive(Debug)]
pub struct Blake2b(State);

impl Blake2b {
    /// Create a new Blake2b hasher with empty state.
    pub fn new_raw() -> Self {
        let state = Params::new().hash_length(HASH_SIZE).to_state();
        Self(state)
    }

    /// Create a new Blake2b hasher, initialised with Merkle leaf node state.
    pub fn new_leaf() -> Self {
        let Self(mut state) = Self::new_raw();
        state.update(&[merkle::LEAF_PREFIX]);

        Self(state)
    }

    /// Create a new Blake2b hasher, initialised with Merkle non-leaf node state.
    pub fn new_node() -> Self {
        let Self(mut state) = Self::new_raw();
        state.update(&[merkle::NODE_PREFIX]);

        Self(state)
    }

    /// Update the hasher with data.
    pub fn update(&mut self, data: &[u8]) -> &mut Self {
        self.0.update(data);
        self
    }

    /// Finalise the hasher and return the digest.
    pub fn as_digest(&self) -> Digest {
        let hash = self.0.finalize();
        let bytes: [u8; HASH_SIZE] = hash.as_bytes().try_into().unwrap();

        Digest::new(bytes)
    }
}
