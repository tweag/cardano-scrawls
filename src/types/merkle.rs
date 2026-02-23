//! Incremental Merkle tree implementation, with Blake2b-224 hashing.
//!
//! Implementation note:
//! - The tree is unbalanced and rolled up by promoting shallow nodes until they can merge with
//!   their neighbours, iterating ultimately to obtain the Merkle root.
//! - Domain separators of `0x00` and `0x01`, for nodes and leaves, respectively, are used to
//!   prevent second pre-image attacks.

// Domain separators
pub const NODE_PREFIX: u8 = 0x00;
pub const LEAF_PREFIX: u8 = 0x01;
