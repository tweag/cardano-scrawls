//! Blake2b-224 digest type.

use std::fmt::Display;

/// Hash length, in bytes.
pub const HASH_SIZE: usize = 28;

/// A HASH_SIZE byte Blake2b digest.
///
/// Used for entry digests, chunk hashes and Merkle tree roots in SCLS files.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Digest([u8; HASH_SIZE]);

impl Digest {
    /// Size of the digest in bytes.
    pub const SIZE: usize = HASH_SIZE;

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

impl AsRef<[u8]> for Digest {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
