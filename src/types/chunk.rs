//! SCLS chunk records and entries.

use crate::error::SclsError;
use crate::types::digest::Digest;

/// Compression format for chunk data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ChunkFormat {
    /// Raw uncompressed CBOR entries
    Raw = 0x00,

    /// All entries compressed as ZSTD
    Zstd = 0x01,

    // Each entry value compressed independently
    ZstdPerEntry = 0x02,
}

impl ChunkFormat {
    /// Parses a chunk format from its byte representation.
    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0x00 => Some(Self::Raw),
            0x01 => Some(Self::Zstd),
            0x02 => Some(Self::ZstdPerEntry),
            _ => None,
        }
    }

    /// Returns the byte representation of this format.
    pub fn to_byte(self) -> u8 {
        self as u8
    }
}

impl TryFrom<u8> for ChunkFormat {
    type Error = SclsError;

    fn try_from(byte: u8) -> Result<Self, Self::Error> {
        Self::from_byte(byte).ok_or(SclsError::MalformedRecord(format!(
            "invalid chunk format: 0x{:02x}",
            byte
        )))
    }
}

/// A chunk of entries with associated metadata and integrity information.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chunk {
    /// Sequential chunk number
    pub seqno: u64,

    /// Compression format
    pub format: ChunkFormat,

    /// Namespace these entries belong to
    pub namespace: String,

    /// Fixed key size for all entries in this chunk
    pub key_len: u32,

    /// The entries in this chunk
    pub entries: Vec<Entry>,

    /// Chunk footer with count and digest
    pub footer: ChunkFooter,
}

/// A single key-value entry within a chunk
pub struct Entry {
    /// Fixed-size key (length determined by chunk's key_len)
    pub key: Vec<u8>,

    /// CBOR-encoded value
    pub value: Vec<u8>,
}

/// Footer at the end of each chunk containing integrity information.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkFotter {
    /// Number of entries in the chunk
    pub entries_count: u64,

    /// Blake2b-224 hash of the chunk's entries
    pub digest: Digest,
}
