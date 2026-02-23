pub mod chunk;
pub mod digest;
pub mod header;
pub mod manifest;
pub mod merkle;

use crate::error::SclsError;
pub use chunk::{Chunk, ChunkFooter, ChunkFormat, Entry};
pub use digest::Digest;
pub use header::Header;
pub use manifest::{Manifest, NamespaceInfo, Summary};

/// Record type identifiers for SCLS records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RecordType {
    /// File header
    Header = 0x00,

    /// Manifest with global commitments
    Manifest = 0x01,

    /// Chunk of ordered entries
    Chunk = 0x10,

    /// Delta updates (reserved for future use)
    Delta = 0x11,

    /// Bloom filter (reserved for future use)
    Bloom = 0x20,

    /// Index data (reserved for future use)
    Index = 0x21,

    /// Directory footer (reserved for future use)
    Directory = 0x30,

    /// Metadata entries
    Metadata = 0x31,
}

impl RecordType {
    /// Parses a record type from its byte representation.
    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0x00 => Some(Self::Header),
            0x01 => Some(Self::Manifest),
            0x10 => Some(Self::Chunk),
            0x11 => Some(Self::Delta),
            0x20 => Some(Self::Bloom),
            0x21 => Some(Self::Index),
            0x30 => Some(Self::Directory),
            0x31 => Some(Self::Metadata),
            _ => None,
        }
    }

    /// Returns the byte representation of this record type.
    pub fn to_byte(self) -> u8 {
        self as u8
    }
}

impl TryFrom<u8> for RecordType {
    type Error = SclsError;

    fn try_from(byte: u8) -> Result<Self, Self::Error> {
        Self::from_byte(byte).ok_or(SclsError::UnknownRecordType(byte))
    }
}
