//! SCLS chunk records and entries.

use crate::error::{Result, SclsError};
use crate::types::Digest;

/// Compression format for chunk data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ChunkFormat {
    /// Raw uncompressed CBOR entries
    Raw = 0x00,

    /// All entries compressed as ZSTD
    Zstd = 0x01,

    /// Each entry value compressed independently
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

    fn try_from(byte: u8) -> std::result::Result<Self, Self::Error> {
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// Fixed-size key (length determined by chunk's key_len)
    pub key: Vec<u8>,

    /// CBOR-encoded value
    pub value: Vec<u8>,
}

/// Footer at the end of each chunk containing integrity information.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkFooter {
    /// Number of entries in the chunk
    pub entries_count: u32,

    /// Blake2b-224 hash of the chunk's entries
    pub digest: Digest,
}

impl TryFrom<&[u8]> for Chunk {
    type Error = SclsError;

    /// Parses a chunk record from its payload.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The payload is too small (fewer than 49 bytes)
    /// - The chunk format is not recognised
    /// - The namespace length overruns the payload
    /// - The namespace is not valid UTF-8
    /// - The footer (32 bytes) overruns the payload
    fn try_from(value: &[u8]) -> std::result::Result<Self, Self::Error> {
        // Minimum size:
        // seqno(8) + format(1) + len_ns(4) + key_len(4) + entries_count(4) + digest(28) = 49 bytes
        if value.len() < 49 {
            return Err(SclsError::MalformedRecord(format!(
                "chunk too short: {} bytes",
                value.len()
            )));
        }

        let mut pos = 0;

        // Parse seqno
        let seqno = u64::from_be_bytes(value[pos..pos + 8].try_into().unwrap());
        pos += 8;

        // Parse format
        let format = ChunkFormat::from_byte(value[pos]).ok_or_else(|| {
            SclsError::MalformedRecord(format!("invalid chunk format: 0x{:02x}", value[pos]))
        })?;
        pos += 1;

        // Parse namespace
        let len_ns = u32::from_be_bytes(value[pos..pos + 4].try_into().unwrap()) as usize;
        pos += 4;

        if pos + len_ns > value.len() {
            return Err(SclsError::MalformedRecord(
                "namespace length exceeds data".into(),
            ));
        }

        let namespace = str::from_utf8(&value[pos..pos + len_ns])
            .map_err(|_| SclsError::MalformedRecord("invalid UTF-8 in namespace".into()))?
            .to_string();
        pos += len_ns;

        // Parse key length
        let key_len = u32::from_be_bytes(value[pos..pos + 4].try_into().unwrap());
        pos += 4;

        // Footer is at the end: entries_count(4) + digest(28) = 32 bytes
        let footer_size = 32;
        if value.len() < pos + footer_size {
            return Err(SclsError::MalformedRecord(
                "chunk too short for footer".into(),
            ));
        }

        let footer_start = value.len() - footer_size;
        let entries_data = &value[pos..footer_size];

        // Parse footer
        let entries_count =
            u32::from_be_bytes(value[footer_start..footer_start + 4].try_into().unwrap());

        let digest_bytes: [u8; 28] = value[footer_start + 4..footer_start + 32]
            .try_into()
            .unwrap();
        let digest = digest_bytes.into();

        let footer = ChunkFooter {
            entries_count,
            digest,
        };

        // Parse entries
        let entries = parse_entries(entries_data, key_len)?;

        // Verify count
        if entries.len() as u32 != entries_count {
            return Err(SclsError::MalformedRecord(format!(
                "entry count mismatch: expected {}, found {}",
                entries_count,
                entries.len()
            )));
        }

        Ok(Chunk {
            seqno,
            format,
            namespace,
            key_len,
            entries,
            footer,
        })
    }
}

/// Parse entries
fn parse_entries(data: &[u8], key_len: u32) -> Result<Vec<Entry>> {
    todo!()
}
