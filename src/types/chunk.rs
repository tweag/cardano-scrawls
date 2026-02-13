//! SCLS chunk records and entries.

use std::str;

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

/// A chunk of entries with associated metadata and integrity information.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chunk<'a> {
    /// Sequential chunk number
    pub seqno: u64,

    /// Compression format
    pub format: ChunkFormat,

    /// Namespace these entries belong to
    pub namespace: String,

    /// Fixed key size for all entries in this chunk
    pub key_len: u32,

    /// Raw entry data (parsed on-demand via iterator)
    entries_data: &'a [u8],

    /// Chunk footer with count and digest
    pub footer: ChunkFooter,
}

impl<'a> Chunk<'a> {
    /// Returns an iterator over entries in this chunk
    pub fn entries(&self) -> EntryIter<'a> {
        EntryIter {
            data: self.entries_data,
            key_len: self.key_len,
            pos: 0,
        }
    }
}

/// Iterator over entries in a chunk
pub struct EntryIter<'a> {
    data: &'a [u8],
    key_len: u32,
    pos: usize,
}

impl<'a> Iterator for EntryIter<'a> {
    type Item = Result<Entry>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos >= self.data.len() {
            return None;
        }

        // Parse next entry (i.e., consume one from the current position)
        Some(self.parse_next_entry())
    }
}

impl<'a> EntryIter<'a> {
    /// Parse the next entry from a chunk's data blob.
    ///
    /// Each entry consists of a 4-byte length prefix, a fixed-size key and a variable-size value.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Byte offsets overflow
    /// - An entry's length prefix extends beyond the payload
    /// - An entry's body is shorter than the key length
    fn parse_next_entry(&mut self) -> Result<Entry> {
        // Need at least 4 bytes for length prefix
        let needed_len = self
            .pos
            .checked_add(4)
            .ok_or_else(|| SclsError::MalformedRecord("entry length overflow".into()))?;

        if needed_len > self.data.len() {
            return Err(SclsError::MalformedRecord(
                "incomplete entry length prefix".into(),
            ));
        }

        // Parse entry length
        let len_body =
            u32::from_be_bytes(self.data[self.pos..self.post + 4].try_into().unwrap()) as usize;
        self.pos += 4;

        // Check we have enough data for the body
        let needed_len = pos
            .checked_add(len_body)
            .ok_or_else(|| SclsError::MalformedRecord("entry body length overflow".into()))?;

        if needed_len > self.data.len() {
            return Err(SclsError::MalformedRecord(format!(
                "entry body extends beyond data: need {} bytes, have {} bytes",
                len_body,
                self.data.len() - self.pos
            )));
        }

        let key_len_usize = self.key_len as usize;

        // Body must be at least as large as the key
        if len_body < key_len_usize {
            return Err(SclsError::MalformedRecord(format!(
                "entry body too short for key: body {} bytes, key {} bytes",
                len_body, self.key_len
            )));
        }

        // Extract key and value
        let key = self.data[self.pos..self.pos + key_len_usize].to_vec();
        let value = self.data[self.pos + key_len_usize..self.pos + len_body].to_vec();

        self.pos += len_body;

        Ok(Entry { key, value })
    }
}

impl<'a> TryFrom<&'a [u8]> for Chunk<'a> {
    type Error = SclsError;

    /// Parses a chunk record from its payload.
    ///
    /// Entries are not parsed eagerly; use [`Chunk::entries`] to iterate over them.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The payload is too small (fewer than 49 bytes)
    /// - Byte offsets overflow
    /// - The chunk format is not recognised
    /// - The namespace length overruns the payload
    /// - The namespace is not valid UTF-8
    /// - The footer (32 bytes) overruns the payload
    fn try_from(value: &'a [u8]) -> std::result::Result<Self, Self::Error> {
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

        let total_len = pos
            .checked_add(len_ns)
            .ok_or_else(|| SclsError::MalformedRecord("namespace length overflow".into()))?;

        if total_len > value.len() {
            return Err(SclsError::MalformedRecord(
                "namespace length extends beyond data".into(),
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
        let needed_len = pos
            .checked_add(footer_size)
            .ok_or_else(|| SclsError::MalformedRecord("footer length overflow".into()))?;

        if value.len() < needed_len {
            return Err(SclsError::MalformedRecord(
                "chunk too short for footer".into(),
            ));
        }

        let footer_start = value.len() - footer_size;
        let entries_data = &value[pos..footer_start];

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

        Ok(Chunk {
            seqno,
            format,
            namespace,
            key_len,
            entries_data,
            footer,
        })
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    // Strategy to generate a single serialised entry
    fn entry_bytes(key_len: u32) -> impl Strategy<Value = Vec<u8>> {
        let key_len = key_len as usize;

        (
            prop::collection::vec(any::<u8>(), key_len..=key_len), // Key
            prop::collection::vec(any::<u8>(), 0..100),            // Value
        )
            .prop_map(move |(key, value)| {
                let body_len = (key.len() + value.len()) as u32;
                let mut bytes = body_len.to_be_bytes().to_vec();

                bytes.extend_from_slice(&key);
                bytes.extend_from_slice(&value);

                bytes
            })
    }

    // Strategy to generate multiple entries
    fn entries_data(key_len: u32, num_entries: usize) -> impl Strategy<Value = Vec<u8>> {
        prop::collection::vec(entry_bytes(key_len), num_entries..=num_entries)
            .prop_map(|entries| entries.concat())
    }

    proptest! {
        #[test]
        fn parse_entries_count_matches(
            params in (1u32..=64, 0usize..=10)
                .prop_flat_map(|(key_len, num_entries)| {
                    entries_data(key_len, num_entries)
                        .prop_map(move |data| (key_len, num_entries, data))
                })
        ) {
            let (key_len, num_entries, data) = params;
            let result = parse_entries(&data, key_len)?;

            prop_assert_eq!(result.len(), num_entries);
        }

        #[test]
        fn parse_entries_keys_correct_length(
            params in (1u32..=64, 1usize..=10)
                .prop_flat_map(|(key_len, num_entries)| {
                    entries_data(key_len, num_entries)
                        .prop_map(move |data| (key_len, data))
                })
        ) {
            let (key_len, data) = params;
            let entries = parse_entries(&data, key_len)?;

            for entry in entries {
                prop_assert_eq!(entry.key.len(), key_len as usize);
            }
        }

        #[test]
        fn parse_entries_rejects_truncated_length(
            key_len in 1u32..=64,
        ) {
            // Only 2 bytes instead of 4 for length prefix
            let data = vec![0x00, 0x01];
            let result = parse_entries(&data, key_len);
            prop_assert!(result.is_err());
        }

        #[test]
        fn parse_entries_rejects_body_too_short_for_key(
            key_len in 4u32..=64,
        ) {
            // Claim body is 2 bytes, but key_len is larger
            let mut data = 2u32.to_be_bytes().to_vec();
            data.extend_from_slice(&[0xff, 0xff]);

            let result = parse_entries(&data, key_len);
            prop_assert!(result.is_err());
        }
    }
}
