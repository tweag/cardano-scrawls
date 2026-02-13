//! SCLS chunk records and entries.

use std::io::{Read, Seek, SeekFrom};
use std::ops::Range;
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

/// A handle to a chunk in the SCLS file.
///
/// Entry data is loaded lazily when calling ['entries'](ChunkHandle::entries).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkHandle {
    /// Sequential chunk number
    pub seqno: u64,

    /// Compression format
    pub format: ChunkFormat,

    /// Namespace these entries belong to
    pub namespace: String,

    /// Fixed key size for all entries in this chunk
    pub key_len: u32,

    /// Chunk footer with count and digest
    pub footer: ChunkFooter,

    /// Byte range where entry data is located
    entries_range: Range<u64>,
}

impl ChunkHandle {
    /// Returns an iterator that streams entries from the file on-demand.
    ///
    /// Each entry is read from disk as the iterator advances.
    /// This requires mutable access to the reader.
    ///
    /// # Errors
    ///
    /// Returns an error if seeking to the entry data fails.
    pub fn entries<'a, R: Read + Seek>(
        &self,
        reader: &'a mut R,
    ) -> Result<StreamingEntryIter<'a, R>> {
        reader.seek(SeekFrom::Start(self.entries_range.start))?;
        Ok(StreamingEntryIter {
            reader,
            key_len: self.key_len,
            remaining_bytes: self.entries_range.end - self.entries_range.start,
        })
    }

    /// Parses a chunk record, calculating file offsets for lazy entry loading.
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
    pub fn parse(data: &[u8], record_start_offset: u64) -> Result<Self> {
        // Minimum size:
        // seqno(8) + format(1) + len_ns(4) + key_len(4) + entries_count(4) + digest(28) = 49 bytes
        if data.len() < 49 {
            return Err(SclsError::MalformedRecord(format!(
                "chunk too short: {} bytes",
                data.len()
            )));
        }

        let mut pos = 0;

        // Parse seqno
        let seqno = u64::from_be_bytes(data[pos..pos + 8].try_into().unwrap());
        pos += 8;

        // Parse format
        let format = ChunkFormat::from_byte(data[pos]).ok_or_else(|| {
            SclsError::MalformedRecord(format!("invalid chunk format: 0x{:02x}", data[pos]))
        })?;
        pos += 1;

        // Parse namespace
        let len_ns = u32::from_be_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
        pos += 4;

        let total_len = pos
            .checked_add(len_ns)
            .ok_or_else(|| SclsError::MalformedRecord("namespace length overflow".into()))?;

        if total_len > data.len() {
            return Err(SclsError::MalformedRecord(
                "namespace length extends beyond data".into(),
            ));
        }

        let namespace = str::from_utf8(&data[pos..pos + len_ns])
            .map_err(|_| SclsError::MalformedRecord("invalid UTF-8 in namespace".into()))?
            .to_string();
        pos += len_ns;

        // Parse key length
        let key_len = u32::from_be_bytes(data[pos..pos + 4].try_into().unwrap());
        pos += 4;

        // Footer is at the end: entries_count(4) + digest(28) = 32 bytes
        let footer_size = 32;
        let needed_len = pos
            .checked_add(footer_size)
            .ok_or_else(|| SclsError::MalformedRecord("footer length overflow".into()))?;

        if data.len() < needed_len {
            return Err(SclsError::MalformedRecord(
                "chunk too short for footer".into(),
            ));
        }

        let footer_start = data.len() - footer_size;
        let entries_len = footer_start - pos;

        // Parse footer
        let entries_count =
            u32::from_be_bytes(data[footer_start..footer_start + 4].try_into().unwrap());

        let digest_bytes: [u8; 28] = data[footer_start + 4..footer_start + 32]
            .try_into()
            .unwrap();
        let digest = digest_bytes.into();

        let footer = ChunkFooter {
            entries_count,
            digest,
        };

        // Calculate absolute file offset for entry data
        // record_start_offset + len_prefix(4) + record_type(1) + header_size
        let entries_offset = record_start_offset
            .checked_add(4) // len_prefix
            .and_then(|offset| offset.checked_add(1)) // record_type
            .and_then(|offset| offset.checked_add(pos as u64)) // chunk header
            .ok_or_else(|| SclsError::MalformedRecord("offset overflow".into()))?;

        let entries_end = entries_offset
            .checked_add(entries_len as u64)
            .ok_or_else(|| SclsError::MalformedRecord("offset overflow".into()))?;

        Ok(ChunkHandle {
            seqno,
            format,
            namespace,
            key_len,
            footer,
            entries_range: entries_offset..entries_end,
        })
    }
}

/// Iterator that streams entries from a file on-demand.
pub struct StreamingEntryIter<'a, R> {
    reader: &'a mut R,
    key_len: u32,
    remaining_bytes: u64,
}

impl<R: Read> Iterator for StreamingEntryIter<'_, R> {
    type Item = Result<Entry>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining_bytes == 0 {
            return None;
        }

        // Read 4 byte length prefix
        let mut len_buf = [0u8; 4];
        if let Err(e) = self.reader.read_exact(&mut len_buf) {
            return Some(Err(e.into()));
        }
        let len_body = u32::from_be_bytes(len_buf) as usize;

        // Check we're not reading beyond our range
        let total_read = match 4u64.checked_add(len_body as u64) {
            None => {
                return Some(Err(SclsError::MalformedRecord(
                    "entry body length overflow".into(),
                )))
            }

            Some(total_read) if total_read > self.remaining_bytes => {
                return Some(Err(SclsError::MalformedRecord(
                    "entry extends beyond chunk data".into(),
                )))
            }

            Some(total_read) => total_read,
        };

        let key_len_usize = self.key_len as usize;

        // Body must be at least as large as the key
        if len_body < key_len_usize {
            return Some(Err(SclsError::MalformedRecord(format!(
                "entry body too short for key: body {} bytes, key {} bytes",
                len_body, self.key_len
            ))));
        }

        // Read the entry body (key + value)
        let mut body = vec![0u8; len_body];
        if let Err(e) = self.reader.read_exact(&mut body) {
            return Some(Err(e.into()));
        }

        self.remaining_bytes -= total_read;

        // Split into key and value
        let key = body[..key_len_usize].to_vec();
        let value = body[key_len_usize..].to_vec();

        Some(Ok(Entry { key, value }))
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
