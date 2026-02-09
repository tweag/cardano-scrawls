//! SCLS file reader and record parsing.

use std::io::{Read, Seek};
use std::str;

use crate::error::{Result, SclsError};
use crate::types::{Chunk, ChunkFooter, ChunkFormat, Entry, Header, Manifest, RecordType};

/// A reader for SCLS files that can iterate over records.
pub struct SclsReader<R> {
    reader: R,
}

// NOTE Our iterator-based reader doesn't need `Seek`, but we'll need it later when it comes to
// verification. It might also be worthwhile having separate impls for Read and Read + Seek.
impl<R: Read + Seek> SclsReader<R> {
    /// Creates a new SCLS reader from the given I/O source.
    ///
    /// This does not parse the header yet; use [`records`](Self::records) to begin iteration.
    pub fn new(reader: R) -> Self {
        Self { reader }
    }

    /// Returns an iterator over records in the file.
    pub fn records(&mut self) -> RecordIter<'_, R> {
        RecordIter { reader: self }
    }
}

/// An iterator over records in an SCLS file.
pub struct RecordIter<'a, R> {
    reader: &'a mut SclsReader<R>,
}

/// A parsed record from an SCLS file.
#[derive(Debug)]
pub enum Record {
    /// File header
    Header(Header),

    /// Data chunk
    Chunk(Chunk),

    /// Manifest
    Manifest(Manifest),

    /// Unknown record (can be safely skipped)
    Unknown { record_type: u8, data: Vec<u8> },
}

impl<'a, R: Read + Seek> Iterator for RecordIter<'a, R> {
    type Item = Result<Record>;

    fn next(&mut self) -> Option<Self::Item> {
        // Read the 4-byte length prefix
        let mut len_buf = [0u8; 4];
        match self.reader.reader.read_exact(&mut len_buf) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return None,
            Err(e) => return Some(Err(e.into())),
        }

        let payload_len = u32::from_be_bytes(len_buf);

        // Read the 1-byte record type
        let mut type_buf = [0u8; 1];
        if let Err(e) = self.reader.reader.read_exact(&mut type_buf) {
            return Some(Err(e.into()));
        }
        let record_type = type_buf[0];

        // Read the remaining payload
        let data_len = payload_len.saturating_sub(1) as usize;
        let mut data = vec![0u8; data_len];
        if let Err(e) = self.reader.reader.read_exact(&mut data) {
            return Some(Err(e.into()));
        }

        // Parse based on type
        Some(parse_record(record_type, data))
    }
}

/// Parses a record from its type byte and payload data
fn parse_record(record_type: u8, data: Vec<u8>) -> Result<Record> {
    match RecordType::from_byte(record_type) {
        Some(RecordType::Header) => {
            let header = parse_header(&data)?;
            Ok(Record::Header(header))
        }

        Some(RecordType::Chunk) => {
            let chunk = parse_chunk(&data)?;
            Ok(Record::Chunk(chunk))
        }

        Some(RecordType::Manifest) => {
            let manifest = parse_manifest(&data)?;
            Ok(Record::Manifest(manifest))
        }

        // Future/unimplemented types
        Some(_) => Ok(Record::Unknown { record_type, data }),

        // Actually unknown
        None => Ok(Record::Unknown { record_type, data }),
    }
}

/// Parse a header record from its payload
fn parse_header(data: &[u8]) -> Result<Header> {
    // Header size: magic(4) + version(4) = 8 bytes
    if data.len() != 8 {
        return Err(SclsError::MalformedRecord(format!(
            "header must be exactly 8 bytes, found {}",
            data.len()
        )));
    }

    // Check magic bytes
    let magic = &data[0..4];
    if magic != Header::MAGIC {
        return Err(SclsError::InvalidMagic {
            found: magic.to_vec(),
        });
    }

    // Parse version (big-endian u32)
    // NOTE unwrap is safe because we already checked for length
    let version_bytes: [u8; 4] = data[4..8].try_into().unwrap();
    let version = u32::from_be_bytes(version_bytes);

    Ok(Header::new(version))
}

/// Parses a chunk record from its payload.
fn parse_chunk(data: &[u8]) -> Result<Chunk> {
    // Minimum size:
    // seqno(8) + format(1) + len_ns(4) + len_key(4) + entries_count(4) + digest(28) = 49 bytes
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

    if pos + len_ns > data.len() {
        return Err(SclsError::MalformedRecord(
            "namespace length exceeds data".into(),
        ));
    }

    let namespace = str::from_utf8(&data[pos..pos + len_ns])
        .map_err(|_| SclsError::MalformedRecord("invalid UTF-8 in namespace".into()))?
        .to_string();
    pos += len_ns;

    // Parse key length
    let len_key = u32::from_be_bytes(data[pos..pos + 4].try_into().unwrap());
    pos += 4;

    // Footer is at the end: entries_count(4) + digest(28) = 32 bytes
    let footer_size = 32;
    if data.len() < pos + footer_size {
        return Err(SclsError::MalformedRecord(
            "chunk too short for footer".into(),
        ));
    }

    let footer_start = data.len() - footer_size;
    let entries_data = &data[pos..footer_size];

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

    // Parse entries
    let entries = parse_entries(entries_data, len_key)?;

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
        key_len: len_key,
        entries,
        footer,
    })
}

/// Parse entries
fn parse_entries(data: &[u8], len_key: u32) -> Result<Vec<Entry>> {
    todo!()
}

/// Parse manifest
fn parse_manifest(data: &[u8]) -> Result<Manifest> {
    todo!()
}
