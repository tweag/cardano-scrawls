//! SCLS file reader and record parsing.

use std::io::{Read, Seek};

use crate::error::{Result, SclsError};
use crate::types::{Chunk, Header, Manifest, RecordType};

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
            OK(()) => {}
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
    // Need exactly 8 bytes: 4 for magic + 4 for version
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
