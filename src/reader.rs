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
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return None,
            Err(e) => return Some(Err(e.into())),
        }

        let payload_len = u32::from_be_bytes(len_buf);

        // Check the payload isn't empty
        if payload_len == 0 {
            return Some(Err(SclsError::MalformedRecord(
                "zero length payload record".into(),
            )));
        }

        // Read the 1-byte record type
        let mut type_buf = [0u8; 1];
        if let Err(e) = self.reader.reader.read_exact(&mut type_buf) {
            return Some(Err(e.into()));
        }
        let record_type = type_buf[0];

        // Read the remaining payload
        let data_len = (payload_len - 1) as usize;
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
        Some(RecordType::Header) => Ok(Record::Header(data.as_slice().try_into()?)),

        Some(RecordType::Chunk) => Ok(Record::Chunk(data.as_slice().try_into()?)),

        Some(RecordType::Manifest) => Ok(Record::Manifest(data.as_slice().try_into()?)),

        // Future/unimplemented types
        Some(_) => Ok(Record::Unknown { record_type, data }),

        // Actually unknown
        None => Ok(Record::Unknown { record_type, data }),
    }
}
