//! SCLS file reader and record parsing.

use std::io::{Read, Seek};

use crate::error::Result;
use crate::types::{Chunk, Header, Manifest};

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
