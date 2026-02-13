//! SCLS file reader and record parsing.

use std::io::{Read, Seek};

use crate::error::{Result, SclsError};
use crate::types::{ChunkHandle, Header, Manifest, RecordType};

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
        RecordIter {
            reader: self,
            current_offset: 0,
        }
    }
}

/// An iterator over records in an SCLS file.
pub struct RecordIter<'a, R> {
    reader: &'a mut SclsReader<R>,
    current_offset: u64,
}

/// A parsed record from an SCLS file.
#[derive(Debug)]
pub enum Record {
    /// File header
    Header(Header),

    /// Data chunk (with lazy loading)
    Chunk(ChunkHandle),

    /// Manifest
    Manifest(Manifest),

    /// Unknown record (can be safely skipped)
    Unknown { record_type: u8, data: Vec<u8> },
}

impl<'a, R: Read + Seek> Iterator for RecordIter<'a, R> {
    type Item = Result<Record>;

    fn next(&mut self) -> Option<Self::Item> {
        // Track the offset where this record starts
        let record_start = self.current_offset;

        // Read the 4-byte length prefix
        // NOTE We don't distinguish between EOF or a partial read, so an incomplete length at the
        // end of the file won't be picked up as a truncated/corrupted file; see issue #9.
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

        // Update offset
        self.current_offset = match self.current_offset.checked_add(4) {
            Some(offset) => offset,
            None => return Some(Err(SclsError::MalformedRecord("offset overflow".into()))),
        };

        // Read the 1-byte record type
        let mut type_buf = [0u8; 1];
        if let Err(e) = self.reader.reader.read_exact(&mut type_buf) {
            return Some(Err(e.into()));
        }
        let record_type = type_buf[0];

        // Update offset
        self.current_offset = match self.current_offset.checked_add(1) {
            Some(offset) => offset,
            None => return Some(Err(SclsError::MalformedRecord("offset overflow".into()))),
        };

        // Read the remaining payload
        let data_len = (payload_len - 1) as usize;
        let mut data = vec![0u8; data_len];
        if let Err(e) = self.reader.reader.read_exact(&mut data) {
            return Some(Err(e.into()));
        }

        // Update offset
        self.current_offset = match self.current_offset.checked_add(data_len as u64) {
            Some(offset) => offset,
            None => return Some(Err(SclsError::MalformedRecord("offset overflow".into()))),
        };

        // Parse based on type, passing the record start offset
        Some(parse_record(record_type, &data, record_start))
    }
}

/// Parses a record from its type byte and payload data
fn parse_record(record_type: u8, data: &[u8], record_start_offset: u64) -> Result<Record> {
    match RecordType::from_byte(record_type) {
        Some(RecordType::Header) => Ok(Record::Header(data.try_into()?)),

        Some(RecordType::Chunk) => {
            // Calculate where the chunk data starts in the file
            // record_start_offset points to the length prefix
            // After: len(4) + type(1) + header fields, we get to entry data
            let chunk_handle = ChunkHandle::parse(data, record_start_offset)?;
            Ok(Record::Chunk(chunk_handle))
        }

        Some(RecordType::Manifest) => Ok(Record::Manifest(data.try_into()?)),

        // Future/unimplemented types
        Some(_) => Ok(Record::Unknown {
            record_type,
            data: data.to_vec(),
        }),

        // Actually unknown
        None => Ok(Record::Unknown {
            record_type,
            data: data.to_vec(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use std::ops::RangeInclusive;
    use std::str;

    use crate::error::Result;
    use crate::types::ChunkFormat;

    use super::{Record, SclsReader};

    /// Slurped in fixture generated from Haskell reference implementation:
    /// ```sh
    /// scls-util debug generate minimal-raw.scls --namespace blocks/v0:1
    /// ```
    const FIXTURE: &[u8] = include_bytes!("../tests/fixtures/minimal-raw.scls");

    /// Fixture ranges extracted from the [Kaitai IDE](https://ide.kaitai.io), using the Kaitai
    /// specification defined in [CIP-0165](https://github.com/tweag/CIPs/tree/cip-canonical/CIP-0165)
    const HEADER_VERSION: RangeInclusive<usize> = 0x9..=0xc;
    const CHUNK_SEQ_NO: RangeInclusive<usize> = 0x12..=0x19;
    const CHUNK_NAMESPACE: RangeInclusive<usize> = 0x1f..=0x27;
    const CHUNK_KEY_LEN: RangeInclusive<usize> = 0x28..=0x2b;
    const CHUNK_ENTRY_KEY: RangeInclusive<usize> = 0x30..=0x53;
    const CHUNK_ENTRY_VALUE: RangeInclusive<usize> = 0x54..=0x5c;
    const CHUNK_ENTRY_COUNT: RangeInclusive<usize> = 0x5d..=0x60;
    const CHUNK_DIGEST: RangeInclusive<usize> = 0x61..=0x7c;
    const MANIFEST_SLOT_NO: RangeInclusive<usize> = 0x82..=0x89;
    const MANIFEST_TOTAL_ENTRIES: RangeInclusive<usize> = 0x8a..=0x91;
    const MANIFEST_TOTAL_CHUNKS: RangeInclusive<usize> = 0x92..=0x99;
    const MANIFEST_ROOT_HASH: RangeInclusive<usize> = 0x11c..=0x137;
    const MANIFEST_NSINFO_ENTRIES_COUNT: RangeInclusive<usize> = 0xdb..=0xe2;
    const MANIFEST_NSINFO_CHUNKS_COUNT: RangeInclusive<usize> = 0xe3..=0xea;
    const MANIFEST_NSINFO_NAME: RangeInclusive<usize> = 0xeb..=0xf3;
    const MANIFEST_NSINFO_DIGEST: RangeInclusive<usize> = 0xf4..=0x10f;
    const MANIFEST_PREV_MANIFEST: RangeInclusive<usize> = 0x114..=0x11b;
    const MANIFEST_SUMMARY_CREATED_AT: RangeInclusive<usize> = 0x9e..=0xbb;
    const MANIFEST_SUMMARY_TOOL: RangeInclusive<usize> = 0xc0..=0xd2;
    const MANIFEST_OFFSET: RangeInclusive<usize> = 0x138..=0x13b;

    #[test]
    fn read_fixture_records() -> Result<()> {
        let scls = Cursor::new(FIXTURE);
        let mut reader = SclsReader::new(scls);

        for record in reader.records() {
            match record? {
                Record::Header(header) => {
                    assert_eq!(
                        header.version,
                        u32::from_be_bytes(FIXTURE[HEADER_VERSION].try_into().unwrap())
                    )
                }

                // We only have one chunk, with one entry
                Record::Chunk(chunk) => {
                    assert_eq!(
                        chunk.seqno,
                        u64::from_be_bytes(FIXTURE[CHUNK_SEQ_NO].try_into().unwrap())
                    );

                    assert_eq!(chunk.format, ChunkFormat::Raw);

                    assert_eq!(
                        chunk.namespace,
                        str::from_utf8(&FIXTURE[CHUNK_NAMESPACE]).unwrap()
                    );

                    assert_eq!(
                        chunk.key_len,
                        u32::from_be_bytes(FIXTURE[CHUNK_KEY_LEN].try_into().unwrap())
                    );

                    let footer_entry_count =
                        u32::from_be_bytes(FIXTURE[CHUNK_ENTRY_COUNT].try_into().unwrap());

                    assert_eq!(chunk.entries.len(), footer_entry_count as usize);

                    let entry = chunk.entries.first().unwrap();
                    assert_eq!(entry.key, FIXTURE[CHUNK_ENTRY_KEY]);
                    assert_eq!(entry.value, FIXTURE[CHUNK_ENTRY_VALUE]);

                    assert_eq!(chunk.footer.entries_count, footer_entry_count);

                    assert_eq!(*chunk.footer.digest.as_bytes(), FIXTURE[CHUNK_DIGEST]);
                }

                Record::Manifest(manifest) => {
                    assert_eq!(
                        manifest.slot_no,
                        u64::from_be_bytes(FIXTURE[MANIFEST_SLOT_NO].try_into().unwrap())
                    );

                    assert_eq!(
                        manifest.total_entries,
                        u64::from_be_bytes(FIXTURE[MANIFEST_TOTAL_ENTRIES].try_into().unwrap())
                    );

                    assert_eq!(
                        manifest.total_chunks,
                        u64::from_be_bytes(FIXTURE[MANIFEST_TOTAL_CHUNKS].try_into().unwrap())
                    );

                    assert_eq!(*manifest.root_hash.as_bytes(), FIXTURE[MANIFEST_ROOT_HASH]);

                    assert_eq!(manifest.namespace_info.len(), 1);
                    let ns_info = manifest.namespace_info.first().unwrap();

                    assert_eq!(
                        ns_info.entries_count,
                        u64::from_be_bytes(
                            FIXTURE[MANIFEST_NSINFO_ENTRIES_COUNT].try_into().unwrap()
                        )
                    );

                    assert_eq!(
                        ns_info.chunks_count,
                        u64::from_be_bytes(
                            FIXTURE[MANIFEST_NSINFO_CHUNKS_COUNT].try_into().unwrap()
                        )
                    );

                    assert_eq!(
                        ns_info.name,
                        str::from_utf8(&FIXTURE[MANIFEST_NSINFO_NAME]).unwrap()
                    );

                    assert_eq!(*ns_info.digest.as_bytes(), FIXTURE[MANIFEST_NSINFO_DIGEST]);

                    assert_eq!(
                        manifest.prev_manifest,
                        u64::from_be_bytes(FIXTURE[MANIFEST_PREV_MANIFEST].try_into().unwrap())
                    );

                    assert_eq!(
                        manifest.summary.created_at,
                        str::from_utf8(&FIXTURE[MANIFEST_SUMMARY_CREATED_AT]).unwrap()
                    );

                    assert_eq!(
                        manifest.summary.tool,
                        str::from_utf8(&FIXTURE[MANIFEST_SUMMARY_TOOL]).unwrap()
                    );

                    assert_eq!(manifest.summary.comment, None);

                    assert_eq!(
                        manifest.offset,
                        u32::from_be_bytes(FIXTURE[MANIFEST_OFFSET].try_into().unwrap())
                    );
                }

                Record::Unknown { record_type, .. } => {
                    panic!("Unknown record type: 0x{:02x}", record_type)
                }
            }
        }

        Ok(())
    }

    #[test]
    fn fixture_has_expected_structure() -> Result<()> {
        let scls = Cursor::new(FIXTURE);
        let mut reader = SclsReader::new(scls);
        let records: Vec<_> = reader.records().collect::<Result<_>>()?;

        assert_eq!(records.len(), 3);
        assert!(matches!(records[0], Record::Header(_)));
        assert!(matches!(records[1], Record::Chunk(_)));
        assert!(matches!(records[2], Record::Manifest(_)));

        Ok(())
    }
}
