//! SCLS file reader and record parsing.

use std::collections::{BTreeMap, BTreeSet}; // To maintain key order
use std::io::{Read, Seek};

use crate::error::{Result, SclsError};
use crate::types::digest::HASH_SIZE;
use crate::types::merkle::LEAF_PREFIX;
use crate::types::{Chunk, Digest, Header, Manifest, MerkleTree, RecordType};

use blake2b_simd::Params;

/// Structural integrity check options.
#[derive(Debug, Eq, PartialEq)]
pub enum CheckStructure {
    /// Do not verify structural integrity.
    Disabled,

    /// Verify that:
    /// - the chunk sequence is strictly monotonically increasing;
    /// - chunk namespaces are in bytewise ascending order;
    /// - manifest chunk and entry counts are correct for each namespace.
    Simple,

    /// [Simple verification](CheckStructure::Simple), plus verify that:
    /// - chunk keys are in lexicographically ascending order.
    ///
    /// Note: This requires key materialisation and, hence, more memory.
    Full,
}

impl CheckStructure {
    /// Whether structural integrity verification is enabled.
    pub fn enabled(&self) -> bool {
        self != &CheckStructure::Disabled
    }
}

/// SCLS file verification options
#[derive(Debug, Eq, PartialEq)]
pub struct VerifyOptions {
    /// Check structural integrity
    pub check_structure: CheckStructure,

    /// Check that all digests are valid. That is:
    /// - Chunk digests
    /// - Namespace Merkle root digests
    /// - The global Merkle root digest
    pub check_integrity: bool,
}

impl VerifyOptions {
    /// Full verification.
    pub fn full() -> Self {
        Self {
            check_structure: CheckStructure::Full,
            check_integrity: true,
        }
    }
}

impl Default for VerifyOptions {
    fn default() -> Self {
        Self {
            check_structure: CheckStructure::Simple,
            check_integrity: true,
        }
    }
}

/// A reader for SCLS files that can iterate over records.
pub struct SclsReader<R> {
    reader: R,
}

// NOTE We need `Seek` to be able to lazily stream CHUNK records. It may be worthwhile having a
// limited `Read`-only impl as well for, e.g., pipe access.
impl<R: Read + Seek> SclsReader<R> {
    /// Creates a new SCLS reader from the given I/O source.
    ///
    /// This does not parse the header yet; use [`records`](Self::records) to begin iteration.
    pub fn new(reader: R) -> Self {
        Self { reader }
    }

    /// Returns an iterator over records in the file.
    ///
    /// The iterator will rewind the reader if it is not currently at the start of the stream.
    ///
    /// # Errors
    ///
    /// Returns an error if querying the reader's current position or rewinding fails.
    pub fn records(&mut self) -> Result<RecordIter<'_, R>> {
        // Rewind the reader if it's not at the start of the stream
        if self.reader.stream_position()? != 0 {
            self.reader.seek(std::io::SeekFrom::Start(0))?;
        }

        Ok(RecordIter {
            reader: self,
            failed: false,
        })
    }

    /// Verify the SCLS file with the given options.
    ///
    /// The reader will be rewound if it is not currently at the start of the stream.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - TODO
    pub fn verify(&mut self, options: VerifyOptions) -> Result<()> {
        if !options.check_structure.enabled() && !options.check_integrity {
            // This is vacuous, but technically allowed
            return Ok(());
        }

        let mut last_chunk_seqno: Option<u64> = None;
        let mut last_chunk_namespace: Option<String> = None;
        let mut last_ns_entry_key: Option<Vec<u8>> = None;
        let mut ns_chunks: BTreeMap<String, u64> = BTreeMap::new();
        let mut ns_entries: BTreeMap<String, u64> = BTreeMap::new();
        let mut ns_digests: BTreeMap<String, MerkleTree> = BTreeMap::new();

        // TODO
        // - [x] Iterate through records
        // - [ ] For chunks:
        //   - [x] Update the current seqno and namespace
        //     - if CheckStructure::Simple
        //       - [x] Check monotonicity of seqno and namespace
        //     - if namespace has changed and CheckStructure::Full
        //       - [x] reset last_namespace_key
        //   - if check_integrity:
        //     - [ ] Verify the chunk
        //   - if CheckStructure::Full
        //     - [ ] Iterate through entries and update last namespace key
        //     - [ ] Check monotonicity
        //   - [ ] Add entry digest to namespace Merkle tree
        // - [x] For manifest
        //   - [x] Namespace sets are the same
        //   - if CheckStructure::Simple
        //     - [x] Namespace chunk count matches
        //     - [x] Namespace entry count matches
        //   - if check_integrity
        //     - [x] Check namespace Merkle roots
        //     - [x] Construct global Merkle tree from namespace roots in ascending order by namespace, prepended with 0x01
        //     - [x] Check global Merkle root

        for record in self.records()? {
            match record? {
                Record::Chunk(chunk) => {
                    if options.check_structure.enabled() {
                        // Check strict monotonicity of chunk sequence number
                        if let Some(previous) = last_chunk_seqno
                            && previous >= chunk.seqno
                        {
                            return Err(SclsError::SeqnoDisordered {
                                previous,
                                found: chunk.seqno,
                            });
                        }

                        if let Some(previous) = last_chunk_namespace {
                            // Check monotonicity of chunk namespace
                            if previous > chunk.namespace {
                                return Err(SclsError::NamespaceDisordered {
                                    previous,
                                    found: chunk.namespace,
                                });
                            }

                            // Reset last namespace's last entry key if the namespaces changes
                            // during a full check
                            if options.check_structure == CheckStructure::Full
                                && previous == chunk.namespace
                            {
                                last_ns_entry_key = None;
                            }
                        }
                    }

                    // WIP...

                    // Update chunk state for the next round
                    last_chunk_seqno = Some(chunk.seqno);
                    last_chunk_namespace = Some(chunk.namespace);
                }

                Record::Manifest(manifest) => {
                    // Convert manifest namespace info vector into an ordered map of chunk count,
                    // entry count and digest tuples. A BTree map is used to ensure entries are
                    // ordered by namespace.
                    let ns_info: BTreeMap<String, (u64, u64, Digest)> = manifest
                        .namespace_info
                        .iter()
                        .map(|ns_info| {
                            (
                                ns_info.name.clone(),
                                (ns_info.chunks_count, ns_info.entries_count, ns_info.digest),
                            )
                        })
                        .collect();

                    // Chunk namespaces must match manifest namespaces
                    let chunk_namespaces: BTreeSet<&String> = ns_chunks.keys().collect();
                    let manifest_namespaces: BTreeSet<&String> = ns_info.keys().collect();

                    if chunk_namespaces != manifest_namespaces {
                        // Only clone when necessary, for the error
                        let in_chunks: Vec<String> =
                            chunk_namespaces.into_iter().cloned().collect();
                        let in_manifest: Vec<String> =
                            manifest_namespaces.into_iter().cloned().collect();

                        return Err(SclsError::NamespaceMismatch {
                            in_chunks,
                            in_manifest,
                        });
                    }

                    // Check structure
                    if options.check_structure.enabled() {
                        for (namespace, (chunk_count, entry_count, _)) in &ns_info {
                            // Namespace chunk counts must match those in the manifest
                            let expected = *chunk_count;
                            let found = ns_chunks[namespace];
                            if expected != found {
                                return Err(SclsError::NamespaceChunkMismatch {
                                    namespace: namespace.to_string(),
                                    expected,
                                    found,
                                });
                            }

                            // Namespace entry counts must match those in the manifest
                            let expected = *entry_count;
                            let found = ns_entries[namespace];
                            if expected != found {
                                return Err(SclsError::NamespaceEntryMismatch {
                                    namespace: namespace.to_string(),
                                    expected,
                                    found,
                                });
                            }
                        }
                    }

                    // Check integrity
                    if options.check_integrity {
                        let mut global_merkle: MerkleTree = MerkleTree::new();

                        // Namespaces will be iterated through in order by virtue of the BTree map,
                        // so the global Merkle tree's order will be correct
                        for (namespace, (_, _, digest)) in &ns_info {
                            // Check namespace root digests match computed
                            let expected = *digest;
                            let computed = ns_digests.remove(namespace).unwrap().root();
                            if expected != computed {
                                return Err(SclsError::NamespaceDigestMismatch {
                                    namespace: namespace.to_string(),
                                    expected,
                                    computed,
                                });
                            }

                            // Update the global Merkle tree
                            let ns_hash = Params::new()
                                .hash_length(HASH_SIZE)
                                .to_state()
                                .update(&[LEAF_PREFIX])
                                .update(expected.as_bytes())
                                .finalize();

                            let ns_hash_bytes: [u8; HASH_SIZE] =
                                ns_hash.as_bytes().try_into().unwrap();

                            global_merkle.add_leaf(Digest::new(ns_hash_bytes));
                        }

                        // Check the global Merkle root matches
                        let expected = manifest.root_hash;
                        let computed = global_merkle.root();
                        if expected != computed {
                            return Err(SclsError::GlobalDigestMismatch { expected, computed });
                        }
                    }
                }

                _ => {}
            };
        }

        Ok(())
    }
}

/// An iterator over records in an SCLS file.
pub struct RecordIter<'a, R> {
    reader: &'a mut SclsReader<R>,
    failed: bool,
}

/// A parsed record from an SCLS file.
#[derive(Debug)]
pub enum Record {
    /// File header
    Header(Header),

    /// Data chunk (with lazy loading)
    Chunk(Chunk),

    /// Manifest
    Manifest(Manifest),

    /// Unknown record (can be safely skipped)
    Unknown { record_type: u8, data: Vec<u8> },
}

impl Record {
    /// Read and parse the next record from the reader's current position.
    ///
    /// Returns `Ok(None)` at end of file. Chunk records are parsed lazily -- only the header and
    /// footer are read -- entry data is not loaded until explicitly requested via
    /// [`Chunk::for_each_entry`] or [`Chunk::verify_and`].
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - An I/O error occurs
    /// - The record has a zero-length payload
    /// - The payload offset overflows a `u64`
    /// - The record payload is malformed
    fn read_next<R: Read + Seek>(reader: &mut R) -> Result<Option<Self>> {
        // Read the 4-byte length prefix
        let mut len_buf = [0u8; 4];
        if let Err(e) = reader.read_exact(&mut len_buf) {
            // NOTE We don't distinguish between EOF or a partial read, so an incomplete length at
            // the end of the file won't be picked up as a truncated/corrupted file; see issue #9.
            if e.kind() == std::io::ErrorKind::UnexpectedEof {
                return Ok(None);
            }
            return Err(e.into());
        }

        // Check the payload isn't empty
        let payload_len = u32::from_be_bytes(len_buf);
        if payload_len == 0 {
            return Err(SclsError::MalformedRecord(
                "zero length payload record".into(),
            ));
        }

        // Read the 1-byte record type
        let mut type_buf = [0u8; 1];
        reader.read_exact(&mut type_buf)?;
        let record_type = type_buf[0];

        // The remaining payload length (excluding type byte)
        let data_len = payload_len - 1;

        // Handle chunks specially: parse directly from reader without buffering
        if RecordType::from_byte(record_type) == Some(RecordType::Chunk) {
            // Current position is payload start (after type byte)
            let payload_start = reader.stream_position()?;

            // Parse chunk directly from reader (reads only header + footer)
            let chunk_result = Chunk::parse(reader, payload_start, data_len);

            // Byte offset for next record
            let next_offset = match payload_start.checked_add(data_len as u64) {
                Some(offset) => offset,
                None => return Err(SclsError::MalformedRecord("offset overflow".into())),
            };

            // Seek to end of record and return the parsed chunk
            reader.seek(std::io::SeekFrom::Start(next_offset))?;
            return chunk_result.map(Record::Chunk).map(Some);
        }

        // For non-chunk records, read the full payload into a buffer
        let mut data = vec![0u8; data_len as usize];
        reader.read_exact(&mut data)?;

        // Parse based on type
        Record::parse(record_type, &data).map(Some)
    }

    /// Parses a non-chunk record from its type byte and payload data.
    ///
    /// Note: Chunk records are parsed directly from the reader in `Record::read_next` to achieve
    /// lazy loading, so this method will return an error for chunk types.
    fn parse(record_type: u8, data: &[u8]) -> Result<Self> {
        match RecordType::from_byte(record_type) {
            Some(RecordType::Header) => Ok(Self::Header(data.try_into()?)),

            // Chunks are parsed directly from the reader, not here
            Some(RecordType::Chunk) => {
                unreachable!("chunk records are parsed in Record::read_next")
            }

            Some(RecordType::Manifest) => Ok(Self::Manifest(data.try_into()?)),

            // Future/unimplemented types
            Some(_) => Ok(Self::Unknown {
                record_type,
                data: data.to_vec(),
            }),

            // Actually unknown
            None => Ok(Self::Unknown {
                record_type,
                data: data.to_vec(),
            }),
        }
    }
}

impl<'a, R: Read + Seek> Iterator for RecordIter<'a, R> {
    type Item = Result<Record>;

    fn next(&mut self) -> Option<Self::Item> {
        // Terminate the iterator if it has failed midway
        if self.failed {
            return None;
        }

        // Parse the next record
        match Record::read_next(&mut self.reader.reader) {
            Ok(Some(record)) => Some(Ok(record)),
            Ok(None) => None,
            Err(e) => {
                self.failed = true;
                Some(Err(e))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use std::ops::RangeInclusive;
    use std::str;

    use crate::error::Result;
    use crate::types::{ChunkFormat, Entry};

    use super::{Record, SclsReader};

    /// Slurped in fixture generated from Haskell reference implementation:
    ///
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
    fn minimal_fixture() -> Result<()> {
        let scls = Cursor::new(FIXTURE);
        let mut reader = SclsReader::new(scls);

        let records: Vec<_> = reader.records()?.collect::<Result<_>>()?;
        assert_eq!(records.len(), 3);

        // Test header
        if let Record::Header(header) = &records[0] {
            assert_eq!(
                header.version,
                u32::from_be_bytes(FIXTURE[HEADER_VERSION].try_into().unwrap())
            )
        } else {
            panic!("Expected header");
        }

        // Test chunk
        if let Record::Chunk(chunk) = &records[1] {
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

            assert_eq!(chunk.footer.entries_count, footer_entry_count);

            assert_eq!(*chunk.footer.digest.as_bytes(), FIXTURE[CHUNK_DIGEST]);

            let mut cursor = Cursor::new(FIXTURE);
            chunk.verify(&mut cursor)?;

            let mut cursor = Cursor::new(FIXTURE);
            let mut entries: Vec<Entry> = Vec::with_capacity(chunk.footer.entries_count as usize);
            chunk.for_each_entry(&mut cursor, |reader, key_len, val_len| {
                let entry = Entry::materialise(reader, key_len, val_len)?;
                entries.push(entry);
                Ok(())
            })?;

            assert_eq!(entries.len(), 1);

            let entry = entries.first().unwrap();
            assert_eq!(entry.key, FIXTURE[CHUNK_ENTRY_KEY]);
            assert_eq!(entry.value, FIXTURE[CHUNK_ENTRY_VALUE]);
        } else {
            panic!("Expected chunk");
        }

        // Test manifest
        if let Record::Manifest(manifest) = &records[2] {
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
                u64::from_be_bytes(FIXTURE[MANIFEST_NSINFO_ENTRIES_COUNT].try_into().unwrap())
            );

            assert_eq!(
                ns_info.chunks_count,
                u64::from_be_bytes(FIXTURE[MANIFEST_NSINFO_CHUNKS_COUNT].try_into().unwrap())
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
        } else {
            panic!("Expected manifest");
        }

        Ok(())
    }
}
