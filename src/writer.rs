//! SCLS file writing.

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::io::Write;

use chrono::{SecondsFormat, Utc};

use crate::error::{Result, SclsError};
use crate::hash::{Blake2b, HASH_SIZE, MerkleTree};
use crate::records::{ChunkFormat, Header, Manifest, NamespaceInfo, RecordType, Summary};

/// Default tool name.
pub const DEFAULT_TOOL: &str = "cardano-scrawls";

/// Default maximum chunk size (modulo pathologically large entries)
pub const DEFAULT_MAX_CHUNK_SIZE: usize = 16 * 1024 * 1024; // 16 MiB

/// SclsWriter builder.
#[derive(Debug)]
pub struct SclsWriterBuilder<W: Write> {
    output: Option<W>,
    slot_no: Option<u64>,
    tool: String,
    comment: Option<String>,
    max_chunk_size: usize,
}

impl<W: Write> SclsWriterBuilder<W> {
    /// Create a new SCLS writer builder with its default parameters.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the writer's output source (required).
    pub fn output(mut self, writer: W) -> Self {
        self.output = Some(writer);
        self
    }

    /// Set the writer's blockchain point/slot number (required).
    pub fn slot_no(mut self, slot_no: u64) -> Self {
        self.slot_no = Some(slot_no);
        self
    }

    /// Set the writer's tool name (optional).
    pub fn tool<S: AsRef<str>>(mut self, tool: S) -> Self {
        self.tool = tool.as_ref().to_string();
        self
    }

    /// Set the writer's comment (optional).
    pub fn comment<S: AsRef<str>>(mut self, comment: S) -> Self {
        self.comment = Some(comment.as_ref().to_string());
        self
    }

    /// Set the writer's ideal maximum chunk size (optional).
    ///
    /// Note that entries that exceed this threshold will not be split and the materialised chunk
    /// size will necessarily exceed this threshold.
    pub fn max_chunk_size(mut self, max_chunk_size: usize) -> Self {
        self.max_chunk_size = max_chunk_size;
        self
    }

    /// Build an [`SclsWriter`] given the current parameters and write the header record.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Any required parameters have been omitted
    /// - I/O failure when writing the header
    pub fn build(self) -> Result<SclsWriter<W>> {
        let output = self.output.ok_or(SclsError::WriterBuilderMissingOutput)?;
        let slot_no = self.slot_no.ok_or(SclsError::WriterBuilderMissingSlotNo)?;

        let mut writer = SclsWriter {
            output,
            slot_no,
            tool: self.tool,
            comment: self.comment,
            max_chunk_size: self.max_chunk_size,
            prev_namespace: None,
            prev_ns_entry_key: None,
            chunk_seqno: 0,
            current_chunk: None,
            ns_state: BTreeMap::new(),
        };

        let header = Header::current();
        header.write(&mut writer.output)?;

        Ok(writer)
    }
}

impl<W: Write> Default for SclsWriterBuilder<W> {
    fn default() -> Self {
        Self {
            output: None,
            slot_no: None,
            tool: DEFAULT_TOOL.to_string(),
            comment: None,
            max_chunk_size: DEFAULT_MAX_CHUNK_SIZE,
        }
    }
}

/// Namespace state tracking.
#[derive(Debug)]
struct NamespaceState {
    /// Namespace key length
    key_len: Option<u32>,

    /// Number of chunks in the namespace
    chunks: u64,

    /// Number of entries in the namespace
    entries: u64,

    /// Merkle tree for namespace
    merkle: MerkleTree,
}

impl NamespaceState {
    fn new() -> Self {
        Self {
            key_len: None,
            chunks: 0,
            entries: 0,
            merkle: MerkleTree::new(),
        }
    }
}

/// Chunk state tracking.
#[derive(Debug)]
struct ChunkState {
    /// Serialised entries payload
    payload: Vec<u8>,

    /// Chunk digest hasher
    hasher: Blake2b,

    /// Number of entries in the chunk
    entries: u32,
}

impl ChunkState {
    fn new() -> Self {
        Self {
            payload: Vec::new(),
            hasher: Blake2b::new_raw(),
            entries: 0,
        }
    }
}

/// A writer for SCLS files.
#[derive(Debug)]
pub struct SclsWriter<W> {
    /// Output sink
    output: W,

    /// Blockchain point/slot number
    slot_no: u64,

    /// Tool name
    tool: String,

    /// Comment
    comment: Option<String>,

    /// Ideal maximum chunk size (bytes)
    max_chunk_size: usize,

    /* State tracking */
    /// Previously written namespace
    prev_namespace: Option<String>,

    /// Previously written namespace entry key
    // NOTE Reset this to `None` when `prev_namespace` changes
    prev_ns_entry_key: Option<Vec<u8>>,

    /// Chunk sequence number
    chunk_seqno: u64,

    /// Chunk state
    // NOTE Reset this to `None` whenever a chunk is flushed
    current_chunk: Option<ChunkState>,

    /// Namespace state
    ns_state: BTreeMap<String, NamespaceState>,
}

impl<W: Write> SclsWriter<W> {
    /// Build a new writer incrementally from its parameters.
    pub fn builder() -> SclsWriterBuilder<W> {
        SclsWriterBuilder::new()
    }

    /// Write an entry to the SCLS output.
    ///
    /// # Errors
    ///
    /// Returns an error when:
    /// - The namespace is not the same or bytewise ascending from previously written namespaces
    /// - The entry key is not strictly lexicographically monotonic for previously written entry
    ///   keys in the given namespace
    /// - The entry, its key or its value has length greater than 2^32 bytes
    /// - Entry key length is inconsistent within the same namespace
    /// - Wire format field overflows
    /// - I/O failures
    pub fn write_entry(&mut self, namespace: &str, key: &[u8], value: &[u8]) -> Result<()> {
        // Check and update (if necessary) namespace state
        match &self.prev_namespace {
            None => {
                self.prev_namespace = Some(namespace.to_string());
                self.ns_state
                    .insert(namespace.to_string(), NamespaceState::new());
            }

            Some(prev_namespace) => {
                let order = prev_namespace.as_str().cmp(namespace);
                match order {
                    // No namespace change: nothing to do
                    Ordering::Equal => {}

                    // New namespace is monotonically increasing: flush chunk and reset state
                    Ordering::Less => {
                        self.flush_chunk()?;
                        self.prev_namespace = Some(namespace.to_string());
                        self.prev_ns_entry_key = None;
                        self.ns_state
                            .insert(namespace.to_string(), NamespaceState::new());
                    }

                    // Non-monotonic namespace
                    Ordering::Greater => {
                        return Err(SclsError::NonMonotonicNamespace {
                            previous: prev_namespace.clone(),
                            found: namespace.to_string(),
                        });
                    }
                };
            }
        }

        // Check key monotonicity (without updating state yet)
        if let Some(prev_key) = &self.prev_ns_entry_key
            && prev_key.as_slice() >= key
        {
            return Err(SclsError::NonStrictlyMonotonicKeys {
                namespace: namespace.to_string(),
            });
        }

        // Flush any existing chunk that's reached the size limit
        // Note that this resets the current chunk (see SclsWriter::flush_chunk)
        if let Some(chunk) = &self.current_chunk
            && chunk.payload.len() >= self.max_chunk_size
        {
            self.flush_chunk()?;
        }

        // Create a new chunk, if required
        if self.current_chunk.is_none() {
            self.current_chunk = Some(ChunkState::new());
        }

        self.update_chunk(key, value)?;

        // Only advance key state after successful write
        self.prev_ns_entry_key = Some(key.to_vec());

        Ok(())
    }

    /// Update the chunk that is currently being built with the next entry.
    ///
    /// Note that this _must_ be called when the necessary state is available. Namely:
    /// [`SclsWriter::prev_namespace`], [`SclsWriter::current_chunk`] and the respective namespace
    /// entry in [`SclsWriter::ns_state`].
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The entry, its key or its value has length greater than 2^32 bytes
    /// - Entry key length is inconsistent within the same namespace
    fn update_chunk(&mut self, key: &[u8], value: &[u8]) -> Result<()> {
        let Some(namespace) = &self.prev_namespace else {
            unreachable!("must only be called when the namespace is set");
        };

        let Some(chunk) = &mut self.current_chunk else {
            unreachable!("must only be called when the current chunk is set");
        };

        let Some(ns_state) = self.ns_state.get_mut(namespace) else {
            unreachable!("must only be called when the namespace state is set")
        };

        // Set and check the key length, as necessary
        match ns_state.key_len {
            Some(key_len) => {
                // Key length consistency check
                if key.len() != key_len as usize {
                    return Err(SclsError::InconsistentKeyLength {
                        namespace: namespace.clone(),
                        expected: key_len as usize,
                        found: key.len(),
                    });
                }
            }

            None => {
                // Checked truncation
                let key_len = u32::try_from(key.len())
                    .map_err(|_| SclsError::WireLengthOverflow("entry key".into()))?;
                ns_state.key_len = Some(key_len);
            }
        };

        // Compute and check entry length
        let entry_len = u32::try_from(
            key.len()
                .checked_add(value.len())
                .ok_or(SclsError::WireLengthOverflow("entry".into()))?,
        )
        .map_err(|_| SclsError::WireLengthOverflow("entry".into()))?;

        // Compute entry digest
        let entry_digest = Blake2b::new_leaf()
            .update(namespace.as_bytes())
            .update(key)
            .update(value)
            .as_digest();

        // Update chunk digest and namespace Merkle tree
        chunk.hasher.update(entry_digest.as_bytes());
        ns_state.merkle.add_leaf(entry_digest);

        // Serialise entry
        chunk.entries += 1;
        chunk.payload.extend_from_slice(&entry_len.to_be_bytes());
        chunk.payload.extend_from_slice(key);
        chunk.payload.extend_from_slice(value);

        Ok(())
    }

    /// Discharge the current chunk buffer to the writer and update the state.
    ///
    /// Note that this _must_ be called when the necessary state is available. Namely:
    /// [`SclsWriter::prev_namespace`], [`SclsWriter::current_chunk`] and the respective namespace
    /// entry in [`SclsWriter::ns_state`].
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Wire format field overflows
    /// - I/O failures
    fn flush_chunk(&mut self) -> Result<()> {
        let Some(namespace) = &self.prev_namespace else {
            unreachable!("must only be called when the namespace is set");
        };

        // Get the current chunk state and reset it (i.e., replace it with `None`)
        let Some(chunk) = self.current_chunk.take() else {
            unreachable!("must only be called when the current chunk is set");
        };

        let Some(ns_state) = self.ns_state.get_mut(namespace) else {
            unreachable!("must only be called when the namespace state is set")
        };

        let len_ns = u32::try_from(namespace.len())
            .map_err(|_| SclsError::WireLengthOverflow("namespace".into()))?;
        let len_key = ns_state.key_len.unwrap(); // Safe (set in update_chunk)
        let len_entries = u32::try_from(chunk.payload.len())
            .map_err(|_| SclsError::WireLengthOverflow("entries".into()))?;

        let len_record = [
            1,                // Type
            8,                // Sequence number
            1,                // Format
            4,                // Namespace length
            len_ns,           // Namespace
            4,                // Entry key length
            len_entries,      // Entries payload
            4,                // Entries count
            HASH_SIZE as u32, // Digest
        ]
        .iter()
        .try_fold(0u32, |acc, &x| acc.checked_add(x))
        .ok_or(SclsError::WireLengthOverflow("record".into()))?;

        // Discharge chunk wire format
        self.output.write_all(&len_record.to_be_bytes())?;
        self.output.write_all(&[RecordType::Chunk.to_byte()])?;
        self.output.write_all(&self.chunk_seqno.to_be_bytes())?;
        self.output.write_all(&[ChunkFormat::Raw.to_byte()])?; // Compression support forthcoming
        self.output.write_all(&len_ns.to_be_bytes())?;
        self.output.write_all(namespace.as_bytes())?;
        self.output.write_all(&len_key.to_be_bytes())?;
        self.output.write_all(&chunk.payload)?;
        self.output.write_all(&chunk.entries.to_be_bytes())?;
        self.output.write_all(chunk.hasher.as_digest().as_bytes())?;

        // Update state (recall that we already reset the chunk state earlier)
        self.chunk_seqno += 1;
        ns_state.chunks += 1;
        ns_state.entries += u64::from(chunk.entries);

        Ok(())
    }

    /// Finalise the SCLS output.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Wire format field overflows
    /// - I/O failures
    pub fn finalise(mut self) -> Result<()> {
        // Discharge the final chunk, if there is one, to the writer
        if self.current_chunk.is_some() {
            self.flush_chunk()?;
        }

        let mut global_digest = MerkleTree::new();
        let mut namespace_info = Vec::new();
        let mut total_entries = 0u64;
        let mut total_chunks = 0u64;
        let mut ns_info_len = 0usize;

        // Compute manifest state
        for (namespace, info) in self.ns_state {
            let ns_digest = info.merkle.root();
            let ns_leaf = Blake2b::new_leaf().update(ns_digest.as_bytes()).as_digest();

            // Update global Merkle tree
            global_digest.add_leaf(ns_leaf);

            total_entries += info.entries;
            total_chunks += info.chunks;

            // Namespace info wire length:
            // len_ns(4) + entries(8) + chunks(8) + namespace(len_ns) + digest(HASH_SIZE)
            ns_info_len += 4 + 8 + 8 + namespace.len() + HASH_SIZE;

            namespace_info.push(NamespaceInfo {
                entries_count: info.entries,
                chunks_count: info.chunks,
                name: namespace,
                digest: ns_digest,
            });
        }

        // Current UTC timestamp in RFC 3339 format, with second resolution and Zulu time zone
        let created_at = Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true);

        // A rather nice property of the manifest record is that its offset field is the same as
        // the payload length on the wire, so it's bookended by the same value.
        let offset = u32::try_from(
            [
                1,                                                // Type
                8,                                                // Slot number
                8,                                                // Total entries
                8,                                                // Total chunks
                4 + created_at.len(),                             // Summary: created at
                4 + self.tool.len(),                              // Summary: tool
                4 + self.comment.as_ref().map_or(0, |s| s.len()), // Summary: comment
                ns_info_len,                                      // Namespace info
                4,                                                // ns_info terminal sentinel
                8,                                                // Previous manifest
                HASH_SIZE,                                        // Global hash
                4,                                                // Offset
            ]
            .iter()
            .try_fold(0usize, |acc, &x| acc.checked_add(x))
            .ok_or(SclsError::WireLengthOverflow("manifest offset".into()))?,
        )
        .map_err(|_| SclsError::WireLengthOverflow("manifest offset".into()))?;

        let manifest = Manifest {
            slot_no: self.slot_no,
            total_entries,
            total_chunks,
            root_hash: global_digest.root(),
            namespace_info,
            prev_manifest: 0,
            summary: Summary {
                created_at,
                tool: self.tool,
                comment: self.comment,
            },
            offset,
        };

        manifest.write(&mut self.output)
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;
    use crate::reader::{Record, SclsReader, VerifyOptions};
    use crate::records::Entry;

    use proptest::prelude::*;

    #[test]
    fn accept_same_namespace() -> Result<()> {
        let buf = Vec::new();
        let mut writer = SclsWriter::builder().output(buf).slot_no(0).build()?;

        assert!(writer.write_entry("test", b"a", b"a").is_ok());
        assert!(writer.write_entry("test", b"b", b"a").is_ok());

        Ok(())
    }

    #[test]
    fn accept_monotonic_namespace() -> Result<()> {
        let buf = Vec::new();
        let mut writer = SclsWriter::builder().output(buf).slot_no(0).build()?;

        assert!(writer.write_entry("a", b"a", b"a").is_ok());
        assert!(writer.write_entry("b", b"a", b"a").is_ok());

        Ok(())
    }

    #[test]
    fn forbid_decreasing_namespace() -> Result<()> {
        let buf = Vec::new();
        let mut writer = SclsWriter::builder().output(buf).slot_no(0).build()?;

        assert!(writer.write_entry("b", b"a", b"a").is_ok());
        let Err(err) = writer.write_entry("a", b"a", b"a") else {
            panic!("descending namespace should be forbidden")
        };

        assert!(matches!(err, SclsError::NonMonotonicNamespace { .. }));

        Ok(())
    }

    #[test]
    fn forbid_previous_namespace() -> Result<()> {
        let buf = Vec::new();
        let mut writer = SclsWriter::builder().output(buf).slot_no(0).build()?;

        assert!(writer.write_entry("a", b"a", b"a").is_ok());
        assert!(writer.write_entry("b", b"a", b"a").is_ok());
        let Err(err) = writer.write_entry("a", b"b", b"a") else {
            panic!("descending namespace should be forbidden");
        };

        assert!(matches!(err, SclsError::NonMonotonicNamespace { .. }));

        Ok(())
    }

    #[test]
    fn accept_strictly_increasing_keys() -> Result<()> {
        let buf = Vec::new();
        let mut writer = SclsWriter::builder().output(buf).slot_no(0).build()?;

        assert!(writer.write_entry("a", b"a", b"a").is_ok());
        assert!(writer.write_entry("a", b"b", b"a").is_ok());
        assert!(writer.write_entry("b", b"a", b"a").is_ok());
        assert!(writer.write_entry("b", b"b", b"a").is_ok());

        Ok(())
    }

    #[test]
    fn forbid_equal_keys() -> Result<()> {
        let buf = Vec::new();
        let mut writer = SclsWriter::builder().output(buf).slot_no(0).build()?;

        assert!(writer.write_entry("test", b"a", b"a").is_ok());
        assert!(matches!(
            writer.write_entry("test", b"a", b"a"),
            Err(SclsError::NonStrictlyMonotonicKeys { .. })
        ));

        Ok(())
    }

    #[test]
    fn forbid_decreasing_keys() -> Result<()> {
        let buf = Vec::new();
        let mut writer = SclsWriter::builder().output(buf).slot_no(0).build()?;

        assert!(writer.write_entry("test", b"b", b"a").is_ok());
        assert!(matches!(
            writer.write_entry("test", b"a", b"a"),
            Err(SclsError::NonStrictlyMonotonicKeys { .. })
        ));

        Ok(())
    }

    #[test]
    fn key_order_resets_with_namespace() -> Result<()> {
        let buf = Vec::new();
        let mut writer = SclsWriter::builder().output(buf).slot_no(0).build()?;

        assert!(writer.write_entry("a", b"b", b"a").is_ok());
        assert!(writer.write_entry("b", b"a", b"a").is_ok());

        Ok(())
    }

    #[test]
    fn forbid_inconsistent_key_length_within_namespace() -> Result<()> {
        let buf = Vec::new();
        let mut writer = SclsWriter::builder().output(buf).slot_no(0).build()?;

        assert!(writer.write_entry("test", b"a", b"a").is_ok());
        assert!(matches!(
            writer.write_entry("test", b"foo", b"a"),
            Err(SclsError::InconsistentKeyLength { .. })
        ));

        Ok(())
    }

    #[test]
    fn chunk_size_below_threshold() -> Result<()> {
        let mut buf = Vec::new();
        let mut writer = SclsWriter::builder()
            .output(&mut buf)
            .slot_no(0)
            .max_chunk_size(12)
            .build()?;

        // Entry length: len_body(4) + key(1) + value(1) = 6 bytes
        writer.write_entry("test", b"a", b"a")?; // +6 bytes
        writer.write_entry("test", b"b", b"a")?; // +6 bytes

        // At threshold, no chunk should have been written
        let mut cursor = Cursor::new(buf.clone());
        assert!(matches!(
            Record::read_next(&mut cursor)?,
            Some(Record::Header(_))
        ));
        assert!(Record::read_next(&mut cursor)?.is_none());

        Ok(())
    }

    #[test]
    fn chunk_size_above_threshold() -> Result<()> {
        let key = b"a";
        let value = b"this is an oversized entry";

        let mut buf = Vec::new();
        let mut writer = SclsWriter::builder()
            .output(&mut buf)
            .slot_no(0)
            .max_chunk_size(12)
            .build()?;

        writer.write_entry("test", key, value)?; // +31 bytes
        writer.write_entry("test", b"b", b"a")?; // +6 bytes (to force flush)

        // We should have one chunk with the oversized record
        let mut cursor = Cursor::new(buf.clone());
        assert!(matches!(
            Record::read_next(&mut cursor)?,
            Some(Record::Header(_))
        ));
        let Some(Record::Chunk(chunk)) = Record::read_next(&mut cursor)? else {
            panic!("expected chunk");
        };
        assert!(Record::read_next(&mut cursor)?.is_none());

        chunk.for_each_entry(&mut cursor, |reader, key_len, val_len| {
            let entry = Entry::materialise(reader, key_len, val_len)?;
            assert_eq!(entry.key, key);
            assert_eq!(entry.value, value);

            Ok(())
        })?;

        Ok(())
    }

    // Strategy to generate valid (namespace, key, entry) sequences
    prop_compose! {
        fn valid_entry_writes()
            (
                // (Namespace, entry key) pairs will be correctly ordered in a BTreeSet.
                // The entry key is limited to one byte to side-step the fixed key length per
                // namespace constraint.
                pairs in proptest::collection::btree_set(("[a-z]+", any::<u8>()), 1..=20),
            )
            (
                values in proptest::collection::vec(
                    proptest::collection::vec(any::<u8>(), 0..=16usize),
                    pairs.len()..=pairs.len(),
                ),
                pairs in Just(pairs),
            )
        -> Vec<(String, Vec<u8>, Vec<u8>)> {
            pairs.into_iter()
                .zip(values)
                .map(|((ns, key), value)| (ns, vec![key], value))
                .collect()
        }
    }

    proptest! {
        #[test]
        fn chunk_roundtrip(entries in valid_entry_writes()) {
            let mut buf = Vec::new();
            let mut writer = SclsWriter::builder().output(&mut buf).slot_no(0).build()?;

            let mut written_by_ns: BTreeMap<String, Vec<Entry>> = BTreeMap::new();
            let mut read_by_ns: BTreeMap<String, Vec<Entry>> = BTreeMap::new();

            for (namespace, key, value) in &entries {
                // Group entries by namespace (correctly ordered)
                written_by_ns.entry(namespace.clone())
                    .or_default()
                    .push(Entry { key: key.clone(), value: value.clone() });

                writer.write_entry(namespace.as_str(), key, value)?;
            }

            // Flush the last chunk with a dummy namespace which is guaranteed to be monotonic (the
            // strategy generates namespaces that match /[a-z]+/ and CJK characters are way beyond
            // that range in Unicode). The chunk with this entry will never be flushed, by design.
            writer.write_entry("最终", b"a", b"a")?;

            let mut cursor = Cursor::new(buf.clone());
            let header_first = matches!(Record::read_next(&mut cursor)?, Some(Record::Header(_)));
            prop_assert!(header_first);

            let mut seqno = 0;

            while let Some(Record::Chunk(chunk)) = Record::read_next(&mut cursor)? {
                let mut cursor = Cursor::new(buf.clone());

                // Check ascending sequence number
                prop_assert_eq!(chunk.seqno, seqno);
                seqno += 1;

                // Verify chunk digest
                prop_assert!(chunk.verify(&mut cursor).is_ok());

                // Build up entries by namespace
                chunk.for_each_entry(&mut cursor, |reader, key_len, val_len| {
                    let namespace = chunk.namespace.clone();
                    let entry = Entry::materialise(reader, key_len, val_len)?;

                    read_by_ns.entry(namespace)
                        .or_default()
                        .push(entry);

                    Ok(())
                })?;
            }

            // Check namespace entries match
            prop_assert_eq!(read_by_ns, written_by_ns);
        }

        #[test]
        fn roundtrip_verification(entries in valid_entry_writes()) {
            let mut buf = Vec::new();
            let mut writer = SclsWriter::builder().output(&mut buf).slot_no(0).build()?;

            for (namespace, key, value) in &entries {
                writer.write_entry(namespace.as_str(), key, value)?;
            }
            writer.finalise()?;

            let cursor = Cursor::new(buf);
            let mut reader = SclsReader::new(cursor);
            prop_assert!(reader.verify(VerifyOptions::full()).is_ok());
        }
    }
}
