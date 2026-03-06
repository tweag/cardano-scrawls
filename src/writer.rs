//! SCLS file writing.

use std::collections::BTreeMap;
use std::io::Write;

use crate::error::{Result, SclsError};
use crate::hash::{Blake2b, MerkleTree};
use crate::records::Header;

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

    /// Chunk digest
    digest: Blake2b,

    /// Number of entries in the chunk
    entries: u32,
}

impl ChunkState {
    fn new() -> Self {
        Self {
            payload: Vec::new(),
            digest: Blake2b::new_raw(),
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
    /// - TODO
    pub fn write_entry(&mut self, namespace: &str, key: &[u8], value: &[u8]) -> Result<()> {
        // SclsWriter::write_entry - namespace, key, value
        // - [ ] Check namespace:
        //   - [ ] Previous None =>
        //     - [ ] Set previous namespace
        //     - [ ] Create new ns_state
        //   - [ ] Check monotonicity if changed:
        //     - [ ] OK =>
        //       - [ ] Flush chunk (must exist)
        //       - [ ] Update previous namespace
        //       - [ ] Reset previous key
        //       - [ ] Create new ns_state
        //     - [ ] Fail => Error
        // - [ ] Check entry key
        //   - [ ] Previous None =>
        //     - [ ] Set previous key
        //   - Check strict monotonicity:
        //     - [ ] OK => Update previous key
        //     - [ ] Fail => Error
        // - [ ] Is previous chunk, if it exists, oversized => Flush chunk
        // - [ ] Is current chunk None => Create new chunk
        // - [x] Update chunk
        //
        // SclsWriter::update_chunk - namespace, key, value
        // - [x] Compute entry digest
        // - [x] Update chunk digest accumulator
        // - [x] Add leaf to namespace Merkle tree
        // - [x] Serialise entry into chunk buffer
        //
        // ChunkState::write - writer (SclsWriter.output), seqno (SclsWriter.chunk_seqno), namespace (SclsWriter.prev_namespace)
        // OR SclsWriter::flush_chunk - chunk state [cleaner]
        // - [ ] Discharge chunk wire format to writer
        // - [ ] Increment chunk_seqno
        // - [ ] Update ns_state[namespace].{chunks, entries}
        // - [ ] Reset current_chunk to None
        //
        //  NOTE: Finalise will have to call flush_chunk to empty what's left in the buffer

        self.update_chunk(key, value)
    }

    /// Update the chunk that is currently being built with the next entry.
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
                let key_len = u32::try_from(key.len()).map_err(|_| SclsError::EntryOverflow)?;
                ns_state.key_len = Some(key_len);
            }
        };

        // Compute entry digest
        let entry_digest = Blake2b::new_leaf()
            .update(namespace.as_bytes())
            .update(key)
            .update(value)
            .as_digest();

        // Update chunk digest and namespace Merkle tree
        chunk.digest.update(entry_digest.as_bytes());
        ns_state.merkle.add_leaf(entry_digest);

        // Serialise entry
        let entry_len = u32::try_from(
            key.len()
                .checked_add(value.len())
                .ok_or(SclsError::EntryOverflow)?,
        )
        .map_err(|_| SclsError::EntryOverflow)?;

        chunk.entries += 1;
        chunk.payload.extend_from_slice(&entry_len.to_be_bytes());
        chunk.payload.extend_from_slice(key);
        chunk.payload.extend_from_slice(value);

        Ok(())
    }

    // TODO: Flush chunk
    // len_record (4) = 1 + 8 + 1 + 4 + len_ns + 4 + len(entries) + 4 + 28
    // type byte (1)
    // seqno (8)
    // format (1)
    // len_ns (4)
    // namespace (len_ns)
    // len_key (4)
    // entries payload
    // entries_count (4)
    // digest (28)

    /// Finalise the SCLS output.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - TODO
    pub fn finalise(self) -> Result<()> {
        todo!()
    }
}
