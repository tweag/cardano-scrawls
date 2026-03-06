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
        //  - [ ] Check entry key
        //    - [ ] Previous None =>
        //      - [ ] Set previous key
        //    - Check strict monotonicity:
        //      - [ ] OK => Update previous key
        //      - [ ] Fail => Error
        //  - [ ] Is previous chunk, if it exists, oversized => Flush chunk
        //  - [ ] Is current chunk None => Create new chunk
        //  - [ ] Build chunk
        //
        //  SclsWriter::build_chunk - namespace, key, value
        //  - [ ] Compute entry digest
        //  - [ ] Update chunk digest accumulator
        //  - [ ] Add leaf to namespace Merkle tree
        //  - [ ] Serialise entry into chunk buffer
        //
        //  NOTE: Finalise will have to call build_chunk to empty what's left in the buffer
        //
        // ChunkState::write - writer (SclsWriter.output), seqno (SclsWriter.chunk_seqno), namespace (SclsWriter.prev_namespace)
        // OR SclsWriter::flush_chunk - chunk state [cleaner]
        // - [ ] Discharge chunk wire format to writer
        // - [ ] Increment chunk_seqno
        // - [ ] Update ns_state[namespace].{chunks, entries}
        // - [ ] Reset current_chunk to None
        Ok(())
    }

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
