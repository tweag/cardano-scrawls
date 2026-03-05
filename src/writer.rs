//! SCLS file writing.

use std::io::Write;

use crate::error::{Result, SclsError};

/// Default tool name.
pub const DEFAULT_TOOL: &str = "cardano-scrawls";

/// Default maximum chunk size (modulo pathologically large entries)
pub const DEFAULT_MAX_CHUNK_SIZE: usize = 16 * 1024 * 1024; // 16 MiB

/// SclsWriter builder.
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

    /// Build an [`SclsWriter`] given the current parameters.
    ///
    /// # Errors
    ///
    /// Returns an error if any required parameters have been omitted.
    pub fn build(self) -> Result<SclsWriter<W>> {
        let output = self.output.ok_or(SclsError::WriterBuilderMissingOutput)?;
        let slot_no = self.slot_no.ok_or(SclsError::WriterBuilderMissingSlotNo)?;

        let writer = SclsWriter {
            output,
            slot_no,
            tool: self.tool,
            comment: self.comment,
            max_chunk_size: self.max_chunk_size,
            prev_namespace: None,
            prev_ns_entry_key: None,
        };

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

/// A writer for SCLS files.
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

    /// Previously written namespace
    prev_namespace: Option<String>,

    /// Previously written namespace entry key
    // NOTE Reset this to `None` when `prev_namespace` changes
    prev_ns_entry_key: Option<Vec<u8>>,
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
        todo!()
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
