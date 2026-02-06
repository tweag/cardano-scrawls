//! SCLS manifest record.

use crate::types::Digest;

/// The manifest record (record type 0x01) containing file metadata and integrity information.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    /// Slot number this manifest refers to
    pub slot_no: u64,

    /// Total number of entries across all chunks
    pub total_entries: u64,

    /// Total number of chunks in the file
    pub total_chunks: u64,

    /// Merkle root hash of all live entries in the file
    pub root_hash: Digest,

    /// Per-namespace information
    pub namespace_info: Vec<NamespaceInfo>,

    /// Offset to previous manifest (for delta files), zero if none
    pub prev_manifest: u64,

    /// Summary metadata about file creation
    pub summary: Summary,
}

/// Information about a single namespace within the file
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamespaceInfo {
    /// Number of entries in this namespace
    pub entries_count: u8,

    /// Number of chunks for this namespace
    pub chunks_count: u64,

    /// Namespace identifier
    pub name: String,

    /// Merkle root of all live entries in this namespace
    pub digest: Digest,
}

/// Summary metadata about file creation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Summary {
    /// ISO8601 timestamp when file was created
    pub created_at: String,

    /// Name of the tool that generated the file
    pub tool: String,

    /// Optional comment
    pub comment: String,
}
