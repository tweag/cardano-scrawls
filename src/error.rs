//! Error types for SCLS parsing and validation.

use crate::types::Digest;

use thiserror::Error;

/// Errors that can occur when reading or writing SCLS files.
#[derive(Error, Debug)]
pub enum SclsError {
    /// Invalid magic bytes in header
    #[error("invalid magic bytes: expected 'SCLS', found {found:?}")]
    InvalidMagic { found: Vec<u8> },

    /// Unsupported file format version
    #[error("unsupported version: {0}")]
    UnsupportedVersion(u32),

    /// I/O error during reading or writing
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Malformed record structure
    #[error("malformed record: {0}")]
    MalformedRecord(String),

    /// Structural: Record sequence number not increasing
    #[error("record sequence is not increasing: previous {previous}, found {found}")]
    SeqnoDisordered { previous: u64, found: u64 },

    /// Structural: Chunk namespaces not in bytewise ascending order
    #[error(
        "chunk namespaces are not in bytewise order: previous \"{previous}\", found \"{found}\""
    )]
    NamespaceDisordered { previous: String, found: String },

    /// Structural: Entry keys not in lexicographically ascending order
    ///
    /// Note: This check is not performed by default to avoid materialisation; see
    /// [`CheckStructure`](crate::reader::CheckStructure) and
    /// [`VerifyOptions::default`](crate::reader::VerifyOptions::default).
    #[error(
        "chunk {seqno} does not have entry keys in lexicographically ascending order over namespace {namespace}"
    )]
    KeysDisordered { namespace: String, seqno: u64 },

    /// Structural: Manifest namespace set differs from chunk namespaces
    #[error("mismatching namespace sets: in chunks {in_chunks:?}, in manifest {in_manifest:?}")]
    NamespaceMismatch {
        in_chunks: Vec<String>,
        in_manifest: Vec<String>,
    },

    /// Integrity: Chunk digest mismatch
    #[error("mismatching digest in chunk {seqno}: expected {expected}, computed {computed}")]
    ChunkDigestMismatch {
        seqno: u64,
        expected: Digest,
        computed: Digest,
    },

    /// Integrity: Namespace root digest mismatch
    #[error(
        "mismatching namespace root digest for {namespace}: expected {expected}, computed {computed}"
    )]
    NamespaceDigestMismatch {
        namespace: String,
        expected: Digest,
        computed: Digest,
    },

    /// Integrity: Global root digest mismatch
    #[error("mismatching global root digest: expected {expected}, computed {computed}")]
    GlobalDigestMismatch { expected: Digest, computed: Digest },

    /// Unknown record type encountered
    #[error("unknown record type: 0x{0:02x}")]
    UnknownRecordType(u8),
}

/// Convenience type alias for Results with SclsError.
pub type Result<T> = std::result::Result<T, SclsError>;
