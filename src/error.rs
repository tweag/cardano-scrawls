//! Error types for SCLS parsing and validation.

use crate::hash::Digest;

use thiserror::Error;

/// Errors that can occur when reading or writing SCLS files.
#[derive(Error, Debug)]
pub enum SclsError {
    /* Parsing errors ****************************************************************************/
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

    /// Truncated record length prefix
    #[error("truncated record length prefix")]
    TruncatedRecord,

    /// Unknown record type encountered
    #[error("unknown record type: 0x{0:02x}")]
    UnknownRecordType(u8),

    /* Record sequence verification errors *******************************************************/
    /// Unexpected record type found in stream
    #[error("unexpected record type: found {found}, expected {expected}")]
    UnexpectedRecord { found: String, expected: String },

    /// Unexpected EOF found in stream
    #[error("unexpected EOF: expected {expected}")]
    UnexpectedEof { expected: String },

    /* Structural verification errors ************************************************************/
    /// Record sequence number not increasing
    #[error("record sequence is not increasing: previous {previous}, found {found}")]
    SeqnoDisordered { previous: u64, found: u64 },

    /// Chunk namespaces not in bytewise ascending order
    #[error(
        "chunk namespaces are not in bytewise order: previous \"{previous}\", found \"{found}\""
    )]
    NamespaceDisordered { previous: String, found: String },

    /// Entry keys not in lexicographically ascending order
    ///
    /// Note: This check is not performed by default to avoid materialisation; see
    /// [`CheckStructure`](crate::reader::CheckStructure) and
    /// [`VerifyOptions::default`](crate::reader::VerifyOptions::default).
    #[error(
        "chunk {seqno} does not have entry keys in lexicographically ascending order over namespace {namespace}"
    )]
    KeysDisordered { namespace: String, seqno: u64 },

    /// Manifest namespace set differs from chunk namespaces
    #[error("mismatching namespace sets: in chunks {in_chunks:?}, in manifest {in_manifest:?}")]
    NamespaceMismatch {
        in_chunks: Vec<String>,
        in_manifest: Vec<String>,
    },

    /// Manifest namespace chunk counts differ
    #[error("mismatching chunk counts for {namespace}: expected {expected}, found {found}")]
    NamespaceChunkMismatch {
        namespace: String,
        expected: u64,
        found: u64,
    },

    /// Manifest namespace entry counts differ
    #[error("mismatching entry counts for {namespace}: expected {expected}, found {found}")]
    NamespaceEntryMismatch {
        namespace: String,
        expected: u64,
        found: u64,
    },

    /* Integrity verification errors *************************************************************/
    /// Chunk digest mismatch
    #[error("mismatching digest in chunk {seqno}: expected {expected}, computed {computed}")]
    ChunkDigestMismatch {
        seqno: u64,
        expected: Digest,
        computed: Digest,
    },

    /// Namespace root digest mismatch
    #[error(
        "mismatching namespace root digest for {namespace}: expected {expected}, computed {computed}"
    )]
    NamespaceDigestMismatch {
        namespace: String,
        expected: Digest,
        computed: Digest,
    },

    /// Global root digest mismatch
    #[error("mismatching global root digest: expected {expected}, computed {computed}")]
    GlobalDigestMismatch { expected: Digest, computed: Digest },

    /* Writer errors *****************************************************************************/
    /// Writer builder missing required output parameter
    #[error("writer builder is missing its required output parameter")]
    WriterBuilderMissingOutput,

    /// Writer builder missing required slot number parameter
    #[error("writer builder is missing its required slot number parameter")]
    WriterBuilderMissingSlotNo,

    /// Overflow error when writing to the wire format
    #[error("{0} length overflow in wire format")]
    WireLengthOverflow(String),

    /// Inconsistent entry key lengths within a namespace
    #[error("inconsistent entry key length in {namespace}: expected {expected}, found {found}")]
    InconsistentKeyLength {
        namespace: String,
        expected: usize,
        found: usize,
    },

    /// Attempted to write non-monotonic namespace
    ///
    /// Note, this is effectively equivalent to [`SclsError::NamespaceDisordered`]. We maintain the
    /// distinction because they occur under semantically distinct operations.
    #[error("Namespaces are not in bytewise order: previous \"{previous}\", found \"{found}\"")]
    NonMonotonicNamespace { previous: String, found: String },

    /// Attempted to write non-strictly monotonic entry key
    ///
    /// Note, this is similar to [`SclsError::KeysDisordered`]. We maintain the distinction because
    /// they occur under semantically distinct operations.
    #[error("Entry keys are not strictly lexicographically increasing in {namespace}")]
    NonStrictlyMonotonicKeys { namespace: String },

    /// Manifest offset does not match the on-wire record length
    #[error("Manifest offset should match the record length: expected {expected}, found {found}")]
    InconsistentManifestOffset { expected: u32, found: u32 },
}

/// Convenience type alias for Results with SclsError.
pub type Result<T> = std::result::Result<T, SclsError>;
