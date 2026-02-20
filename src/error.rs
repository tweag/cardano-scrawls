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

    /// Digest mismatch
    #[error("mismatching hash digests: expected {expected}, computed {computed}")]
    DigestMismatch { expected: Digest, computed: Digest },

    /// Unknown record type encountered
    #[error("unknown record type: 0x{0:02x}")]
    UnknownRecordType(u8),
}

/// Convenience type alias for Results with SclsError.
pub type Result<T> = std::result::Result<T, SclsError>;
