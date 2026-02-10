//! SCLS file header record.

use std::result::Result;

use crate::error::SclsError;

/// The SCLS file header (record type 0x00)
///
/// Contains magic bytes for file identification and version information.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// File format version number
    pub version: u32,
}

impl Header {
    /// Magic bytes that identify an SCLS file
    pub const MAGIC: &'static [u8; 4] = b"SCLS";

    /// Current supported version that this library writes
    pub const CURRENT_VERSION: u32 = 1;

    /// Creates a new header with the specified version.
    pub const fn new(version: u32) -> Self {
        Self { version }
    }

    /// Creates a header with the current supported version.
    pub const fn current() -> Self {
        Self::new(Self::CURRENT_VERSION)
    }

    /// Checks if this version is supported for reading.
    pub fn is_supported(&self) -> bool {
        self.version == Self::CURRENT_VERSION // For now
    }
}

impl TryFrom<&[u8]> for Header {
    type Error = SclsError;

    /// Parses a header record from its payload.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The payload is not exactly 8 bytes
    /// - The magic bytes are not "SCLS"
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        // Header size: magic(4) + version(4) = 8 bytes
        if value.len() != 8 {
            return Err(SclsError::MalformedRecord(format!(
                "header must be exactly 8 bytes, found {}",
                value.len()
            )));
        }

        // Check magic bytes
        let magic = &value[0..4];
        if magic != Header::MAGIC {
            return Err(SclsError::InvalidMagic {
                found: magic.to_vec(),
            });
        }

        // Parse version (big-endian u32)
        // NOTE unwrap is safe because we already checked for length
        let version_bytes: [u8; 4] = value[4..8].try_into().unwrap();
        let version = u32::from_be_bytes(version_bytes);

        Ok(Self::new(version))
    }
}
