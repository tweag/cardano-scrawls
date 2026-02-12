//! SCLS file header record.

use crate::error::{Result, SclsError};

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
    fn try_from(value: &[u8]) -> Result<Self> {
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
        // NOTE Version checking is left to the caller (there's only one version atm)
        let version_bytes: [u8; 4] = value[4..8].try_into().unwrap();
        let version = u32::from_be_bytes(version_bytes);

        Ok(Self::new(version))
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    proptest! {
        #[test]
        fn rejects_wrong_length(bytes in prop::collection::vec(any::<u8>(),0..100)) {
            // Skip the valid case
            prop_assume!(bytes.len() != 8);

            let result = Header::try_from(bytes.as_slice());
            prop_assert!(result.is_err());
        }

        #[test]
        fn rejects_wrong_magic(
            wrong_magic in prop::collection::vec(any::<u8>(), 4..=4),
            version_bytes in prop::array::uniform4(any::<u8>())
        ) {
            // Skip the valid case
            prop_assume!(wrong_magic.as_slice() != b"SCLS");

            let mut bytes = wrong_magic;
            bytes.extend_from_slice(&version_bytes);

            let result = Header::try_from(bytes.as_slice());
            let is_invalid_magic = matches!(result, Err(SclsError::InvalidMagic { .. }));
            prop_assert!(is_invalid_magic);
        }

        #[test]
        fn accepts_any_valid_version(version in any::<u32>()) {
            let mut bytes = b"SCLS".to_vec();
            bytes.extend_from_slice(&version.to_be_bytes());

            let result = Header::try_from(bytes.as_slice());
            prop_assert!(result.is_ok());
            prop_assert_eq!(result.unwrap().version, version);
        }
    }
}
