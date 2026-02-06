//! SCLS file header record.

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
        self.version == 1 // For now
    }
}
