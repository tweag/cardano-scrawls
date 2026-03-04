//! SCLS record sequence state machine.
//!
//! Note that, currently, we only validate the following record sequence defined in
//! [CIP-0165](https://github.com/cardano-foundation/CIPs/tree/master/CIP-0165). That is:
//!
//! ```
//! HDR CHUNK* MANIFEST
//! ```

use super::Record;
use crate::error::{Result, SclsError};

/// Record sequence state machine expectation states.
enum Expect {
    Header,
    ChunkOrManifest,
    Eof,
}

/// SCLS record sequence state machine.
pub(super) struct RecordSequence(Expect);

impl RecordSequence {
    /// Create a new record sequence state machine ready for a new SCLS file.
    pub fn new() -> Self {
        Self(Expect::Header)
    }

    /// Update the record sequence state machine with the next consumed record type.
    ///
    /// Note that unknown records will be skipped over.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The next record is unexpected
    /// - The end of the file is reached unexpectedly
    pub fn update(&mut self, next: &Record) -> Result<()> {
        match (&self.0, next) {
            // Skip unknown records
            (_, Record::Unknown { .. }) => {}

            (Expect::Header, Record::Header(_)) => self.0 = Expect::ChunkOrManifest,

            (Expect::Header, Record::Eof) => {
                return Err(SclsError::UnexpectedEof {
                    expected: "HEADER".into(),
                });
            }

            (Expect::Header, record) => {
                return Err(SclsError::UnexpectedRecord {
                    expected: "HEADER".into(),
                    found: name(record),
                });
            }

            (Expect::ChunkOrManifest, Record::Chunk(_)) => {}

            (Expect::ChunkOrManifest, Record::Manifest(_)) => self.0 = Expect::Eof,

            (Expect::ChunkOrManifest, Record::Eof) => {
                return Err(SclsError::UnexpectedEof {
                    expected: "CHUNK or MANIFEST".into(),
                });
            }

            (Expect::ChunkOrManifest, record) => {
                return Err(SclsError::UnexpectedRecord {
                    expected: "CHUNK or MANIFEST".into(),
                    found: name(record),
                });
            }

            (Expect::Eof, Record::Eof) => {}

            (Expect::Eof, record) => {
                return Err(SclsError::UnexpectedRecord {
                    expected: "EOF".into(),
                    found: name(record),
                });
            }
        };

        Ok(())
    }
}

impl Default for RecordSequence {
    fn default() -> Self {
        Self::new()
    }
}

/// Simple record naming stringification.
fn name(record: &Record) -> String {
    match record {
        Record::Header(_) => "HEADER".into(),
        Record::Chunk(_) => "CHUNK".into(),
        Record::Manifest(_) => "MANIFEST".into(),

        // These should never happen
        Record::Unknown { record_type, .. } => format!("UNKNOWN 0x{record_type:02x}"),
        Record::Eof => "EOF".into(),
    }
}
