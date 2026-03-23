//! SCLS record sequence state machine.
//!
//! Note that, currently, we only validate the following record sequence defined in
//! [CIP-0165](https://github.com/cardano-foundation/CIPs/tree/master/CIP-0165). That is:
//!
//! ```ebnf
//! HDR CHUNK* MANIFEST
//! ```

use std::fmt::Display;

use super::Record;
use crate::error::{Result, SclsError};

/// Record sequence state machine expectation states.
#[derive(PartialEq, Eq)]
enum Expect {
    Header,
    ChunkOrManifest,
    Eof,
}

impl Display for Expect {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Header => "HDR",
                Self::ChunkOrManifest => "CHUNK or MANIFEST",
                Self::Eof => "end of file",
            }
        )
    }
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
    /// Note that unknown records will be skipped over, for now. This _may_ change in a future
    /// release.
    ///
    /// # Errors
    ///
    /// Returns an error if the next record is unexpected.
    pub fn update(&mut self, state: &Record) -> Result<()> {
        let expected = &self.0;

        match (expected, state) {
            // Skip unknown records (for now)
            (_, Record::Unknown { .. }) => {}

            (Expect::Header, Record::Header(_)) => self.0 = Expect::ChunkOrManifest,

            (Expect::Header, record) => {
                return Err(SclsError::UnexpectedRecord {
                    expected: expected.to_string(),
                    found: record.to_string(),
                });
            }

            (Expect::ChunkOrManifest, Record::Chunk(_)) => {}

            (Expect::ChunkOrManifest, Record::Manifest(_)) => self.0 = Expect::Eof,

            (Expect::ChunkOrManifest, record) => {
                return Err(SclsError::UnexpectedRecord {
                    expected: expected.to_string(),
                    found: record.to_string(),
                });
            }

            (Expect::Eof, record) => {
                return Err(SclsError::UnexpectedRecord {
                    expected: expected.to_string(),
                    found: record.to_string(),
                });
            }
        };

        Ok(())
    }

    /// Terminate the state machine.
    ///
    /// # Errors
    ///
    /// Return an error if the end of the file is reached unexpectedly.
    pub fn finalise(&self) -> Result<()> {
        if self.0 != Expect::Eof {
            return Err(SclsError::UnexpectedEof {
                expected: self.0.to_string(),
            });
        }

        Ok(())
    }
}

impl Default for RecordSequence {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use std::sync::LazyLock;

    use proptest::prelude::*;

    use crate::error::SclsError;
    use crate::hash::{Digest, HASH_SIZE};
    use crate::records::{Chunk, Header, Manifest, Summary};

    use super::*;

    const DUMMY_DIGEST: Digest = Digest::new([0x00; HASH_SIZE]);

    const DUMMY_HEADER: Record = Record::Header(Header::current());

    static DUMMY_CHUNK: LazyLock<Record> = LazyLock::new(|| {
        let mut payload = Vec::new();
        payload.extend_from_slice(&0u64.to_be_bytes());
        payload.push(0x00); // Raw format
        payload.extend_from_slice(&4u32.to_be_bytes()); // namespace len
        payload.extend_from_slice(b"test"); // namespace
        payload.extend_from_slice(&1u32.to_be_bytes()); // key_len
        payload.extend_from_slice(&0u32.to_be_bytes()); // footer: entries_count
        payload.extend_from_slice(DUMMY_DIGEST.as_bytes()); // footer: digest

        let payload_len = payload.len() as u32;
        let mut cursor = Cursor::new(payload);
        let chunk = Chunk::parse(&mut cursor, 0, payload_len).unwrap();

        Record::Chunk(chunk)
    });

    const DUMMY_MANIFEST: Record = Record::Manifest(Manifest {
        slot_no: 0,
        total_entries: 0,
        total_chunks: 0,
        root_hash: DUMMY_DIGEST,
        namespace_info: Vec::new(),
        prev_manifest: 0,
        summary: Summary {
            created_at: String::new(),
            tool: String::new(),
            comment: None,
        },
    });

    /// Strategy for generating valid record sequences.
    fn valid_sequence() -> impl Strategy<Value = Vec<Record>> {
        let chunk = &*DUMMY_CHUNK;

        prop::collection::vec(Just(chunk.clone()), 0..=5).prop_map(|chunks| {
            let mut seq = vec![DUMMY_HEADER];
            seq.extend(chunks);
            seq.push(DUMMY_MANIFEST);
            seq
        })
    }

    /// Strategy for generating invalid record sequences.
    fn invalid_sequence() -> impl Strategy<Value = Vec<Record>> {
        prop::collection::vec(
            prop::sample::select(vec![
                DUMMY_HEADER,
                DUMMY_CHUNK.clone(),
                DUMMY_MANIFEST,
                Record::Unknown {
                    record_type: 0xff,
                    data: vec![],
                },
            ]),
            0..=10,
        )
        .prop_filter("sequence must be invalid", |seq| {
            let mut sequence = RecordSequence::new();
            seq.iter().any(|record| sequence.update(record).is_err())
                || sequence.finalise().is_err()
        })
    }

    proptest! {
        #[test]
        fn valid_record_sequence(records in valid_sequence()) {
            let mut sequence = RecordSequence::new();

            for record in records {
                prop_assert!(sequence.update(&record).is_ok());
            }
            prop_assert!(sequence.finalise().is_ok());
        }

        #[test]
        fn invalid_record_sequence(records in invalid_sequence()) {
            let mut sequence = RecordSequence::new();

            let status = records
                .iter()
                .try_for_each(|record| sequence.update(record));

            match status {
                // If the record sequence is fine, check finalisation correctly fails
                Ok(()) => prop_assert!(sequence.finalise().is_err()),

                // Out of order records are expected
                Err(SclsError::UnexpectedRecord { .. }) => {}

                // This should never happen
                Err(e) => prop_assert!(false, "unexpected error: {e}"),
            }
        }
    }
}
