//! SCLS record sequence state machine.
//!
//! Note that, currently, we only validate the following record sequence defined in
//! [CIP-0165](https://github.com/cardano-foundation/CIPs/tree/master/CIP-0165). That is:
//!
//! ```ebnf
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

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use std::iter;
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
        offset: 0,
    });

    /// Strategy for generating valid record sequences.
    fn valid_sequence() -> impl Strategy<Value = Vec<Record>> {
        let chunk = &*DUMMY_CHUNK;
        prop::collection::vec(Just(chunk.clone()), 0..=5).prop_map(|chunks| {
            let mut seq = vec![DUMMY_HEADER];
            seq.extend(chunks);
            seq.push(DUMMY_MANIFEST);
            seq.push(Record::Eof);
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
                Record::Eof,
            ]),
            0..=10,
        )
        .prop_filter("sequence must be invalid", |seq| {
            let mut sequence = RecordSequence::new();
            seq.iter().any(|record| sequence.update(record).is_err())
                || sequence.update(&Record::Eof).is_err()
        })
    }

    proptest! {
        #[test]
        fn valid_record_sequence(records in valid_sequence()) {
            let mut sequence = RecordSequence::new();
            for record in records {
                prop_assert!(sequence.update(&record).is_ok());
            }
        }

        #[test]
        fn invalid_record_sequence(records in invalid_sequence()) {
            let mut sequence = RecordSequence::new();
            let mut current: Option<&Record> = None;

            let status = records
                .iter()
                .chain(iter::once(&Record::Eof)) // Always ensure there's an EOF
                .try_for_each(|record| {
                    current = Some(record);
                    sequence.update(record)
                });

            match status {
                Err(SclsError::UnexpectedEof { .. }) => {
                    prop_assert_eq!(current, Some(&Record::Eof))
                }

                Err(SclsError::UnexpectedRecord { .. }) => {
                    prop_assert_ne!(current, Some(&Record::Eof))
                }

                // These should never happen
                Err(e) => prop_assert!(false, "unexpected error: {e}"),
                Ok(()) => prop_assert!(false, "invalid sequence passed"),
            }
        }
    }
}
