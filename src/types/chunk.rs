//! SCLS chunk records and entries.

use std::io::{Read, Seek, SeekFrom};
use std::ops::Range;

use crate::error::{Result, SclsError};
use crate::types::digest::HASH_SIZE;
use crate::types::merkle;
use crate::types::Digest;

use blake2b_simd::Params;

/// Maximum block size to feed the Blake2b hashing function.
const BLOCK_SIZE: usize = 8 * 1024; // 8 KiB

/// Compression format for chunk data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ChunkFormat {
    /// Raw uncompressed CBOR entries
    Raw = 0x00,

    /// All entries compressed as ZSTD
    Zstd = 0x01,

    /// Each entry value compressed independently
    ZstdPerEntry = 0x02,
}

impl ChunkFormat {
    /// Parses a chunk format from its byte representation.
    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0x00 => Some(Self::Raw),
            0x01 => Some(Self::Zstd),
            0x02 => Some(Self::ZstdPerEntry),
            _ => None,
        }
    }

    /// Returns the byte representation of this format.
    pub fn to_byte(self) -> u8 {
        self as u8
    }
}

impl TryFrom<u8> for ChunkFormat {
    type Error = SclsError;

    fn try_from(byte: u8) -> std::result::Result<Self, Self::Error> {
        Self::from_byte(byte).ok_or(SclsError::MalformedRecord(format!(
            "invalid chunk format: 0x{:02x}",
            byte
        )))
    }
}

/// A single key-value entry within a chunk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// Fixed-size key (length determined by chunk's key_len)
    pub key: Vec<u8>,

    /// CBOR-encoded value
    pub value: Vec<u8>,
}

impl Entry {
    /// Materialise an entry by reading the appropriate number of bytes for the key and value,
    /// respectively.
    ///
    /// The reader argument _should_ be at the correct position to begin without seeking and the
    /// wire format guarantees that the key and value payloads are juxtaposed.
    ///
    /// This is engineered to happen with and should be used in the closure argument of
    /// [`Chunk::for_each_entry`].
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Entry component size overflows
    /// - Memory allocation errors
    /// - I/O errors occur during reading
    pub fn materialise<R: Read>(reader: &mut R, key_len: u64, value_len: u64) -> Result<Self> {
        // Allocate the necessary space
        let key_len = usize::try_from(key_len)
            .map_err(|_| SclsError::MalformedRecord("entry key length overflow".into()))?;

        let mut key = Vec::new();
        key.try_reserve_exact(key_len).map_err(|_| {
            SclsError::MalformedRecord("out of memory: cannot materialise entry key".into())
        })?;
        key.resize(key_len, 0u8);

        let value_len = usize::try_from(value_len)
            .map_err(|_| SclsError::MalformedRecord("entry value length overflow".into()))?;

        let mut value = Vec::new();
        value.try_reserve_exact(value_len).map_err(|_| {
            SclsError::MalformedRecord("out of memory: cannot materialise entry value".into())
        })?;
        value.resize(value_len, 0u8);

        // Read the entry key
        if let Err(e) = reader.read_exact(&mut key) {
            return Err(e.into());
        }

        // Read the entry value
        if let Err(e) = reader.read_exact(&mut value) {
            return Err(e.into());
        }

        Ok(Self { key, value })
    }
}

/// Footer at the end of each chunk containing integrity information.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkFooter {
    /// Number of entries in the chunk
    pub entries_count: u32,

    /// Blake2b-224 hash of the chunk's entries
    pub digest: Digest,
}

/// A chunk record in the SCLS file.
///
/// Entry data can be iterated through with [`Chunk::for_each_entry`] and materialised with
/// [`Entry::materialise`], for example.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chunk {
    /// Sequential chunk number
    pub seqno: u64,

    /// Compression format
    pub format: ChunkFormat,

    /// Namespace these entries belong to
    pub namespace: String,

    /// Fixed key size for all entries in this chunk
    pub key_len: u32,

    /// Chunk footer with count and digest
    pub footer: ChunkFooter,

    /// Byte range where entry data is located
    entries_range: Range<u64>,
}

impl Chunk {
    /// Parses a chunk record directly from a reader, achieving true lazy loading.
    ///
    /// This method reads only the chunk header and footer from the reader, calculating the byte
    /// range where entries are located without ever loading entry data into memory.
    ///
    /// After this method returns, the reader position is unspecified (typically at the end of the
    /// footer). Callers should seek to a known position if they need to continue reading.
    ///
    /// # Arguments
    ///
    /// - `reader`: A seekable reader positioned at the start of the chunk payload (after the
    ///   record type byte)
    /// - `payload_start_offset`: Absolute file offset where the chunk payload begins
    /// - `payload_len`: Length of the chunk payload in bytes (excluding record type)
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The payload is too small (fewer than 49 bytes)
    /// - Byte offsets overflow
    /// - The chunk format is not recognised
    /// - The namespace length overruns the payload
    /// - The namespace is not valid UTF-8
    /// - I/O errors occur while reading
    pub fn parse<R: Read + Seek>(
        reader: &mut R,
        payload_start_offset: u64,
        payload_len: u32,
    ) -> Result<Self> {
        // Minimum payload size:
        // seqno(8) + format(1) + len_ns(4) + key_len(4) + entries_count(4) + digest(HASH_SIZE) = 21 + HASH_SIZE bytes
        if payload_len < 21 + HASH_SIZE as u32 {
            return Err(SclsError::MalformedRecord(format!(
                "chunk payload too short: {} bytes",
                payload_len
            )));
        }

        // Read seqno (8 bytes)
        let mut buf = [0u8; 8];
        reader.read_exact(&mut buf)?;
        let seqno = u64::from_be_bytes(buf);

        // Read format (1 byte)
        let mut format_buf = [0u8; 1];
        reader.read_exact(&mut format_buf)?;
        let format = ChunkFormat::from_byte(format_buf[0]).ok_or_else(|| {
            SclsError::MalformedRecord(format!("invalid chunk format: 0x{:02x}", format_buf[0]))
        })?;

        // Read namespace length (4 bytes)
        let mut len_ns_buf = [0u8; 4];
        reader.read_exact(&mut len_ns_buf)?;
        let len_ns = u32::from_be_bytes(len_ns_buf);

        // Header size so far: seqno(8) + format(1) + len_ns(4) = 13 bytes
        // Plus namespace and key_len(4) and footer(32)
        let header_fixed_size: u32 = 8 + 1 + 4 + 4; // 17 bytes without namespace
        let footer_size: u32 = 32;

        let min_size = header_fixed_size
            .checked_add(len_ns)
            .and_then(|s| s.checked_add(footer_size))
            .ok_or_else(|| SclsError::MalformedRecord("namespace length overflow".into()))?;

        if payload_len < min_size {
            return Err(SclsError::MalformedRecord(
                "chunk payload too short for namespace and footer".into(),
            ));
        }

        // Read namespace
        let mut ns_buf = vec![0u8; len_ns as usize];
        reader.read_exact(&mut ns_buf)?;
        let namespace = String::from_utf8(ns_buf)
            .map_err(|_| SclsError::MalformedRecord("invalid UTF-8 in namespace".into()))?;

        // Read key_len (4 bytes)
        let mut key_len_buf = [0u8; 4];
        reader.read_exact(&mut key_len_buf)?;
        let key_len = u32::from_be_bytes(key_len_buf);

        // Calculate header size: seqno(8) + format(1) + len_ns(4) + namespace + key_len(4)
        let header_size = header_fixed_size + len_ns; // 17 + len_ns

        // Calculate entries range
        // entries start right after header, end 32 bytes before payload end
        let entries_start = payload_start_offset
            .checked_add(header_size as u64)
            .ok_or_else(|| SclsError::MalformedRecord("offset overflow".into()))?;

        let entries_end = payload_start_offset
            .checked_add(payload_len as u64)
            .and_then(|end| end.checked_sub(footer_size as u64))
            .ok_or_else(|| SclsError::MalformedRecord("offset overflow".into()))?;

        // Seek to footer and read it
        let footer_offset = entries_end;
        reader.seek(SeekFrom::Start(footer_offset))?;

        let mut footer_buf = [0u8; 32];
        reader.read_exact(&mut footer_buf)?;

        let entries_count = u32::from_be_bytes(footer_buf[0..4].try_into().unwrap());
        let digest_bytes: [u8; HASH_SIZE] = footer_buf[4..32].try_into().unwrap();
        let digest = digest_bytes.into();

        let footer = ChunkFooter {
            entries_count,
            digest,
        };

        Ok(Chunk {
            seqno,
            format,
            namespace,
            key_len,
            footer,
            entries_range: entries_start..entries_end,
        })
    }

    /// Iterates over the entries in this chunk, invoking the closure for each one.
    ///
    /// The reader is seeked to the start of each entry's key before the closure is called. The
    /// closure receives the reader, the key length, and the value length in bytes. The value
    /// immediately follows the key in the stream. The closure may leave the reader at any
    /// position; it will be repositioned automatically before the next entry.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Seeking or reading from the reader fails
    /// - The entry data is structurally malformed (e.g. length prefix overflow,
    ///   entry extends beyond chunk bounds, entry count mismatches byte count)
    /// - The closure returns an error
    pub fn for_each_entry<R, F>(&self, reader: &mut R, mut f: F) -> Result<()>
    where
        R: Read + Seek,
        F: FnMut(
            &mut R, // reader
            u64,    // key length
            u64,    // value length
        ) -> Result<()>,
    {
        let mut remaining_bytes = self.entries_range.end - self.entries_range.start;
        let mut remaining_entries = self.footer.entries_count;

        let mut pos = self.entries_range.start;
        reader.seek(SeekFrom::Start(pos))?;

        loop {
            // Check if we've consumed all expected entries
            if remaining_entries == 0 {
                // Validate: no bytes should remain
                if remaining_bytes > 0 {
                    return Err(SclsError::MalformedRecord(format!(
                        "entry count exhausted, but {} bytes remain",
                        remaining_bytes
                    )));
                }
                break;
            }

            // Check we've consumed all the bytes
            if remaining_bytes == 0 {
                return Err(SclsError::MalformedRecord(format!(
                    "entry data exhausted, but {} entries expected",
                    remaining_entries
                )));
            }

            // Check we have enough bytes for the length prefix before reading
            if remaining_bytes < 4 {
                return Err(SclsError::MalformedRecord(format!(
                    "incomplete entry length prefix: {} bytes remaining",
                    remaining_bytes
                )));
            }

            // Read 4 byte length prefix
            let mut len_buf = [0u8; 4];
            if let Err(e) = reader.read_exact(&mut len_buf) {
                return Err(e.into());
            }
            let len_body = u32::from_be_bytes(len_buf);

            // Check we're not reading beyond our range
            let total_read = match 4u64.checked_add(len_body as u64) {
                None => {
                    return Err(SclsError::MalformedRecord(
                        "entry body length overflow".into(),
                    ));
                }

                Some(bytes) if bytes > remaining_bytes => {
                    return Err(SclsError::MalformedRecord(
                        "entry extends beyond chunk data".into(),
                    ));
                }

                Some(bytes) => bytes,
            };

            let key_len = self.key_len;

            // Body must be at least as large as the key
            if len_body < key_len {
                return Err(SclsError::MalformedRecord(format!(
                    "entry body too short for key: body {} bytes, key {} bytes",
                    len_body, self.key_len
                )));
            }

            let value_len = len_body - key_len;

            // Pass the key and value lengths to the closure
            f(reader, key_len as u64, value_len as u64)?;

            remaining_bytes -= total_read;
            remaining_entries -= 1;
            pos += total_read;

            // Seek to next entry, if necessary
            let current_pos = reader.stream_position()?;
            if current_pos != pos {
                reader.seek(SeekFrom::Start(pos))?;
            }
        }

        Ok(())
    }

    /// Verify the chunk digest from the entry digests.
    ///
    /// Convenience wrapper around [`Chunk::verify_and`], with a noop closure.
    ///
    /// # Errors
    /// Returns an error if:
    /// - Parsing or I/O failure
    /// - Digest mismatch
    pub fn verify<R: Read + Seek>(&self, reader: &mut R) -> Result<()> {
        self.verify_and(reader, |_, _, _, _| Ok(()))
    }

    /// Verify the chunk digest from the entry digests, invoking the closure for each entry.
    ///
    /// The reader is seeked to the start of each entry's key before the closure is called. The
    /// closure receives the entry's computed digest, the reader, the key length, and the value
    /// length in bytes. The value immediately follows the key in the stream. The closure may leave
    /// the reader at any position; it will be repositioned automatically before the next entry.
    ///
    /// - Each entry's digest is computed as `H(merkle::LEAF_PREFIX || ns_str || key || value)`.
    /// - The chunk digest is computed as `H(concat(digest(e) for e in entries))`.
    /// - `H` is the hashing function; viz. Blake2b-224.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Parsing or I/O failure
    /// - Digest mismatch
    pub fn verify_and<R, F>(&self, reader: &mut R, mut f: F) -> Result<()>
    where
        R: Read + Seek,
        F: FnMut(
            Digest, // entry digest
            &mut R, // reader
            u64,    // key length
            u64,    // value length
        ) -> Result<()>,
    {
        let mut chunk_hash_state = Params::new().hash_length(HASH_SIZE).to_state();

        self.for_each_entry(reader, |reader, key_len, value_len| {
            let pos = reader.stream_position()?;
            let mut entry_hash_state = Params::new().hash_length(HASH_SIZE).to_state();

            // Hash preamble
            entry_hash_state.update(&[merkle::LEAF_PREFIX]);
            entry_hash_state.update(self.namespace.as_bytes());

            // Entry hash
            let mut buffer = [0u8; BLOCK_SIZE];
            let mut remaining = key_len
                .checked_add(value_len)
                .ok_or_else(|| SclsError::MalformedRecord("entry length overflow".into()))?;

            while remaining > 0 {
                let to_read = (remaining as usize).min(BLOCK_SIZE);
                let buf = &mut buffer[..to_read];
                reader.read_exact(buf)?;

                entry_hash_state.update(buf);

                remaining -= to_read as u64;
            }

            // It's safe to unwrap here because we know our hash is HASH_SIZE bytes long
            let entry_hash: [u8; HASH_SIZE] =
                entry_hash_state.finalize().as_bytes().try_into().unwrap();

            // Update the chunk hash with the entry hash
            chunk_hash_state.update(&entry_hash);

            // Invoke the closure
            reader.seek(SeekFrom::Start(pos))?;
            f(Digest::new(entry_hash), reader, key_len, value_len)
        })?;

        // Again, this is safe to unwrap
        let chunk_hash: [u8; HASH_SIZE] =
            chunk_hash_state.finalize().as_bytes().try_into().unwrap();

        // Compare computed with expected chunk hashes
        let expected = self.footer.digest;
        let computed = Digest::from(chunk_hash);

        if expected != computed {
            return Err(SclsError::ChunkDigestMismatch {
                seqno: self.seqno,
                expected,
                computed,
            });
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use blake2b_simd::Params;
    use proptest::prelude::*;
    use rand::prelude::*;

    use super::*;

    const DUMMY_HASH: [u8; HASH_SIZE] = [0x00; HASH_SIZE];

    // Strategy to generate a single serialised entry, with its computed digest
    fn entry_bytes_with_digest(
        key_len: u32,
        namespace: String,
    ) -> impl Strategy<Value = (Vec<u8>, [u8; HASH_SIZE])> {
        let key_len = key_len as usize;

        (
            prop::collection::vec(any::<u8>(), key_len..=key_len), // Key
            prop::collection::vec(any::<u8>(), 0..100),            // Value
        )
            .prop_map(move |(key, value)| {
                let body_len = (key.len() + value.len()) as u32;
                let mut entry_bytes = body_len.to_be_bytes().to_vec();

                entry_bytes.extend_from_slice(&key);
                entry_bytes.extend_from_slice(&value);

                // Compute entry hash
                let hash_bytes: [u8; HASH_SIZE] = Params::new()
                    .hash_length(HASH_SIZE)
                    .to_state()
                    .update(&[merkle::LEAF_PREFIX])
                    .update(namespace.as_bytes())
                    .update(&key)
                    .update(&value)
                    .finalize()
                    .as_bytes()
                    .try_into()
                    .unwrap();

                (entry_bytes, hash_bytes)
            })
    }

    // Strategy to generate multiple entries, with the computed chunk digest
    fn entries_data_with_chunk_digest(
        key_len: u32,
        namespace: String,
        num_entries: usize,
    ) -> impl Strategy<Value = (Vec<u8>, [u8; HASH_SIZE])> {
        prop::collection::vec(
            entry_bytes_with_digest(key_len, namespace),
            num_entries..=num_entries,
        )
        .prop_map(|entries| {
            let mut hash_state = Params::new().hash_length(HASH_SIZE).to_state();
            let mut all_bytes = Vec::new();

            for (entry_bytes, entry_hash) in entries {
                all_bytes.extend_from_slice(&entry_bytes);
                hash_state.update(&entry_hash);
            }

            let chunk_hash: [u8; HASH_SIZE] = hash_state.finalize().as_bytes().try_into().unwrap();

            (all_bytes, chunk_hash)
        })
    }

    // Strategy to generate all the necessary raw parameters for creating test chunks
    // This is exposed as a primitive so we can mutate correct serialisations to elicit failures
    prop_compose! {
        fn chunk_params(min_entries: usize, max_entries: usize)
            (key_len in 1u32..=64, namespace in ".+", num_entries in min_entries..=max_entries)
            (
                entry_data in entries_data_with_chunk_digest(
                    key_len,
                    namespace.clone(),
                    num_entries
                ),
                key_len in Just(key_len),
                namespace in Just(namespace),
                num_entries in Just(num_entries),
            )
        -> (u32, String, usize, Vec<u8>, [u8; HASH_SIZE]) {
            let (bytes, hash) = entry_data;
            (key_len, namespace, num_entries, bytes, hash)
        }
    }

    // Build a minimal valid chunk payload, with a correctly computed chunk digest, wrapping
    // `entry_data`, then parse it into a `Chunk`. The returned cursor is positioned at an
    // unspecified location; `for_each_entry` will seek as needed.
    fn make_chunk(
        key_len: u32,
        namespace: &[u8],
        num_entries: u32,
        entry_data: Vec<u8>,
        chunk_hash: &[u8; HASH_SIZE],
    ) -> (Chunk, Cursor<Vec<u8>>) {
        let len_ns: u32 = namespace.len() as u32;

        let mut payload = Vec::new();
        payload.extend_from_slice(&0u64.to_be_bytes()); // seqno
        payload.push(0x00); // format (Raw)
        payload.extend_from_slice(&len_ns.to_be_bytes()); // len_ns
        payload.extend_from_slice(namespace); // namespace
        payload.extend_from_slice(&key_len.to_be_bytes()); // key_len
        payload.extend_from_slice(&entry_data); // entries
        payload.extend_from_slice(&num_entries.to_be_bytes()); // footer: entries_count
        payload.extend_from_slice(chunk_hash); // footer: chunk_hash

        let payload_len = payload.len() as u32;
        let mut cursor = Cursor::new(payload);
        let chunk = Chunk::parse(&mut cursor, 0, payload_len).unwrap();

        (chunk, cursor)
    }

    // Strategy for generating valid [`Chunk`]s with a cursor into their serialised form
    prop_compose! {
        fn valid_chunks(min_entries: usize, max_entries: usize)
            (params in chunk_params(min_entries, max_entries))
        -> (Chunk, Cursor<Vec<u8>>) {
            let (key_len, namespace, num_entries, entry_data, chunk_hash) = params;

            make_chunk(
                key_len,
                namespace.as_bytes(),
                num_entries as u32,
                entry_data,
                &chunk_hash,
            )
        }
    }

    proptest! {
        #[test]
        fn parse_entries_count_matches((chunk, mut cursor) in valid_chunks(0, 10)) {
            let mut count = 0usize;
            chunk.for_each_entry(&mut cursor, |_reader, _key_len, _val_len| {
                count += 1;
                Ok(())
            })?;

            prop_assert_eq!(count, chunk.footer.entries_count as usize);
        }

        #[test]
        fn parse_entries_keys_correct_length((chunk, mut cursor) in valid_chunks(1, 10)) {
            let mut entries: Vec<Entry> = Vec::new();
            chunk.for_each_entry(&mut cursor, |reader, kl, vl| {
                entries.push(Entry::materialise(reader, kl, vl)?);
                Ok(())
            })?;

            for entry in &entries {
                prop_assert_eq!(entry.key.len(), chunk.key_len as usize);
            }
        }

        #[test]
        fn parse_entries_rejects_truncated_length(key_len in 1u32..=64) {
            // Only 2 bytes instead of 4 for length prefix
            let data = vec![0x00, 0x01];
            let (chunk, mut cursor) = make_chunk(key_len, b"test", 1, data, &DUMMY_HASH);

            let result = chunk.for_each_entry(&mut cursor, |_reader, _kl, _vl| Ok(()));
            prop_assert!(result.is_err());
        }

        #[test]
        fn parse_entries_rejects_body_too_short_for_key(key_len in 4u32..=64) {
            // Claim body is 2 bytes, but key_len is larger
            let mut data = 2u32.to_be_bytes().to_vec();
            data.extend_from_slice(&[0xff, 0xff]);

            let (chunk, mut cursor) = make_chunk(key_len, b"test", 1, data, &DUMMY_HASH);

            let result = chunk.for_each_entry(&mut cursor, |_reader, _kl, _vl| Ok(()));
            prop_assert!(result.is_err());
        }

        #[test]
        fn verify_valid_chunk_digests((chunk, mut cursor) in valid_chunks(0, 10)) {
            let verified = chunk.verify(&mut cursor);
            prop_assert!(verified.is_ok());
        }

        #[test]
        fn catch_corrupted_digest_in_footer(params in chunk_params(0, 10)) {
            let (key_len, namespace, num_entries, entry_data, chunk_hash) = params;

            // Corrupt the chunk digest
            let mut rng = rand::rng();
            let mut corrupted_hash = chunk_hash;
            let idx = rng.random_range(0..HASH_SIZE);
            let mask = rng.random_range(1u8..=255);
            corrupted_hash[idx] ^= mask;

            let (chunk, mut cursor) = make_chunk(
                key_len,
                namespace.as_bytes(),
                num_entries as u32,
                entry_data,
                &corrupted_hash,
            );

            let verified = chunk.verify(&mut cursor);
            prop_assert!(verified.is_err());

            if let Err(SclsError::ChunkDigestMismatch { expected, computed, .. }) = verified {
                prop_assert_eq!(expected.as_bytes(), corrupted_hash);
                prop_assert_eq!(computed.as_bytes(), chunk_hash);
            }
        }

        #[test]
        fn catch_corrupted_entry(params in chunk_params(1, 10)) {
            let (key_len, namespace, num_entries, entry_data, chunk_hash) = params;

            // Corrupt the first entry data
            let mut rng = rand::rng();
            let mut corrupted_entries = entry_data.clone();
            let first_entry_len = {
                let bytes: [u8; 4] = corrupted_entries[..4].try_into().unwrap();
                u32::from_be_bytes(bytes)
            };
            let idx = rng.random_range(4..4 + first_entry_len as usize);
            let mask = rng.random_range(1u8..=255);
            corrupted_entries[idx] ^= mask;

            let (chunk, mut cursor) = make_chunk(
                key_len,
                namespace.as_bytes(),
                num_entries as u32,
                corrupted_entries,
                &chunk_hash,
            );

            let verified = chunk.verify(&mut cursor);
            prop_assert!(verified.is_err());

            if let Err(SclsError::ChunkDigestMismatch { expected, computed, .. }) = verified {
                prop_assert_eq!(expected.as_bytes(), chunk_hash);
                prop_assert_ne!(expected, computed);
            }
        }
    }
}
