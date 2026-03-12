//! SCLS manifest record.

use std::io::Write;
use std::str;

use crate::error::{Result, SclsError};
use crate::hash::{Digest, HASH_SIZE};
use crate::records::RecordType;

/// The manifest record (record type 0x01) containing file metadata and integrity information.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    /// Slot number this manifest refers to
    pub slot_no: u64,

    /// Total number of entries across all chunks
    pub total_entries: u64,

    /// Total number of chunks in the file
    pub total_chunks: u64,

    /// Merkle root hash of all live entries in the file
    pub root_hash: Digest,

    /// Per-namespace information
    pub namespace_info: Vec<NamespaceInfo>,

    /// Offset to previous manifest (for delta files), zero if none
    pub prev_manifest: u64,

    /// Summary metadata about file creation
    pub summary: Summary,
}

impl Manifest {
    /// Write the manifest record to the writer stream.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - There is an I/O failure
    /// - The manifest offset differs from the record length
    pub fn write(&self, writer: &mut impl Write) -> Result<()> {
        let mut buf = Vec::new();
        let len = self.offset()?;

        buf.write_all(&[RecordType::Manifest.to_byte()])?;
        buf.write_all(&self.slot_no.to_be_bytes())?;
        buf.write_all(&self.total_entries.to_be_bytes())?;
        buf.write_all(&self.total_chunks.to_be_bytes())?;
        buf.write_all(&self.summary.to_bytes()?)?;

        for ns_info in &self.namespace_info {
            buf.write_all(&ns_info.to_bytes()?)?;
        }
        buf.write_all(&0u32.to_be_bytes())?; // sentinel

        buf.write_all(&self.prev_manifest.to_be_bytes())?;
        buf.write_all(self.root_hash.as_bytes())?;
        buf.write_all(&len.to_be_bytes())?;

        // Record length should equal offset
        if buf.len() != self.offset()? as usize {
            return Err(SclsError::InconsistentManifestOffset {
                expected: buf.len() as u32,
                found: len,
            });
        }

        writer.write_all(&len.to_be_bytes())?;
        writer.write_all(&buf)?;

        Ok(())
    }

    /// Compute the relative offset (wire length) to the beginning of this record. This can be used
    /// to find the manifest by reading the last 4 bytes of a non-amended SCLS file.
    ///
    /// # Errors
    ///
    /// Return an error if the manifest payload overflows.
    pub fn offset(&self) -> Result<u32> {
        // Length prefixed (u32) UTF-8 strings
        let created_at_len = 4 + self.summary.created_at.len();
        let tool_len = 4 + self.summary.tool.len();
        let comment_len = 4 + self.summary.comment.as_ref().map_or(0, String::len);

        let ns_info_len = self.namespace_info.iter().fold(0usize, |acc, ns_info| {
            // Namespace info wire length:
            // len_ns(4) + entries(8) + chunks(8) + namespace(len_ns) + digest(HASH_SIZE)
            acc + 4 + 8 + 8 + ns_info.name.len() + HASH_SIZE
        });

        // A rather nice property of the manifest record is that its offset field is the same as
        // the payload length on the wire, so it's bookended by the same value.
        u32::try_from(
            [
                1,              // Type
                8,              // Slot number
                8,              // Total entries
                8,              // Total chunks
                created_at_len, // Summary: created at
                tool_len,       // Summary: tool
                comment_len,    // Summary: comment
                ns_info_len,    // Namespace info
                4,              // ns_info terminal sentinel
                8,              // Previous manifest
                HASH_SIZE,      // Global hash
                4,              // Offset
            ]
            .iter()
            .try_fold(0usize, |acc, &x| acc.checked_add(x))
            .ok_or(SclsError::WireLengthOverflow("manifest offset".into()))?,
        )
        .map_err(|_| SclsError::WireLengthOverflow("manifest offset".into()))
    }
}

impl TryFrom<&[u8]> for Manifest {
    type Error = SclsError;

    /// Parses a manifest record from its payload.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The payload is too short for required fields
    /// - UTF-8 decoding fails for strings
    /// - Namespace info parsing fails
    fn try_from(value: &[u8]) -> std::result::Result<Self, Self::Error> {
        let mut pos = 0;

        // Parse fixed-size header fields (slot_no, total_entries, total_chunks)
        if value.len() < 24 {
            return Err(SclsError::MalformedRecord(
                "manifest too short for header fields".into(),
            ));
        }

        let slot_no = u64::from_be_bytes(value[pos..pos + 8].try_into().unwrap());
        pos += 8;

        let total_entries = u64::from_be_bytes(value[pos..pos + 8].try_into().unwrap());
        pos += 8;

        let total_chunks = u64::from_be_bytes(value[pos..pos + 8].try_into().unwrap());
        pos += 8;

        // Parse summary (3 length-prefixed strings)
        let (summary, bytes_read) = Summary::parse(&value[pos..])?;
        pos += bytes_read;

        // Parse namespace_info (repeated until len_ns == 0)
        let (namespace_info, bytes_read) = NamespaceInfo::parse_list(&value[pos..])?;
        pos += bytes_read;

        // Parse footer fields
        let needed_len = pos
            .checked_add(40)
            .ok_or_else(|| SclsError::MalformedRecord("footer length overflow".into()))?;

        if value.len() < needed_len {
            return Err(SclsError::MalformedRecord(
                "manifest too short for footer fields".into(),
            ));
        }

        let prev_manifest = u64::from_be_bytes(value[pos..pos + 8].try_into().unwrap());
        pos += 8;

        let root_hash_bytes: [u8; HASH_SIZE] = value[pos..pos + HASH_SIZE].try_into().unwrap();
        let root_hash = root_hash_bytes.into();
        pos += HASH_SIZE;

        let offset = u32::from_be_bytes(value[pos..pos + 4].try_into().unwrap());
        pos += 4;

        // Verify that we consumed everything
        if pos != value.len() {
            return Err(SclsError::MalformedRecord(format!(
                "manifest has {} trailing bytes",
                value.len() - pos
            )));
        }

        let manifest = Manifest {
            slot_no,
            total_entries,
            total_chunks,
            root_hash,
            namespace_info,
            prev_manifest,
            summary,
        };

        // Check offset matches the computed value
        if offset != manifest.offset()? {
            return Err(SclsError::MalformedRecord(
                "manifest offset does not match record length".into(),
            ));
        }

        Ok(manifest)
    }
}

/// Information about a single namespace within the file
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamespaceInfo {
    /// Number of entries in this namespace
    pub entries_count: u64,

    /// Number of chunks for this namespace
    pub chunks_count: u64,

    /// Namespace identifier
    pub name: String,

    /// Merkle root of all live entries in this namespace
    pub digest: Digest,
}

impl NamespaceInfo {
    /// Parses the list of namespace info structures.
    /// Returns the list and number of bytes consumed.
    fn parse_list(data: &[u8]) -> Result<(Vec<Self>, usize)> {
        let mut namespaces = Vec::new();
        let mut pos: usize = 0;

        loop {
            let needed_len = pos.checked_add(4).ok_or_else(|| {
                SclsError::MalformedRecord("namespace_info length overflow".into())
            })?;

            if data.len() < needed_len {
                return Err(SclsError::MalformedRecord(
                    "incomplete namespace_info length".into(),
                ));
            }

            let len_ns = u32::from_be_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
            pos += 4;

            // len_ns == 0 is the sentinel value indicating when to stop
            if len_ns == 0 {
                break;
            }

            // Parse ns_info: entries_count(8) + chunks_count(8) + name(len_ns) + digest(HASH_SIZE)
            let required = 8 + 8 + len_ns + HASH_SIZE;
            let min_len = pos
                .checked_add(required)
                .ok_or_else(|| SclsError::MalformedRecord("ns_info length overflow".into()))?;

            if data.len() < min_len {
                return Err(SclsError::MalformedRecord(
                    "incomplete namespace_info structure".into(),
                ));
            }

            let entries_count = u64::from_be_bytes(data[pos..pos + 8].try_into().unwrap());
            pos += 8;

            let chunks_count = u64::from_be_bytes(data[pos..pos + 8].try_into().unwrap());
            pos += 8;

            let name = str::from_utf8(&data[pos..pos + len_ns])
                .map_err(|_| SclsError::MalformedRecord("invalid UTF-8 in namespace name".into()))?
                .to_string();
            pos += len_ns;

            let digest_bytes: [u8; HASH_SIZE] = data[pos..pos + HASH_SIZE].try_into().unwrap();
            let digest = digest_bytes.into();
            pos += HASH_SIZE;

            namespaces.push(Self {
                entries_count,
                chunks_count,
                name,
                digest,
            });
        }

        Ok((namespaces, pos))
    }

    /// Return the wire serialisation of the namespace info.
    fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::new();

        let len_ns = u32::try_from(self.name.len())
            .map_err(|_| SclsError::WireLengthOverflow("namespace length".into()))?;

        buf.extend_from_slice(&len_ns.to_be_bytes());
        buf.extend_from_slice(&self.entries_count.to_be_bytes());
        buf.extend_from_slice(&self.chunks_count.to_be_bytes());
        buf.extend_from_slice(self.name.as_bytes());
        buf.extend_from_slice(self.digest.as_bytes());

        Ok(buf)
    }
}

/// Summary metadata about file creation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Summary {
    /// ISO8601 timestamp when file was created
    pub created_at: String,

    /// Name of the tool that generated the file
    pub tool: String,

    /// Comment
    pub comment: Option<String>,
}

impl Summary {
    /// Parses the summary section (3 `tstr` fields).
    /// Returns the summary and number of bytes consumed.
    fn parse(data: &[u8]) -> Result<(Self, usize)> {
        let mut pos = 0;

        let (created_at, len) = parse_tstr(&data[pos..])?;
        pos += len;

        let (tool, len) = parse_tstr(&data[pos..])?;
        pos += len;

        let (comment_str, len) = parse_tstr(&data[pos..])?;
        pos += len;

        let comment = if comment_str.is_empty() {
            None
        } else {
            Some(comment_str)
        };

        Ok((
            Self {
                created_at,
                tool,
                comment,
            },
            pos,
        ))
    }

    /// Return the wire serialisation of the summary.
    fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut buf = to_tstr_bytes(&self.created_at)?;
        buf.extend(to_tstr_bytes(&self.tool)?);
        buf.extend(to_tstr_bytes(self.comment.as_deref().unwrap_or(""))?);

        Ok(buf)
    }
}

/// Parses a length-prefixed UTF-8 string (`tstr` in the Kaitai spec).
/// Returns the string and number of bytes consumed.
fn parse_tstr(data: &[u8]) -> Result<(String, usize)> {
    if data.len() < 4 {
        return Err(SclsError::MalformedRecord(
            "tstr too short for length".into(),
        ));
    }

    let len = u32::from_be_bytes(data[0..4].try_into().unwrap()) as usize;

    let total_len = len
        .checked_add(4)
        .ok_or_else(|| SclsError::MalformedRecord("tstr length overflow".into()))?;

    if data.len() < total_len {
        return Err(SclsError::MalformedRecord(format!(
            "tstr length {} bytes extends beyond remaining data",
            len
        )));
    }

    let s = str::from_utf8(&data[4..total_len])
        .map_err(|_| SclsError::MalformedRecord("invalid UTF-8 in tstr".into()))?
        .to_string();

    Ok((s, total_len))
}

/// Convert an AsRef<str> into a length-prefixed UTF-8 string (`tstr` in the Kaitai spec).
///
/// # Errors
///
/// Returns an error if there's a length overflow
fn to_tstr_bytes<S: AsRef<str>>(input: S) -> Result<Vec<u8>> {
    let len = u32::try_from(input.as_ref().len())
        .map_err(|_| SclsError::WireLengthOverflow("tstr".into()))?;

    let mut buf = len.to_be_bytes().to_vec();
    buf.extend_from_slice(input.as_ref().as_bytes());

    Ok(buf)
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use proptest::prelude::*;

    use super::*;

    // Strategy to generate a tstr (length-prefixed UTF-8 string)
    fn tstr_bytes() -> impl Strategy<Value = Vec<u8>> {
        prop::string::string_regex("[a-zA-Z0-9 ]{0,100}")
            .unwrap()
            .prop_map(|s| {
                let len = s.len() as u32;
                let mut bytes = len.to_be_bytes().to_vec();
                bytes.extend_from_slice(s.as_bytes());
                bytes
            })
    }

    // Strategy to generate a summary section
    fn summary_bytes() -> impl Strategy<Value = Vec<u8>> {
        (tstr_bytes(), tstr_bytes(), tstr_bytes()).prop_map(|(created, tool, comment)| {
            let mut bytes = Vec::new();
            bytes.extend(created);
            bytes.extend(tool);
            bytes.extend(comment);
            bytes
        })
    }

    // Strategy to generate a single namespace_info entry
    fn namespace_info_bytes() -> impl Strategy<Value = Vec<u8>> {
        (
            any::<u64>(),                                         // entries_count
            any::<u64>(),                                         // chunks_count
            prop::string::string_regex("[a-z/_]{1,20}").unwrap(), // name
            prop::array::uniform28(any::<u8>()),                  // digest
        )
            .prop_map(|(entries, chunks, name, digest)| {
                let len_ns = name.len() as u32;
                let mut bytes = len_ns.to_be_bytes().to_vec();
                bytes.extend(entries.to_be_bytes());
                bytes.extend(chunks.to_be_bytes());
                bytes.extend(name.as_bytes());
                bytes.extend(digest);
                bytes
            })
    }

    // Strategy to generate namespace_info list with sentinel
    fn namespace_info_list_bytes(num_namespaces: usize) -> impl Strategy<Value = Vec<u8>> {
        prop::collection::vec(namespace_info_bytes(), num_namespaces..=num_namespaces).prop_map(
            |namespaces| {
                let mut bytes = namespaces.concat();
                bytes.extend(0u32.to_be_bytes()); // Sentinel (len_ns = 0)
                bytes
            },
        )
    }

    // Strategy to generate a complete manifest
    fn manifest_bytes(num_namespaces: usize) -> impl Strategy<Value = Vec<u8>> {
        (
            any::<u64>(),                              // slot_no
            any::<u64>(),                              // total_entries
            any::<u64>(),                              // total_chunks
            summary_bytes(),                           // summary
            namespace_info_list_bytes(num_namespaces), // namespace info
            any::<u64>(),                              // prev_manifest
            prop::array::uniform28(any::<u8>()),       // root_hash
        )
            .prop_map(|(slot, entries, chunks, summary, ns_info, prev, root)| {
                let mut bytes = Vec::new();
                bytes.extend(slot.to_be_bytes());
                bytes.extend(entries.to_be_bytes());
                bytes.extend(chunks.to_be_bytes());
                bytes.extend(summary);
                bytes.extend(ns_info);
                bytes.extend(prev.to_be_bytes());
                bytes.extend(root);

                // offset = payload length + record type(1) + offset field itself(4)
                let offset = (bytes.len() + 1 + 4) as u32;
                bytes.extend(offset.to_be_bytes());

                bytes
            })
    }

    proptest! {
        #[test]
        fn parse_manifest_consumes_all_bytes(data in (0usize..=5).prop_flat_map(manifest_bytes)) {
            // The parser should have consumed all the bytes, which we verify in our try_from impl
            // so there's no need to test here
            let result = Manifest::try_from(data.as_slice());
            prop_assert!(result.is_ok());
        }

        #[test]
        fn parse_manifest_namespace_count_matches(
            params in (0usize..=5)
                .prop_flat_map(|num_ns| {
                    manifest_bytes(num_ns)
                        .prop_map(move |data| (num_ns, data))
                })
        ) {
            let (num_ns, data) = params;
            let manifest = Manifest::try_from(data.as_slice())?;
            prop_assert_eq!(manifest.namespace_info.len(), num_ns);
        }

        #[test]
        fn parse_manifest_rejects_trailing_bytes(
            data in (0usize..=5).prop_flat_map(manifest_bytes),
            extra in prop::collection::vec(any::<u8>(), 1..10)
        ) {
            let mut malformed = data;
            malformed.extend(extra);

            let result = Manifest::try_from(malformed.as_slice());
            prop_assert!(result.is_err());
        }

        #[test]
        fn parse_manifest_rejects_truncated(data in (0usize..=5).prop_flat_map(manifest_bytes)) {
            prop_assume!(data.len() > 10);

            let truncated = &data[..data.len() - 5];
            let result = Manifest::try_from(truncated);
            prop_assert!(result.is_err());
        }

        #[test]
        fn ns_info_roundtrip(wire_in in namespace_info_list_bytes(1)) {
            let (ns_info_list, _) = NamespaceInfo::parse_list(&wire_in)?;
            let ns_info = ns_info_list.first().unwrap();

            let mut wire_out = ns_info.to_bytes()?;
            wire_out.extend_from_slice(&0u32.to_be_bytes()); // sentinel

            prop_assert_eq!(wire_in, wire_out);
        }

        #[test]
        fn summary_roundtrip(wire_in in summary_bytes()) {
            let (summary, _) = Summary::parse(&wire_in)?;
            let wire_out = summary.to_bytes()?;

            prop_assert_eq!(wire_in, wire_out);
        }

        #[test]
        fn manifest_invalid_offset(
            mut wire_in in (0usize..5).prop_flat_map(manifest_bytes),
            bad_offset in any::<u32>(),
        ) {
            let len = wire_in.len();
            prop_assume!(len as u32 != bad_offset);

            // Corrupt manifest offset (last 4 bytes)
            let offset = &mut wire_in[len - 4..];
            offset.copy_from_slice(&bad_offset.to_be_bytes());

            prop_assert!(Manifest::try_from(wire_in.as_slice()).is_err());
        }

        #[test]
        fn manifest_roundtrip(wire_in in (0usize..5).prop_flat_map(manifest_bytes)) {
            let manifest = Manifest::try_from(wire_in.as_slice())?;

            let mut wire_out: Vec<u8> = Vec::new();
            let mut writer = Cursor::new(&mut wire_out);
            manifest.write(&mut writer)?;

            // Record length prefix _includes_ the type(1), which isn't in wire_in
            let len_prefix = {
                let bytes: [u8; 4] = wire_out[0..4].try_into().unwrap();
                u32::from_be_bytes(bytes)
            };

            // Strip the length prefix(4) and record type(1)
            let wire_out = &wire_out[5..];

            prop_assert_eq!(len_prefix, manifest.offset()?);
            prop_assert_eq!(len_prefix as usize, wire_in.len() + 1); // +1 for type
            prop_assert_eq!(wire_in, wire_out);
        }
    }
}
