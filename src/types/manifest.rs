//! SCLS manifest record.

use crate::error::{Result, SclsError};
use crate::types::Digest;

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

    /// Relative offset to the beginning of this record
    /// (can be used to find the manifest by reading the last 4 bytes of the file)
    pub offset: u32,
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

impl TryFrom<&[u8]> for Manifest {
    type Error = SclsError;

    /// Parses a manifest record from its payload.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The payload is too short for required fields
    /// - UTF-8 decoding fails for strings
    /// - Namespace info parsing files
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
        let (summary, bytes_read) = parse_summary(&value[pos..])?;
        pos += bytes_read;

        // Parse namespace_info (repeated until len_ns == 0)
        let (namespace_info, bytes_read) = parse_namespace_info_list(&value[pos..])?;
        pos += bytes_read;

        // Parse footer fields
        if value.len() < pos + 40 {
            return Err(SclsError::MalformedRecord(
                "manifest too short for footer fields".into(),
            ));
        }

        let prev_manifest = u64::from_be_bytes(value[pos..pos + 8].try_into().unwrap());
        pos += 8;

        let root_hash_bytes: [u8; 28] = value[pos..pos + 28].try_into().unwrap();
        let root_hash = root_hash_bytes.into();
        pos += 28;

        let offset = u32::from_be_bytes(value[pos..pos + 4].try_into().unwrap());
        pos += 4;

        // Verify that we consumed everything
        if pos != value.len() {
            return Err(SclsError::MalformedRecord(format!(
                "manifest has {} trailing bytes",
                value.len() - pos
            )));
        }

        Ok(Manifest {
            slot_no,
            total_entries,
            total_chunks,
            root_hash,
            namespace_info,
            prev_manifest,
            summary,
            offset,
        })
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

    if data.len() < 4 + len {
        return Err(SclsError::MalformedRecord(format!(
            "tstr length {} bytes extends beyond remaining data",
            len
        )));
    }

    let s = std::str::from_utf8(&data[4..4 + len])
        .map_err(|_| SclsError::MalformedRecord("invalid UTF-8 in tstr".into()))?
        .to_string();

    Ok((s, 4 + len))
}

/// Parses the summary section (3 `tstr` fields).
/// Returns the summary and number of bytes consumed.
fn parse_summary(data: &[u8]) -> Result<(Summary, usize)> {
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
        Summary {
            created_at,
            tool,
            comment,
        },
        pos,
    ))
}

/// Parses the list of namespace info structures.
/// Returns the list and number of bytes consumed.
fn parse_namespace_info_list(data: &[u8]) -> Result<(Vec<NamespaceInfo>, usize)> {
    let mut namespaces = Vec::new();
    let mut pos = 0;

    loop {
        if data.len() < pos + 4 {
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

        // Parse ns_info: entries_count(8) + chunks_count(8) + name(len_ns) + digest(28)
        let required = 8 + 8 + len_ns + 28;
        if data.len() < pos + required {
            return Err(SclsError::MalformedRecord(
                "incomplete namespace_info structure".into(),
            ));
        }

        let entries_count = u64::from_be_bytes(data[pos..pos + 8].try_into().unwrap());
        pos += 8;

        let chunks_count = u64::from_be_bytes(data[pos..pos + 8].try_into().unwrap());
        pos += 8;

        let name = std::str::from_utf8(&data[pos..pos + len_ns])
            .map_err(|_| SclsError::MalformedRecord("invalid UTF-8 in namespace name".into()))?
            .to_string();
        pos += len_ns;

        let digest_bytes: [u8; 28] = data[pos..pos + 28].try_into().unwrap();
        let digest = digest_bytes.into();
        pos += 28;

        namespaces.push(NamespaceInfo {
            entries_count,
            chunks_count,
            name,
            digest,
        });
    }

    Ok((namespaces, pos))
}
