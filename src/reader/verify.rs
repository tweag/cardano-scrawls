//! SCLS file structural and integrity verification.

use std::collections::{BTreeMap, BTreeSet}; // To maintain key order
use std::io::{Read, Seek};

use crate::error::{Result, SclsError};
use crate::hash::{Blake2b, Digest, MerkleTree};
use crate::records::{Chunk, Manifest};

/// Structural integrity check options.
#[derive(Debug, Eq, PartialEq)]
pub enum CheckStructure {
    /// Do not verify structural integrity.
    Disabled,

    /// Verify that:
    /// - the chunk sequence is strictly monotonically increasing;
    /// - chunk namespaces are in bytewise ascending order;
    /// - manifest chunk and entry counts are correct for each namespace.
    Simple,

    /// [Simple verification](CheckStructure::Simple), plus verify that:
    /// - Entry keys are in lexicographically ascending order per namespace.
    ///
    /// Note: This requires key materialisation and, hence, more memory.
    Full,
}

impl CheckStructure {
    /// Whether structural integrity verification is enabled.
    pub fn enabled(&self) -> bool {
        self != &Self::Disabled
    }
}

/// SCLS file verification options.
#[derive(Debug, Eq, PartialEq)]
pub struct VerifyOptions {
    /// Check structural integrity.
    pub check_structure: CheckStructure,

    /// Check that all digests are valid. That is:
    /// - Chunk digests
    /// - Namespace Merkle root digests
    /// - The global Merkle root digest
    pub check_integrity: bool,
}

impl VerifyOptions {
    /// Full verification.
    pub fn full() -> Self {
        Self {
            check_structure: CheckStructure::Full,
            check_integrity: true,
        }
    }
}

impl Default for VerifyOptions {
    fn default() -> Self {
        Self {
            check_structure: CheckStructure::Simple,
            check_integrity: true,
        }
    }
}

/// Alias for namespace chunk count, entry count and digest tuples.
type NSInfo = (u64, u64, Digest);

/// Verification state.
#[derive(Debug)]
pub(super) struct VerifyState {
    prev_chunk_seqno: Option<u64>,
    prev_chunk_namespace: Option<String>,
    prev_ns_entry_key: Option<Vec<u8>>,
    ns_chunks: BTreeMap<String, u64>,
    ns_entries: BTreeMap<String, u64>,
    ns_digests: BTreeMap<String, MerkleTree>,
}

impl VerifyState {
    /// Initialise verification state.
    pub fn new() -> Self {
        Self {
            prev_chunk_seqno: None,
            prev_chunk_namespace: None,
            prev_ns_entry_key: None,
            ns_chunks: BTreeMap::new(),
            ns_entries: BTreeMap::new(),
            ns_digests: BTreeMap::new(),
        }
    }

    /// Check that chunk sequence numbers are strictly monotonically increasing and that chunk
    /// namespaces are in bytewise ascending order. When `full` is set, the previous entry key is
    /// reset on namespace change (to prepare for per-namespace key ordering checks).
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - A chunk's sequence number is not strictly greater than the previous
    /// - A chunk's namespace is bytewise less than the previous
    pub fn check_chunk_ordering(&mut self, chunk: &Chunk, full: bool) -> Result<()> {
        // Check strict monotonicity of chunk sequence number
        if let Some(previous) = self.prev_chunk_seqno
            && previous >= chunk.seqno
        {
            return Err(SclsError::SeqnoDisordered {
                previous,
                found: chunk.seqno,
            });
        }

        if let Some(previous) = &self.prev_chunk_namespace {
            // Check monotonicity of chunk namespace
            if previous > &chunk.namespace {
                return Err(SclsError::NamespaceDisordered {
                    previous: previous.to_string(),
                    found: chunk.namespace.clone(),
                });
            }

            // Reset previous namespace's previous entry key if the namespace changes during a full
            // check
            if full && previous != &chunk.namespace {
                self.prev_ns_entry_key = None;
            }
        }

        Ok(())
    }

    /// Verify the chunk digest and post-process each entry. When full structural checking is
    /// enabled, entry keys are checked for strict monotonicity within the namespace. When
    /// integrity checking is enabled, the namespace Merkle tree is updated with each entry digest.
    ///
    /// The reader is rewound to its original position after verification.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - An I/O error occurs during reading or seeking
    /// - The chunk digest does not match its computed value
    /// - Entry keys are not in strictly ascending order within a namespace (when `check_structure`
    ///   is [`CheckStructure::Full`])
    pub fn verify_chunk_entries<R: Read + Seek>(
        &mut self,
        chunk: &Chunk,
        reader: &mut R,
        options: &VerifyOptions,
    ) -> Result<()> {
        let pos = reader.stream_position()?;

        chunk.verify_and(reader, |digest, reader, key_len, _| {
            if options.check_structure == CheckStructure::Full {
                // Materialise the key
                let mut key_buf = vec![0u8; key_len as usize];
                reader.read_exact(&mut key_buf)?;

                // Check strict monotonicity of chunk entry keys
                if let Some(previous) = &self.prev_ns_entry_key
                    && *previous >= key_buf
                {
                    return Err(SclsError::KeysDisordered {
                        namespace: chunk.namespace.clone(),
                        seqno: chunk.seqno,
                    });
                }

                // Update chunk state for the next round
                self.prev_ns_entry_key = Some(key_buf);
            }

            // Update namespace Merkle tree with the entry digest
            if options.check_integrity {
                self.ns_digests
                    .entry(chunk.namespace.clone())
                    .or_default()
                    .add_leaf(digest);
            }

            Ok(())
        })?;

        // Rewind
        reader.seek(std::io::SeekFrom::Start(pos))?;
        Ok(())
    }

    /// Update accumulated chunk and entry counts and record the chunk's sequence number and
    /// namespace for the next iteration.
    pub fn update_chunk_state(&mut self, chunk: &Chunk) {
        *self.ns_chunks.entry(chunk.namespace.clone()).or_insert(0) += 1;

        // NOTE We assume that the chunk footer is accurate
        *self.ns_entries.entry(chunk.namespace.clone()).or_insert(0) +=
            chunk.footer.entries_count as u64;

        self.prev_chunk_seqno = Some(chunk.seqno);
        self.prev_chunk_namespace = Some(chunk.namespace.clone());
    }

    /// Check that the set of namespaces found in chunks matches those listed in the manifest.
    ///
    /// # Errors
    ///
    /// Returns an error if the chunk namespace set differs from the manifest namespace set.
    pub fn check_manifest_namespace_sets(&self, ns_info: &BTreeMap<String, NSInfo>) -> Result<()> {
        // Chunk namespaces must match manifest namespaces
        let chunk_namespaces: BTreeSet<&String> = self.ns_chunks.keys().collect();
        let manifest_namespaces: BTreeSet<&String> = ns_info.keys().collect();

        if chunk_namespaces != manifest_namespaces {
            // Only clone when necessary, for the error
            let in_chunks: Vec<String> = chunk_namespaces.into_iter().cloned().collect();
            let in_manifest: Vec<String> = manifest_namespaces.into_iter().cloned().collect();

            return Err(SclsError::NamespaceMismatch {
                in_chunks,
                in_manifest,
            });
        }

        Ok(())
    }

    /// Check that per-namespace chunk and entry counts match those declared in the manifest.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - A namespace's chunk count differs from the manifest
    /// - A namespace's entry count differs from the manifest
    pub fn check_manifest_structure(&self, ns_info: &BTreeMap<String, NSInfo>) -> Result<()> {
        for (namespace, (chunk_count, entry_count, _)) in ns_info {
            // Namespace chunk counts must match those in the manifest
            let expected = *chunk_count;
            let found = self.ns_chunks[namespace];
            if expected != found {
                return Err(SclsError::NamespaceChunkMismatch {
                    namespace: namespace.to_string(),
                    expected,
                    found,
                });
            }

            // Namespace entry counts must match those in the manifest
            let expected = *entry_count;
            let found = self.ns_entries[namespace];
            if expected != found {
                return Err(SclsError::NamespaceEntryMismatch {
                    namespace: namespace.to_string(),
                    expected,
                    found,
                });
            }
        }

        Ok(())
    }

    /// Verify namespace Merkle root digests and the global Merkle root against the manifest.
    ///
    /// Each namespace's computed Merkle root (from accumulated entry digests) is compared to the
    /// digest declared in the manifest. The namespace roots are then combined into a global Merkle
    /// tree whose root is compared to [`Manifest::root_hash`].
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - A namespace Merkle root does not match its computed value
    /// - The global Merkle root does not match its computed value
    pub fn check_manifest_integrity(
        &mut self,
        manifest: &Manifest,
        ns_info: &BTreeMap<String, NSInfo>,
    ) -> Result<()> {
        let mut global_merkle: MerkleTree = MerkleTree::new();

        // Namespaces will be iterated through in order by virtue of the BTree map, so the global
        // Merkle tree's order will be correct
        for (namespace, (_, _, digest)) in ns_info {
            // Check namespace root digests match computed
            let expected = *digest;
            let computed = match self.ns_digests.remove(namespace) {
                Some(tree) => tree.root(),

                // For the case where a namespace has no entries
                None => MerkleTree::new().root(),
            };

            if expected != computed {
                return Err(SclsError::NamespaceDigestMismatch {
                    namespace: namespace.to_string(),
                    expected,
                    computed,
                });
            }

            // Update the global Merkle tree
            let ns_digest = Blake2b::new_leaf().update(expected.as_bytes()).as_digest();
            global_merkle.add_leaf(ns_digest);
        }

        // Check the global Merkle root matches
        let expected = manifest.root_hash;
        let computed = global_merkle.root();
        if expected != computed {
            return Err(SclsError::GlobalDigestMismatch { expected, computed });
        }

        Ok(())
    }
}

/// Convert the manifest namespace information vector into an ordered map of chunk count, entry
/// count and digest tuples. A [`BTreeMap`] is used to ensure entries are ordered by namespace.
///
/// # Errors
///
/// Returns an error if the manifest contains duplicate namespace names
pub(super) fn build_ns_info(manifest: &Manifest) -> Result<BTreeMap<String, NSInfo>> {
    let ns_info: BTreeMap<String, NSInfo> = manifest
        .namespace_info
        .iter()
        .map(|ns_info| {
            (
                ns_info.name.clone(),
                (ns_info.chunks_count, ns_info.entries_count, ns_info.digest),
            )
        })
        .collect();

    if ns_info.len() != manifest.namespace_info.len() {
        return Err(SclsError::MalformedRecord(
            "manifest contains duplicate namespaces".into(),
        ));
    }

    Ok(ns_info)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::io::Cursor;

    use proptest::prelude::*;

    use crate::error::SclsError;
    use crate::hash::{Blake2b, Digest, HASH_SIZE, MerkleTree};
    use crate::records::{Chunk, Manifest, NamespaceInfo, Summary};

    use super::{NSInfo, VerifyState, build_ns_info};

    const DUMMY_DIGEST: Digest = Digest::new([0x00; HASH_SIZE]);

    /// Create a dummy [`Chunk`] with the given sequence number and namespace.
    ///
    /// The chunk has zero entries and a zero'd digest. Only `seqno` and `namespace` are
    /// meaningful; the chunk is not valid for digest verification.
    fn dummy_chunk(seqno: u64, namespace: &str) -> Chunk {
        let ns_bytes = namespace.as_bytes();
        let mut payload = Vec::new();
        payload.extend_from_slice(&seqno.to_be_bytes());
        payload.push(0x00); // Raw format
        payload.extend_from_slice(&(ns_bytes.len() as u32).to_be_bytes());
        payload.extend_from_slice(ns_bytes);
        payload.extend_from_slice(&1u32.to_be_bytes()); // key_len
        payload.extend_from_slice(&0u32.to_be_bytes()); // footer: entries_count
        payload.extend_from_slice(DUMMY_DIGEST.as_bytes()); // footer: digest

        let payload_len = payload.len() as u32;
        let mut cursor = Cursor::new(payload);
        Chunk::parse(&mut cursor, 0, payload_len).unwrap()
    }

    /// Helper to construct a minimal [`Manifest`] with the given root hash and namespace info.
    fn dummy_manifest(root_hash: Digest, namespace_info: Vec<NamespaceInfo>) -> Manifest {
        Manifest {
            slot_no: 0,
            total_entries: 0,
            total_chunks: 0,
            root_hash,
            namespace_info,
            prev_manifest: 0,
            summary: Summary {
                created_at: String::new(),
                tool: String::new(),
                comment: None,
            },
            offset: 0,
        }
    }

    /* verify_chunk_entries **********************************************************************/

    // TODO Test `verify_chunk_entries` with a multi-entry fixture once one is available. The
    // current minimal fixture has only one entry and one chunk, so entry key ordering is trivially
    // satisfied. A fixture with at least two entries in the same namespace would let us test both
    // the happy path and key-ordering rejection.

    /* check_chunk_ordering **********************************************************************/

    prop_compose! {
        /// Strategy that generates a (previous, current) seqno pair where current <= previous.
        fn non_increasing_seqno_pair()
            (previous in 0u64..=u64::MAX)
            (current in 0u64..=previous, previous in Just(previous))
        -> (u64, u64) {
            (previous, current)
        }
    }

    proptest! {
        #[test]
        fn chunk_ordering_rejects_non_increasing_seqno(
            (prev_seqno, this_seqno) in non_increasing_seqno_pair()
        ) {
            let mut state = VerifyState::new();
            state.prev_chunk_seqno = Some(prev_seqno);

            let chunk = dummy_chunk(this_seqno, "ns");
            let result = state.check_chunk_ordering(&chunk, false);

            let is_seqno_err = matches!(
                result,
                Err(SclsError::SeqnoDisordered { previous, found })
                    if previous == prev_seqno && found == this_seqno
            );
            prop_assert!(is_seqno_err);
        }
    }

    #[test]
    fn chunk_ordering_rejects_namespace_decrease() {
        let mut state = VerifyState::new();
        state.prev_chunk_seqno = Some(0);
        state.prev_chunk_namespace = Some("z".into());

        let result = state.check_chunk_ordering(&dummy_chunk(1, "a"), false);
        assert!(matches!(result, Err(SclsError::NamespaceDisordered { .. })));
    }

    #[test]
    fn chunk_ordering_accepts_namespace_equal() {
        let mut state = VerifyState::new();
        state.prev_chunk_seqno = Some(0);
        state.prev_chunk_namespace = Some("ns".into());

        assert!(
            state
                .check_chunk_ordering(&dummy_chunk(1, "ns"), false)
                .is_ok()
        );
    }

    #[test]
    fn chunk_ordering_resets_entry_key_on_namespace_change() {
        let mut state = VerifyState::new();
        state.prev_chunk_seqno = Some(0);
        state.prev_chunk_namespace = Some("a".into());
        state.prev_ns_entry_key = Some(vec![0xff]);

        state
            .check_chunk_ordering(&dummy_chunk(1, "b"), true)
            .unwrap();
        assert!(state.prev_ns_entry_key.is_none());
    }

    #[test]
    fn chunk_ordering_preserves_entry_key_same_namespace() {
        let mut state = VerifyState::new();
        state.prev_chunk_seqno = Some(0);
        state.prev_chunk_namespace = Some("a".into());
        state.prev_ns_entry_key = Some(vec![0xff]);

        state
            .check_chunk_ordering(&dummy_chunk(1, "a"), true)
            .unwrap();
        assert!(state.prev_ns_entry_key.is_some());
    }

    /* check_manifest_namespace_sets *************************************************************/

    proptest! {
        #[test]
        fn manifest_namespace_sets_accepts_matching(
            namespaces in prop::collection::btree_set("[a-z]{1,8}", 1..=5)
        ) {
            let mut state = VerifyState::new();
            let mut ns_info = BTreeMap::new();

            for ns in &namespaces {
                state.ns_chunks.insert(ns.clone(), 1);
                ns_info.insert(ns.clone(), (1, 1, DUMMY_DIGEST));
            }

            prop_assert!(state.check_manifest_namespace_sets(&ns_info).is_ok());
        }

        #[test]
        fn manifest_namespace_sets_rejects_mismatch(
            chunk_ns in prop::collection::btree_set("[a-z]{1,8}", 1..=5),
            manifest_ns in prop::collection::btree_set("[a-z]{1,8}", 1..=5),
        ) {
            prop_assume!(chunk_ns != manifest_ns);

            let mut state = VerifyState::new();
            for ns in &chunk_ns {
                state.ns_chunks.insert(ns.clone(), 1);
            }

            let ns_info: BTreeMap<String, NSInfo> = manifest_ns.iter()
                .map(|ns| (ns.clone(), (1, 1, DUMMY_DIGEST)))
                .collect();

            let is_mismatch = matches!(
                state.check_manifest_namespace_sets(&ns_info),
                Err(SclsError::NamespaceMismatch { .. })
            );
            prop_assert!(is_mismatch);
        }
    }

    /* check_manifest_structure ******************************************************************/

    proptest! {
        #[test]
        fn manifest_structure_accepts_matching_counts(
            data in prop::collection::btree_map(
                "[a-z]{1,8}", (1u64..=100, 1u64..=1000), 1..=5
            )
        ) {
            let mut state = VerifyState::new();
            let mut ns_info = BTreeMap::new();

            for (ns, (chunks, entries)) in &data {
                state.ns_chunks.insert(ns.clone(), *chunks);
                state.ns_entries.insert(ns.clone(), *entries);
                ns_info.insert(ns.clone(), (*chunks, *entries, DUMMY_DIGEST));
            }

            prop_assert!(state.check_manifest_structure(&ns_info).is_ok());
        }

        #[test]
        fn manifest_structure_rejects_chunk_count_mismatch(
            ns in "[a-z]{1,8}",
            actual in 1u64..=100,
            expected in 1u64..=100,
            entries in 1u64..=1000,
        ) {
            prop_assume!(actual != expected);

            let mut state = VerifyState::new();
            state.ns_chunks.insert(ns.clone(), actual);
            state.ns_entries.insert(ns.clone(), entries);

            let mut ns_info = BTreeMap::new();
            ns_info.insert(ns, (expected, entries, DUMMY_DIGEST));

            let is_chunk_mismatch = matches!(
                state.check_manifest_structure(&ns_info),
                Err(SclsError::NamespaceChunkMismatch { .. })
            );
            prop_assert!(is_chunk_mismatch);
        }

        #[test]
        fn manifest_structure_rejects_entry_count_mismatch(
            ns in "[a-z]{1,8}",
            chunks in 1u64..=100,
            actual in 1u64..=1000,
            expected in 1u64..=1000,
        ) {
            prop_assume!(actual != expected);

            let mut state = VerifyState::new();
            state.ns_chunks.insert(ns.clone(), chunks);
            state.ns_entries.insert(ns.clone(), actual);

            let mut ns_info = BTreeMap::new();
            ns_info.insert(ns, (chunks, expected, DUMMY_DIGEST));

            let is_entry_mismatch = matches!(
                state.check_manifest_structure(&ns_info),
                Err(SclsError::NamespaceEntryMismatch { .. })
            );
            prop_assert!(is_entry_mismatch);
        }
    }

    /* check_manifest_integrity ******************************************************************/

    #[test]
    fn manifest_integrity_accepts_correct_digests() {
        let mut state = VerifyState::new();

        let leaf = Blake2b::new_leaf().update(b"test").as_digest();

        let mut tree = MerkleTree::new();
        tree.add_leaf(leaf);
        state.ns_digests.insert("ns".into(), tree);

        // Compute expected roots from an identical tree
        let ns_root = {
            let mut t = MerkleTree::new();
            t.add_leaf(leaf);
            t.root()
        };
        let global_root = {
            let ns_leaf = Blake2b::new_leaf().update(ns_root.as_bytes()).as_digest();
            let mut t = MerkleTree::new();
            t.add_leaf(ns_leaf);
            t.root()
        };

        let mut ns_info = BTreeMap::new();
        ns_info.insert("ns".into(), (1u64, 1u64, ns_root));

        let manifest = dummy_manifest(global_root, vec![]);
        assert!(state.check_manifest_integrity(&manifest, &ns_info).is_ok());
    }

    #[test]
    fn manifest_integrity_rejects_wrong_namespace_digest() {
        let mut state = VerifyState::new();

        let leaf = Blake2b::new_leaf().update(b"test").as_digest();
        let mut tree = MerkleTree::new();
        tree.add_leaf(leaf);
        state.ns_digests.insert("ns".into(), tree);

        let wrong_digest = Digest::new([0xff; HASH_SIZE]);
        let mut ns_info = BTreeMap::new();
        ns_info.insert("ns".into(), (1u64, 1u64, wrong_digest));

        let manifest = dummy_manifest(DUMMY_DIGEST, vec![]);
        assert!(matches!(
            state.check_manifest_integrity(&manifest, &ns_info),
            Err(SclsError::NamespaceDigestMismatch { .. })
        ));
    }

    #[test]
    fn manifest_integrity_rejects_wrong_global_root() {
        let mut state = VerifyState::new();

        // Namespace with no entries — root is the empty tree root
        let empty_root = MerkleTree::new().root();
        let mut ns_info = BTreeMap::new();
        ns_info.insert("ns".into(), (1u64, 0u64, empty_root));

        let wrong_root = Digest::new([0xff; HASH_SIZE]);
        let manifest = dummy_manifest(wrong_root, vec![]);

        assert!(matches!(
            state.check_manifest_integrity(&manifest, &ns_info),
            Err(SclsError::GlobalDigestMismatch { .. })
        ));
    }

    /* build_ns_info *****************************************************************************/

    proptest! {
        #[test]
        fn build_ns_info_maps_namespace_info(
            namespaces in prop::collection::btree_map(
                "[a-z]{1,10}",
                (any::<u64>(), any::<u64>(), prop::array::uniform28(any::<u8>())),
                1..=5,
            )
        ) {
            let manifest = dummy_manifest(
                DUMMY_DIGEST,
                namespaces.iter().map(|(name, (chunks, entries, digest))| {
                    NamespaceInfo {
                        name: name.clone(),
                        chunks_count: *chunks,
                        entries_count: *entries,
                        digest: Digest::new(*digest),
                    }
                }).collect(),
            );

            let ns_info = build_ns_info(&manifest)?;
            prop_assert_eq!(ns_info.len(), namespaces.len());

            for (name, (chunks, entries, digest)) in &namespaces {
                let (c, e, d) = &ns_info[name];
                prop_assert_eq!(*c, *chunks);
                prop_assert_eq!(*e, *entries);
                prop_assert_eq!(*d, Digest::new(*digest));
            }
        }
    }

    #[test]
    fn build_ns_info_rejects_duplicate_namespaces() {
        let manifest = dummy_manifest(
            DUMMY_DIGEST,
            vec![
                NamespaceInfo {
                    name: "dup".into(),
                    chunks_count: 1,
                    entries_count: 1,
                    digest: DUMMY_DIGEST,
                },
                NamespaceInfo {
                    name: "dup".into(),
                    chunks_count: 2,
                    entries_count: 2,
                    digest: Digest::new([0x01; HASH_SIZE]),
                },
            ],
        );

        assert!(matches!(
            build_ns_info(&manifest),
            Err(SclsError::MalformedRecord(_))
        ));
    }
}
