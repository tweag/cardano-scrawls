//! Haskell to Rust integration tests

use std::collections::HashMap;

use cardano_scrawls::reader::{CheckStructure, Record, SclsReader, VerifyOptions};
use proptest::prelude::*;

use super::{Namespace, SclsUtil};

// Strategy for generating collections of namespaces with entry counts
fn namespaces_with_chunk_count(
    max_namespaces: usize,
    max_entries: usize,
) -> impl Strategy<Value = HashMap<Namespace, usize>> {
    Namespace::subset(max_namespaces).prop_flat_map(move |keys| {
        let ns_count = keys.len();

        proptest::collection::vec(1..=max_entries, ns_count)
            .prop_map(move |values| keys.iter().cloned().zip(values).collect())
    })
}

proptest! {
    #[test]
    fn verify_reference_output(params in namespaces_with_chunk_count(5, 5)) {
        let Ok(scls_util) = SclsUtil::probe() else {
            // Skip if scls-util isn't available
            return Ok(());
        };

        let scls = scls_util.generate(params.clone())?;
        let mut reader = SclsReader::new(scls);

        // Full validation
        // FIXME Structural validation broken by ref impl; see tweag/cardano-cls#259
        // Change this to `VerifyOptions::full()` once resolved
        reader.verify(VerifyOptions { check_structure: CheckStructure::Disabled, check_integrity: true })?;

        // Check manifest namespace info matches input parameters
        for record in reader.records()? {
            if let Ok(Record::Manifest(manifest)) = record {
                for (namespace, &entries) in &params {
                    let ns_info = manifest.namespace_info
                        .iter()
                        .find(|ns| ns.name == namespace.to_string())
                        .expect("namespace missing from manifest");

                    prop_assert_eq!(ns_info.entries_count, entries as u64);
                }
            }
        }
    }
}
