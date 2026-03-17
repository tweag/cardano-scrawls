//! Rust to Haskell integration tests

use std::collections::BTreeSet;

use proptest::prelude::*;

use super::{Namespace, SclsUtil};

// Strategy that returns a BTreeSet of a non-empty subset of namespace strings with a selection of
// fixed-length keys, per namespace, in ascending order
fn namespaces_with_keys(
    max_ns: usize,
    max_keys: usize,
) -> impl Strategy<Value = BTreeSet<(String, Vec<u8>)>> {
    Namespace::subset(max_ns).prop_flat_map(move |namespaces| {
        let key_strategies: Vec<_> = namespaces
            .iter()
            .map(|_| {
                (1usize..=10, 1..=max_keys).prop_flat_map(|(key_len, num_keys)| {
                    proptest::collection::vec(
                        proptest::collection::vec(any::<u8>(), key_len),
                        num_keys,
                    )
                })
            })
            .collect();

        key_strategies.prop_map(move |keys| {
            namespaces
                .iter()
                .zip(keys)
                .flat_map(|(ns, keys)| keys.into_iter().map(move |key| (ns.to_string(), key)))
                .collect::<BTreeSet<_>>()
        })
    })
}

// Strategy to generate valid (namespace, key, entry) sequences. That is, the output is in
// ascending order of (namespace, key) and the key length, for each namespace, is the same. (Based
// on `writer::tests::valid_entry_writes`.)
prop_compose! {
    fn valid_entry_writes(max_ns: usize, max_entries: usize)
        (
            ns_key_pairs in namespaces_with_keys(max_ns, max_entries),
        )
        (
            values in proptest::collection::vec(
                proptest::collection::vec(any::<u8>(), 1..=64usize),
                ns_key_pairs.len()
            ),
            ns_key_pairs in Just(ns_key_pairs),
        )
    -> Vec<(String, Vec<u8>, Vec<u8>)> {
        ns_key_pairs.into_iter()
            .zip(values)
            .map(|((ns, key), value)| (ns, key, value))
            .collect()
    }
}
