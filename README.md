# Scrawls

[![crates.io][badge:crate:img]][badge:crate:href]
[![docs.rs][badge:docs:img]][badge:docs:href]
[![CI][badge:ci:img]][badge:ci:href]
[![License][badge:license:img]][badge:license:href]


A Rust library for reading, writing and verifying Cardano Standard
Canonical Ledger State (SCLS) files, as defined in [CIP-0165].

SCLS is a binary container format for streaming, verifiable snapshots of
Cardano ledger state. It stores ordered key-value entries grouped by
namespace, with cryptographic integrity verification via Blake2b-224
hashes and Merkle trees.

> [!NOTE]
> This crate is at version 0.1.0 and should be considered early-stage.
> The API may change as the [CIP-0165] specification matures and
> real-world usage reveals improvements.

## Features

- **Read:** SCLS v1 files with lazy chunk parsing. Only chunk headers
  and footers are read until entry data is explicitly requested.

- **Write:** SCLS v1 files with a builder-pattern API that enforces
  namespace ordering, key ordering and key-length consistency at write
  time.

- **Verify** at multiple granularity levels: structural checks (record
  sequence, namespace ordering, chunk counts), integrity checks (chunk
  digests, per-namespace Merkle roots, global Merkle root), or both.

- **Interoperable** with the Haskell reference implementation
  ([cardano-cls]), validated by property-based integration tests in both
  directions.

Values are treated as opaque byte slices. **No CBOR encoding/decoding is
performed.**

## Quick start

### Reading and verifying a file

```rust
use cardano_scrawls::{SclsReader, VerifyOptions};
use std::fs::File;

let file = File::open("snapshot.scls")?;
let mut reader = SclsReader::new(file);

// Full verification: structural checks + cryptographic integrity
reader.verify(VerifyOptions::full())?;
```

### Iterating over records

```rust
use cardano_scrawls::{SclsReader, Record, Entry};
use std::fs::File;

let file = File::open("snapshot.scls")?;
let mut reader = SclsReader::new(file);

for record in reader.records()? {
    match record? {
        Record::Header(hdr) => println!("Version: {}", hdr.version),

        Record::Chunk(chunk) => {
            println!("Namespace: {}, entries: {}",
                chunk.namespace, chunk.footer.entries_count);

            // Entries are read lazily via closure
            chunk.for_each_entry(&mut reader, |reader, key_len, value_len| {
                let entry = Entry::materialise(reader, key_len, value_len)?;
                // Process entry...

                Ok(())
            })?;
        }

        Record::Manifest(manifest) => {
            println!("Slot: {}, namespaces: {}",
                manifest.slot_no, manifest.namespace_info.len());
        }

        Record::Unknown { .. } => {} // Skip unknown record types
    }
}
```

### Writing a file

```rust
use cardano_scrawls::SclsWriter;
use std::fs::File;

let file = File::create("output.scls")?;
let mut writer = SclsWriter::builder()
    .output(file)
    .slot_no(12345)
    .tool("my-tool")
    .build()?;

// Entries must be written in namespace order, with keys
// strictly ascending within each namespace.
writer.write_entry("utxo/v0", &key, &value)?;

// Finalise computes all Merkle roots and write the manifest.
// This consumes the writer, preventing further writes.
writer.finalise()?;
```

## What's not supported (yet)

- **Compressed chunks.** The `ChunkFormat::Zstd` and
  `ChunkFormat::ZstdPerEntry` variants are defined but not yet
  implemented. The reader accepts only `Raw` chunks and the writer
  always emits `Raw`.

- **Delta files, bloom filters, indices and metadata records.** These
  [CIP-0165] record types are reserved for future use and parsed as
  `Record::Unknown`.

- **Non-seekable input.** The reader requires `Read + Seek` for lazy
  chunk parsing.

## Specification

This crate implements [CIP-0165] (Standard Canonical Ledger State), the
canonical interchange format for Cardano ledger state snapshots. The
specification defines the wire format, record types, namespace
conventions and the Merkle tree verification scheme.

This is a sister project to the Haskell reference implementation,
[cardano-cls].

<!-- Links -->
[badge:ci:href]: https://github.com/tweag/cardano-scrawls/actions
[badge:ci:img]: https://img.shields.io/github/actions/workflow/status/tweag/cardano-scrawls/ci.yaml?branch=main&label=CI&logo=github&style=for-the-badge
[badge:crate:href]: https://crates.io/crates/cardano-scrawls
[badge:crate:img]: https://img.shields.io/crates/v/cardano-scrawls?logo=rust&style=for-the-badge
[badge:docs:href]: https://docs.rs/cardano-scrawls
[badge:docs:img]: https://img.shields.io/docsrs/cardano-scrawls?logo=rust&style=for-the-badge
[badge:license:href]: /LICENSE
[badge:license:img]: https://img.shields.io/github/license/tweag/cardano-scrawls?style=for-the-badge
[cardano-cls]: https://github.com/tweag/cardano-cls
[cip-0165]: https://cips.cardano.org/cip/CIP-0165
