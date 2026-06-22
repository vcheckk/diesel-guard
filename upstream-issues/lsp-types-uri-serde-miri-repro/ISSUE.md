# Miri aliasing failure when serde-deserializing `lsp_types::Uri`

## Summary

`lsp_types::Uri` constructed via `FromStr` passes under Miri, but the same URI
constructed through `serde_json::from_value` fails under Miri during drop. The
failure also appears when deserializing `lsp_types::InitializeParams` containing
a `workspaceFolders[].uri`.

The smallest failing case I found is:

```rust
#[test]
fn miri_uri_deserialize_drop_fails() {
    let value = serde_json::json!("file:///tmp/workspace");

    let uri: lsp_types::Uri = serde_json::from_value(value).unwrap();

    drop(uri);
}
```

The similar direct-construction case passes:

```rust
#[test]
fn miri_uri_from_str_drop_passes() {
    let uri = lsp_types::Uri::from_str("file:///tmp/workspace").unwrap();

    drop(uri);
}
```

## Reproduction

This directory contains a minimal crate:

```toml
[package]
name = "miri-lsp-uri-repro"
version = "0.1.0"
edition = "2024"

[dependencies]
lsp-types = "0.97"
serde_json = "1"
```

Run:

```sh
cargo test
cargo +nightly miri test miri_uri_from_str_drop_passes
cargo +nightly miri test miri_uri_deserialize_drop_fails
MIRIFLAGS="-Zmiri-tree-borrows" cargo +nightly miri test miri_uri_deserialize_drop_fails
MIRIFLAGS="-Zmiri-disable-stacked-borrows" cargo +nightly miri test miri_uri_deserialize_drop_fails
```

## Observed Results

- `cargo test`: passes.
- `cargo +nightly miri test miri_uri_from_str_drop_passes`: passes.
- `cargo +nightly miri test miri_uri_deserialize_drop_fails`: fails.
- `MIRIFLAGS="-Zmiri-tree-borrows" cargo +nightly miri test miri_uri_deserialize_drop_fails`: fails.
- `MIRIFLAGS="-Zmiri-disable-stacked-borrows" cargo +nightly miri test miri_uri_deserialize_drop_fails`: passes.

The failure points at drop/deallocation through `fluent_uri::internal::Capped`
after serde deserialization:

```text
error: Undefined Behavior: attempting deallocation using <...>, but that tag only grants SharedReadOnly permission for this location
  --> .../library/alloc/src/raw_vec/mod.rs:876:17

help: <...> was created by a SharedReadOnly retag
  --> src/lib.rs:... serde_json::from_value(value).unwrap()

stack includes:
  <fluent_uri::internal::Capped as std::ops::Drop>::drop
  std::ptr::drop_glue::<fluent_uri::Uri<std::string::String>>
  std::ptr::drop_glue::<lsp_types::Uri>
```

With Tree Borrows, Miri reports the same shape of failure:

```text
error: Undefined Behavior: deallocation through <...> is forbidden
help: the accessed tag <...> has state Frozen which forbids this deallocation
```

## Environment

```text
rustc 1.97.0-nightly (82bee9650 2026-05-09)
binary: rustc
commit-hash: 82bee965077a631d6fbdee4014f2ec535535aaa3
commit-date: 2026-05-09
host: x86_64-unknown-linux-gnu
release: 1.97.0-nightly
LLVM version: 22.1.4

miri 0.1.0 (82bee96507 2026-05-09)

lsp-types v0.97.0
fluent-uri v0.1.4
serde_json v1.0.150
```

## Notes

I found this while running Miri experimentally on an LSP server implementation.
The issue minimized away from that project: no server code is needed to
reproduce it.

Because `lsp_types::Uri::from_str` passes and serde deserialization fails, this
may be specific to the deserialize implementation or to how ownership is handed
to `fluent_uri::Uri<String>` through that path.
