# commonware-codec

[![Crates.io](https://img.shields.io/crates/v/commonware-codec.svg)](https://crates.io/crates/commonware-codec)
[![Docs.rs](https://docs.rs/commonware-codec/badge.svg)](https://docs.rs/commonware-codec)

Serialize structured data.

## Deriving

`Write`, `EncodeSize`, `FixedSize`, and `Read` can be derived for types whose encoding is a plain field-order fold. On a derived type, field declaration order is the wire format: reordering fields is a wire-format change, so every derived type should be pinned by a conformance fixture. Keep an impl hand-written when decoding must validate beyond structure, when the config needs adapting before it reaches a field, or when the encoding is not a plain fold (varint transforms, skipped fields, padded frames, `Lazy` fields).

## Status 

Stability varies by primitive. See [README](https://github.com/commonwarexyz/monorepo#stability) for details.