# commonware-codec

[![Crates.io](https://img.shields.io/crates/v/commonware-codec.svg)](https://crates.io/crates/commonware-codec)
[![Docs.rs](https://docs.rs/commonware-codec/badge.svg)](https://docs.rs/commonware-codec)

Serialize structured data.

## Deriving

`Write`, `EncodeSize`, `FixedSize`, and `Read` can be derived for types whose encoding is a plain field-order fold. Hand-write `Read` only when decoding must validate: a manual `read_cfg` marks the types that check more than structure.

## Status 

Stability varies by primitive. See [README](https://github.com/commonwarexyz/monorepo#stability) for details.