# commonware-codec-derive

Derive macros for `commonware-codec` traits.

This crate provides procedural derive macros for automatically implementing the `Read`, `Write`, and `EncodeSize` traits from `commonware-codec`.

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
commonware-codec = "0.0.54"
commonware-codec-derive = "0.0.54"
```

Then derive the traits on your structs:

```rust
use commonware_codec::{Read, Write, EncodeSize};
use commonware_codec_derive::{Read, Write, EncodeSize};

#[derive(Debug, Clone, PartialEq, Read, Write, EncodeSize)]
struct Point {
    x: u32,
    y: u32,
}

// The traits are now automatically implemented!
```

## Supported Types

The derive macros work with:
- Structs with named fields
- Tuple structs  
- Unit structs

All fields must implement the corresponding traits.

## Limitations

- The generated `Read` implementation uses `()` as the `Cfg` type
- Enums are not supported
- Unions are not supported