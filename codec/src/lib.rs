//! Serialize structured data.
//!
//! # Overview
//!
//! Provides traits and implementations for efficient and safe binary serialization and
//! deserialization of structured data. The library focuses on:
//!
//! - **Performance:** Uses the [bytes] crate and aims to minimize allocations.
//! - **Safety:** Deserialization of untrusted data is made safer via the `Cfg` associated type in
//!   the [Read] trait, allowing users to impose limits (like maximum lengths) or other strict
//!   constraints on the data.
//! - **Ease of Use:** Provides implementations for common Rust types and uses extension traits
//!   ([ReadExt], [DecodeExt], etc.) for ergonomic usage.
//!
//! # Core Concepts
//!
//! The library revolves around a few core traits:
//!
//! - [Write]: Implement this to define how your type is written to a byte buffer.
//! - [Read]: Implement this to define how your type is read from a byte buffer.
//!   It has an associated `Cfg` type, primarily used to enforce constraints (e.g., size limits)
//!   when reading untrusted data. Use `()` if no config is needed.
//! - [EncodeSize]: Implement this to calculate the exact encoded byte size of a value.
//!   Required for efficient buffer pre-allocation.
//! - [FixedSize]: Marker trait for types whose encoded size is constant. Automatically
//!   implements [EncodeSize].
//!
//! Helper traits combine these for convenience:
//!
//! - [Encode]: Combines [Write] + [EncodeSize]. Provides [Encode::encode()] method.
//! - [Decode]: Requires [Read]. Provides [Decode::decode_cfg()] method that ensures
//!   that the entire buffer is consumed.
//! - [Codec]: Combines [Encode] + [Decode].
//!
//! # Derive macros
//!
//! Structs and tagged enums can derive [`Write`](derive@Write) and
//! [`Read`](derive@Read). Choose [`FixedSize`](derive@FixedSize) for a constant
//! encoded length or [`EncodeSize`](derive@EncodeSize) for a value-dependent
//! length. [`Encode`](derive@Encode) is shorthand for `Write, EncodeSize`.
//! The macro documentation includes compiling examples and configuration attributes.
//!
//! # Decode Inputs
//!
//! Readers accept [Buf] inputs so decoded byte fields can share the input allocation.
//! Pass owned buffers such as [::bytes::Bytes] directly, or clone a shared buffer to retain
//! a separate cursor. Decoders also accept owned [`Vec<u8>`] values through [Input],
//! transferring their allocation without copying the payload.
//!
//! Borrowed slices require [Copying]. Creating this adapter does not allocate, so scalar
//! and byte-array reads can use reusable scratch storage. Fields that retain bytes copy
//! their contents when decoded through the adapter.
//!
//! Use [Buf] for generic readers of serialized values and every helper on that read path,
//! including fixed-size reads and length or padding validation. Use [Input] at entry
//! points that convert owned inputs into readable buffers, then preserve [Buf] internally.
//!
//! Use [::bytes::Buf] for raw buffer implementations and byte-stream inputs to I/O,
//! encoding, or hashing. When its cursor methods must be in scope alongside [Buf],
//! import it as `use bytes::Buf as _;`.
//!
//! # Specialization
//!
//! Byte-oriented container paths use hidden trait hooks on [Write], [Read], and [EncodeSize] to
//! select bulk-copy implementations while keeping generic fallbacks. Container implementations
//! call hooks such as `T::write_slice`, `T::read_vec`, and `T::encode_size_slice`. The default
//! methods preserve element-by-element behavior, while concrete element implementations can
//! override only the paths they can make faster.
//!
//! Encoding specialization has two parts: aggregate sizing and aggregate writing. For example,
//! `Vec<u8>::encode()` first asks for the output size, then writes the bytes. The [EncodeSize]
//! slice hooks let fixed-size elements compute `SIZE * len` without scanning every element, while
//! the [Write] slice hooks let byte containers write the payload with one bulk copy.
//!
//! These hooks keep the container code generic: a container like `Vec<T>` calls one element-level
//! method for sizing, writing, or reading, and the element implementation decides whether the
//! default element-by-element behavior or a bulk path applies.
//!
//! # Supported Types
//!
//! Natively supports encoding/decoding for:
//! - Primitives: [bool],
//!   [u8], [u16], [u32], [u64], [u128],
//!   [i8], [i16], [i32], [i64], [i128],
//!   [f32], [f64], and [usize] (must fit within a [u32] for cross-platform compatibility).
//! - Arrays: `[T; N]` supports [Write] and [Read] when `T` does, and supports [FixedSize],
//!   [Encode], [Codec], [EncodeFixed], and [CodecFixed] when `T: FixedSize`.
//! - Collections: [`Vec`], [`Option`], `BTreeMap`, `BTreeSet`
//! - Tuples: `(T1, T2, ...)` (up to 12 elements)
//! - Common External Types: [::bytes::Bytes], `Arc<T>` (delegates to `T`)
//!
//! With the `std` feature (enabled by default):
//! - Networking:
//!   [`std::net::Ipv4Addr`],
//!   [`std::net::Ipv6Addr`],
//!   [`std::net::SocketAddrV4`],
//!   [`std::net::SocketAddrV6`],
//!   [`std::net::IpAddr`],
//!   [`std::net::SocketAddr`]
//! - Collections:
//!   [`std::collections::HashMap`],
//!   [`std::collections::HashSet`]
//!
//! # Implementing for Custom Types
//!
//! You typically need to implement [Write], [EncodeSize] (unless [FixedSize]), and [Read]
//! for your custom structs and enums.
//!
//! ## Example 1. Fixed-Size Type
//!
//! ```
//! use commonware_codec::{DecodeExt, Encode, FixedSize, Read, Write};
//!
//! // Define a custom struct
//! #[derive(Debug, Clone, PartialEq, Write, Read, FixedSize)]
//! struct Point {
//!     x: u32, // FixedSize
//!     y: u32, // FixedSize
//! }
//!
//! // Point now automatically implements Encode, Decode, Codec
//! let point = Point { x: 1, y: 2 };
//!
//! // Encode is available via FixedSize + Write
//! let bytes = point.encode();
//! assert_eq!(bytes.len(), Point::SIZE);
//!
//! // Decode is available via Read, use DecodeExt
//! let decoded_point = Point::decode(bytes).unwrap();
//! assert_eq!(point, decoded_point);
//! ```
//!
//! ## Example 2. Variable-Size Type
//!
//! ```
//! use commonware_codec::{Decode, Encode, Read};
//!
//! // Define a simple configuration for reading Item
//! // Here, it just specifies the maximum allowed metadata length.
//! #[derive(Clone)]
//! pub struct ItemConfig {
//!     max_metadata_len: usize,
//! }
//!
//! // Define a custom struct
//! #[derive(Debug, Clone, PartialEq, Encode, Read)]
//! #[read_cfg(ItemConfig)]
//! struct Item {
//!     #[codec(cfg = &())]
//!     id: u64,           // FixedSize
//!     #[codec(cfg = &())]
//!     name: Option<u32>, // EncodeSize (depends on Option)
//!     #[codec(cfg = &((0..=cfg.max_metadata_len).into(), ()))]
//!     metadata: Vec<u8>, // EncodeSize (variable)
//! }
//!
//! // Now you can use Encode and Decode:
//! let item = Item { id: 101, name: None, metadata: vec![1, 2, 3] };
//! let config = ItemConfig { max_metadata_len: 1024 };
//!
//! // Encode the item (uses Write + EncodeSize)
//! let bytes = item.encode(); // Returns BytesMut
//!
//! // Decode the item
//! // decode_cfg ensures all bytes are consumed.
//! let decoded_item = Item::decode_cfg(bytes, &config).unwrap();
//! assert_eq!(item, decoded_item);
//! ```

#![doc(
    html_logo_url = "https://commonware.xyz/imgs/rustdoc_logo.svg",
    html_favicon_url = "https://commonware.xyz/favicon.ico"
)]
#![cfg_attr(not(any(feature = "std", test)), no_std)]

// Derive expansions use this path both inside the library and in consumer targets.
#[allow(unused_extern_crates)]
extern crate self as commonware_codec;

commonware_macros::stability_scope!(BETA {
    #[cfg(not(feature = "std"))]
    extern crate alloc;

    mod buf;
    pub use buf::{Buf, Copying, Input};

    pub mod codec;
    pub mod config;
    pub mod error;
    pub mod extensions;
    pub mod mode;
    pub mod types;
    pub mod util;
    pub mod varint;

    // Re-export main types and traits
    pub use codec::*;
    mod derive;
    pub use derive::*;
    #[doc(hidden)]
    pub use bytes::BufMut as __BufMut;
    pub use config::RangeCfg;
    pub use error::Error;
    pub use extensions::*;
    pub use mode::{InvalidMode, Mode, Modes};
});

commonware_macros::stability_scope!(ALPHA {
    #[cfg(test)]
    mod derive_tests;

    #[cfg(feature = "arbitrary")]
    pub mod conformance;

    // Re-export paste for use in conformance macros
    #[cfg(feature = "arbitrary")]
    #[doc(hidden)]
    pub use paste;
});
