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
//! - Markers: `PhantomData<T>` (encodes as zero bytes)
//! - Common External Types: [::bytes::Bytes], `Arc` (encoding only)
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
//! for your custom structs and enums. When the encoding is a plain field-order fold with no
//! decode-time validation, derive them instead (see [Write](macro@Write), [EncodeSize](macro@EncodeSize),
//! [FixedSize](macro@FixedSize), and [Read](macro@Read)). A hand-written [Read] signals that the
//! type checks something beyond structure.
//!
//! ## Example 1. Fixed-Size Type
//!
//! ```
//! use bytes::{Buf, BufMut};
//! use commonware_codec::{Error, FixedSize, Read, ReadExt, Write, Encode, DecodeExt};
//!
//! // Define a custom struct
//! #[derive(Debug, Clone, PartialEq)]
//! struct Point {
//!     x: u32, // FixedSize
//!     y: u32, // FixedSize
//! }
//!
//! // 1. Implement Write: How to serialize the struct
//! impl Write for Point {
//!     fn write(&self, buf: &mut impl BufMut) {
//!         // u32 implements Write
//!         self.x.write(buf);
//!         self.y.write(buf);
//!     }
//! }
//!
//! // 2. Implement FixedSize (provides EncodeSize automatically)
//! impl FixedSize for Point {
//!     // u32 implements FixedSize
//!     const SIZE: usize = u32::SIZE + u32::SIZE;
//! }
//!
//! // 3. Implement Read: How to deserialize the struct (uses default Cfg = ())
//! impl Read for Point {
//!     type Cfg = ();
//!     fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, Error> {
//!         // Use ReadExt::read for ergonomic reading when Cfg is ()
//!         let x = u32::read(buf)?;
//!         let y = u32::read(buf)?;
//!         Ok(Self { x, y })
//!     }
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
//! use bytes::{Buf, BufMut};
//! use commonware_codec::{
//!     Decode, Encode, EncodeSize, Error, FixedSize, Read, ReadExt,
//!     ReadRangeExt, Write, RangeCfg
//! };
//! use core::ops::RangeInclusive; // Example RangeCfg
//!
//! // Define a simple configuration for reading Item
//! // Here, it just specifies the maximum allowed metadata length.
//! #[derive(Clone)]
//! pub struct ItemConfig {
//!     max_metadata_len: usize,
//! }
//!
//! // Define a custom struct
//! #[derive(Debug, Clone, PartialEq)]
//! struct Item {
//!     id: u64,           // FixedSize
//!     name: Option<u32>, // EncodeSize (depends on Option)
//!     metadata: Vec<u8>, // EncodeSize (variable)
//! }
//!
//! // 1. Implement Write
//! impl Write for Item {
//!     fn write(&self, buf: &mut impl BufMut) {
//!         self.id.write(buf);       // u64 implements Write
//!         self.name.write(buf);     // Option<u32> implements Write
//!         self.metadata.write(buf); // Vec<u8> implements Write
//!     }
//! }
//!
//! // 2. Implement EncodeSize
//! impl EncodeSize for Item {
//!     fn encode_size(&self) -> usize {
//!         // Sum the sizes of the parts
//!         self.id.encode_size()         // u64 implements EncodeSize (via FixedSize)
//!         + self.name.encode_size()     // Option<u32> implements EncodeSize
//!         + self.metadata.encode_size() // Vec<u8> implements EncodeSize
//!     }
//! }
//!
//! // 3. Implement Read
//! impl Read for Item {
//!     type Cfg = ItemConfig;
//!     fn read_cfg(buf: &mut impl Buf, cfg: &ItemConfig) -> Result<Self, Error> {
//!         // u64 requires Cfg = (), uses ReadExt::read
//!         let id = <u64>::read(buf)?;
//!
//!         // Option<u32> requires Cfg = (), uses ReadExt::read
//!         let name = <Option<u32>>::read(buf)?;
//!
//!         // For Vec<u8>, the required config is (RangeCfg, InnerConfig)
//!         // InnerConfig for u8 is (), so we need (RangeCfg, ())
//!         // We use ReadRangeExt::read_range which handles the () for us.
//!         // The RangeCfg limits the vector length using our ItemConfig.
//!         let metadata_range = 0..=cfg.max_metadata_len; // Create the RangeCfg
//!         let metadata = <Vec<u8>>::read_range(buf, metadata_range)?;
//!
//!         Ok(Self { id, name, metadata })
//!     }
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

// Let derive-generated `::commonware_codec` paths resolve inside this crate itself.
#[allow(unused_extern_crates)]
extern crate self as commonware_codec;

commonware_macros::stability_scope!(BETA {
    #[cfg(not(feature = "std"))]
    extern crate alloc;

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
    pub use commonware_codec_macros::FixedArray;
    pub use config::RangeCfg;
    pub use error::Error;
    pub use extensions::*;
    pub use mode::{InvalidMode, Mode, Modes};

    // Names referenced by derive-generated code; not public API.
    #[doc(hidden)]
    pub mod __private {
        pub use bytes::{Buf, BufMut};

        use crate::IsUnit;

        /// Returns the unit-like config value (`C::default()`) for an unmarked derived field.
        pub fn unit_cfg<C: IsUnit>() -> C {
            C::default()
        }
    }

    /// Derives [Write](trait@Write) by writing each field in declaration order; enum variants
    /// write their mandatory `#[codec(tag = N)]` byte first, and `write_bufs` forwards to each
    /// field's `write_bufs`.
    ///
    /// Field declaration order is the wire format: reordering the fields of a derived type is
    /// a wire-format change.
    ///
    /// All four codec derives accept `#[codec(bound = "...")]` to replace the auto-generated
    /// per-field bounds (an empty string keeps only the type's inherited bounds). The generated
    /// bounds are per-field (`FieldTy: Write`), so a generic-mentioning field's type appears in
    /// the impl's public where clause.
    ///
    /// ```
    /// use commonware_codec::{DecodeExt, Encode, EncodeSize, Read, Write};
    ///
    /// #[derive(Debug, PartialEq, Write, EncodeSize, Read)]
    /// struct Item {
    ///     id: u32,
    ///     label: Option<u8>,
    /// }
    ///
    /// #[derive(Debug, PartialEq, Write, EncodeSize, Read)]
    /// enum Message {
    ///     #[codec(tag = 0)]
    ///     Ping,
    ///     #[codec(tag = 7)]
    ///     Item(Item),
    /// }
    ///
    /// let message = Message::Item(Item { id: 1, label: None });
    /// let encoded = message.encode();
    /// assert_eq!(encoded[0], 7);
    /// assert_eq!(Message::decode(encoded).unwrap(), message);
    /// ```
    ///
    /// Duplicate tags are rejected at compile time:
    /// ```compile_fail
    /// #[derive(commonware_codec::Write)]
    /// enum Bad {
    ///     #[codec(tag = 0)]
    ///     A,
    ///     #[codec(tag = 0)]
    ///     B,
    /// }
    /// ```
    pub use commonware_codec_macros::Write;

    /// Derives [EncodeSize](trait@EncodeSize) as the sum of field sizes, plus one tag byte for
    /// enums; `encode_inline_size` forwards to each field's `encode_inline_size`.
    ///
    /// Derive [Write](macro@Write) and [EncodeSize](macro@EncodeSize) together: the generated
    /// `write_bufs` and `encode_inline_size` are a matched pair, and mixing a derived half with
    /// a manual half that keeps the trait defaults breaks the inline-size contract.
    ///
    /// Deriving this alongside [FixedSize](trait@FixedSize) fails to compile: `FixedSize`
    /// provides [EncodeSize](trait@EncodeSize) through a blanket impl.
    pub use commonware_codec_macros::EncodeSize;

    /// Derives [FixedSize](trait@FixedSize) with `SIZE` the sum of field sizes.
    ///
    /// ```
    /// use commonware_codec::{FixedSize, Read, Write};
    ///
    /// #[derive(Write, Read, FixedSize)]
    /// struct Pair {
    ///     a: u32,
    ///     b: [u8; 8],
    /// }
    ///
    /// assert_eq!(Pair::SIZE, 12);
    /// ```
    ///
    /// Enums are rejected (variants differ in size):
    /// ```compile_fail
    /// #[derive(commonware_codec::FixedSize)]
    /// enum Bad {
    ///     #[codec(tag = 0)]
    ///     A,
    /// }
    /// ```
    pub use commonware_codec_macros::FixedSize;

    /// Derives [Read](trait@Read) by reading each field in declaration order.
    ///
    /// `Cfg` is `()` unless exactly one field (or at most one per enum variant) is marked
    /// `#[codec(cfg)]`, in which case that field's [Read::Cfg](trait@Read) becomes the
    /// container's and receives the caller's config; every other field must have a unit-like
    /// ([IsUnit]) config. When multiple enum variants carry `#[codec(cfg)]` fields, their `Cfg`
    /// types must all be the container's (taken from the first such field in declaration
    /// order). Unknown enum tags yield [Error::InvalidEnum].
    ///
    /// ```
    /// use bytes::Bytes;
    /// use commonware_codec::{Decode, Encode, EncodeSize, RangeCfg, Read, Write};
    ///
    /// #[derive(Debug, PartialEq, Write, EncodeSize, Read)]
    /// struct Blob {
    ///     seq: u64,
    ///     #[codec(cfg)]
    ///     data: Bytes,
    /// }
    ///
    /// let blob = Blob { seq: 9, data: Bytes::from_static(b"abc") };
    /// let cfg: RangeCfg<usize> = (0..=16).into();
    /// assert_eq!(Blob::decode_cfg(blob.encode(), &cfg).unwrap(), blob);
    /// ```
    ///
    /// A field with a non-unit config must be marked `#[codec(cfg)]`:
    /// ```compile_fail
    /// #[derive(commonware_codec::Read)]
    /// struct Bad {
    ///     data: bytes::Bytes,
    /// }
    /// ```
    ///
    /// At most one field may be marked:
    /// ```compile_fail
    /// #[derive(commonware_codec::Read)]
    /// struct Bad {
    ///     #[codec(cfg)]
    ///     a: bytes::Bytes,
    ///     #[codec(cfg)]
    ///     b: bytes::Bytes,
    /// }
    /// ```
    pub use commonware_codec_macros::Read;
});

commonware_macros::stability_scope!(ALPHA {
    #[cfg(feature = "arbitrary")]
    pub mod conformance;

    // Re-export paste for use in conformance macros
    #[cfg(feature = "arbitrary")]
    #[doc(hidden)]
    pub use paste;
});
