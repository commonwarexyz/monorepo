//! Serialize structured data.
//!
//! # Overview
//!
//! Provides traits and implementations for efficient and safe binary serialization and
//! deserialization of structured data. The library focuses on:
//!
//! - **Performance:** Uses the [`bytes`] crate and aims to minimize allocations.
//! - **Safety:** Deserialization of untrusted data is made safer via the [`Config`] system for the
//!   [`Read`] trait, allowing users to impose limits (like maximum lengths) or other strict
//!   constraints on the data.
//! - **Ease of Use:** Provides implementations for common Rust types and uses extension traits
//!   ([`ReadExt`], [`DecodeExt`], etc.) for ergonomic usage.
//!
//! # Core Concepts
//!
//! The library revolves around a few core traits:
//!
//! - [`Write`]: Implement this to define how your type is written to a byte buffer.
//! - [`Read<Cfg>`]: Implement this to define how your type is read from a byte buffer.
//!   It takes a configuration `Cfg` parameter, primarily used to enforce constraints
//!   (e.g., size limits) when reading untrusted data. Use `()` if no config is needed.
//! - [`EncodeSize`]: Implement this to calculate the exact encoded byte size of a value.
//!   Required for efficient buffer pre-allocation.
//! - [`FixedSize`]: Marker trait for types whose encoded size is constant. Automatically
//!   implements [`EncodeSize`].
//!
//! Helper traits combine these for convenience:
//!
//! - [`Encode`]: Combines [`Write`] + [`EncodeSize`]. Provides [`Encode::encode()`] method.
//! - [`Decode<Cfg>`]: Requires [`Read<Cfg>`]. Provides [`Decode::decode_cfg()`] method that ensures
//!   that the entire buffer is consumed.
//! - [`Codec<Cfg>`]: Combines [`Encode`] + [`Decode<Cfg>`].
//!
//! # Supported Types
//!
//! Natively supports encoding/decoding for:
//! - Primitives: [`bool`],
//!   [`u8`], [`u16`], [`u32`], [`u64`], [`u128`],
//!   [`i8`], [`i16`], [`i32`], [`i64`], [`i128`],
//!   [`f32`], [`f64`], `[u8; N]`
//! - Collections: [`Vec<T>`], [`Option<T>`]
//! - Tuples: `(T1, T2, ...)` (up to 12 elements)
//! - Networking:
//!   [`Ipv4Addr`](`std::net::Ipv4Addr`),
//!   [`Ipv6Addr`](`std::net::Ipv6Addr`),
//!   [`SocketAddrV4`](`std::net::SocketAddrV4`),
//!   [`SocketAddrV6`](`std::net::SocketAddrV6`),
//!   [`SocketAddr`](`std::net::SocketAddr`)
//! - Common External Types: [`bytes::Bytes`]
//!
//! # Implementing for Custom Types
//!
//! You typically need to implement [`Write`], [`EncodeSize`] (unless [`FixedSize`]), and [`Read<Cfg>`]
//! for your custom structs and enums.
//!
//! ## Example (Fixed Size Type)
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
//!     fn read_cfg(buf: &mut impl Buf, _: ()) -> Result<Self, Error> {
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
//! // Decode is available via Read<()>, use DecodeExt
//! let decoded_point = Point::decode(bytes).unwrap();
//! assert_eq!(point, decoded_point);
//! ```
//!
//! ## Example (Variable Size Type)
//!
//! ```
//! use bytes::{Buf, BufMut};
//! use commonware_codec::{
//!     Config, Decode, Encode, EncodeSize, Error, FixedSize, Read, ReadExt,
//!     ReadRangeExt, Write, RangeConfig
//! };
//! use std::ops::RangeInclusive; // Example RangeConfig
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
//! // 3. Implement Read<Cfg>
//! impl Read<ItemConfig> for Item {
//!     // Use the config Cfg = ItemConfig
//!     fn read_cfg(buf: &mut impl Buf, cfg: ItemConfig) -> Result<Self, Error> {
//!         // u64 requires Cfg = (), uses ReadExt::read
//!         let id = <u64>::read(buf)?;
//!
//!         // Option<u32> requires Cfg = (), uses ReadExt::read
//!         let name = <Option<u32>>::read(buf)?;
//!
//!         // For Vec<u8>, the required config is (RangeConfig, InnerConfig)
//!         // InnerConfig for u8 is (), so we need (RangeConfig, ())
//!         // We use ReadRangeExt::read_range which handles the () for us.
//!         // The RangeConfig limits the vector length using our ItemConfig.
//!         let metadata_range = 0..=cfg.max_metadata_len; // Create the RangeConfig
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
//! // Decode the item (uses Read<ItemConfig>)
//! // decode_cfg ensures all bytes are consumed.
//! let decoded_item = Item::decode_cfg(bytes, config).unwrap();
//! assert_eq!(item, decoded_item);
//! ```

pub mod codec;
pub mod config;
pub mod error;
pub mod extensions;
pub mod types;
pub mod util;
pub mod varint;

// Re-export main types and traits
pub use codec::*;
pub use config::{Config, Pair, RangeConfig};
pub use error::Error;
pub use extensions::*;
pub use types::{net, primitives};
