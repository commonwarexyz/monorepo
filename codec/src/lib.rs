//! Serialize structured data.
//!
//! # Overview
//!
//! A binary serialization library designed to efficiently and safely:
//! - Serialize structured data into a binary format
//! - Deserialize untrusted binary input into structured data
//!
//! # Supported Types
//!
//! Natively supports:
//! - Primitives: `u8`, `u16`, `u32`, `u64`, `i8`, `i16`, `i32`, `i64`, `f32`, `f64`, `bool`
//! - Collections: `Vec<T>`, `Option<T>`, tuples, and fixed-size arrays like `[u8; N]`
//! - Recursive serialization of nested structs and enums via trait implementations
//!
//! User-defined types can be serialized and deserialized by implementing the `Codec` trait.
//! For types with a constant encoded size, optionally implement the `SizedCodec` trait.
//!
//! # Example (Variable Size)
//!
//! ```
//! use bytes::{Buf, BufMut};
//! use commonware_codec::{Encode, Error, Read, ReadExt, Write};
//!
//! // Define a custom struct
//! #[derive(Debug, Clone, PartialEq)]
//! struct Item {
//!     xy: (u64, u64),
//!     z: Option<u32>,
//!     metadata: [u8; 11],
//! }
//!
//! // Implement the `Write` trait
//! impl Write for Item {
//!     fn write(&self, buf: &mut impl BufMut) {
//!         self.xy.write(buf);
//!         self.z.write(buf);
//!         self.metadata.write(buf);
//!     }
//! }
//!
//! // Implement the `Read` trait
//! impl Read for Item {
//!     fn read_cfg(buf: &mut impl Buf, _: ()) -> Result<Self, Error> {
//!         let xy = <(u64, u64)>::read(buf)?;
//!         let z = <Option<u32>>::read(buf)?;
//!         let metadata = <[u8; 11]>::read(buf)?;
//!         Ok(Self { xy, z, metadata })
//!     }
//! }
//!
//! // Since `Item` has a variable size, we implement the `len_encoded` method manually.
//! impl Encode for Item {
//!     fn len_encoded(&self) -> usize {
//!       self.xy.len_encoded() + self.z.len_encoded() + self.metadata.len_encoded()
//!     }
//! }
//! ```
//!
//! # Example (Fixed Size)
//!
//! ```
//! use bytes::{Buf, BufMut};
//! use commonware_codec::{Error, FixedSize, Read, ReadExt, Write};
//!
//! // Define a custom struct
//! #[derive(Debug, Clone, PartialEq)]
//! struct Point {
//!     x: u32,
//!     y: u32,
//! }
//!
//! // Implement the `Write` trait
//! impl Write for Point {
//!     fn write(&self, buf: &mut impl BufMut) {
//!         self.x.write(buf);
//!         self.y.write(buf);
//!     }
//! }
//!
//! // Implement the `Read` trait
//! impl Read for Point {
//!     fn read_cfg(buf: &mut impl Buf, _: ()) -> Result<Self, Error> {
//!         let x = <u32>::read(buf)?;
//!         let y = <u32>::read(buf)?;
//!         Ok(Self { x, y })
//!     }
//! }
//!
//! // Since `Point` has a fixed size, we implement `FixedSize`.
//! impl FixedSize for Point {
//!     const LEN_ENCODED: usize = u32::LEN_ENCODED + u32::LEN_ENCODED;
//! }
//! ```

pub mod codec;
pub mod error;
pub mod types;
pub mod util;
pub mod varint;

// Re-export main types and traits
pub use codec::{Codec, Decode, DecodeExt, Encode, EncodeFixed, FixedSize, Read, ReadExt, Write};
pub use error::Error;
pub use types::{net, primitives};
