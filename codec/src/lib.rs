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
//! # Example
//!
//! ```
//! use bytes::{Buf, BufMut};
//! use commonware_codec::{Encode, Decode, Error};
//!
//! // Define a custom struct
//! #[derive(Debug, Clone, PartialEq)]
//! struct Point {
//!     xy: (u64, u64),
//!     z: Option<u32>,
//!     metadata: [u8; 11],
//! }
//!
//! // Implement the Encode trait
//! impl Encode for Point {
//!     fn len_encoded(&self) -> usize {
//!       self.xy.len_encoded() + self.z.len_encoded() + self.metadata.len_encoded()
//!     }
//!
//!     fn write(&self, buf: &mut impl BufMut) {
//!         // Basic types can be written by inferring the type
//!         self.xy.write(buf);
//!         self.z.write(buf);
//!         self.metadata.write(buf);
//!     }
//! }
//!
//! // Implement the Decode trait
//! impl Decode<()> for Point {
//!     fn read(buf: &mut impl Buf, _: ()) -> Result<Self, Error> {
//!         // Basic types can be inferred by the return type
//!         let xy = <(u64, u64)>::read(buf, ((), ()))?;
//!         let z = <Option<u32>>::read(buf, ())?;
//!         let metadata = <[u8; 11]>::read(buf, ())?;
//!         Ok(Self { xy, z, metadata })
//!     }
//! }
//! ```

pub mod codec;
pub mod error;
pub mod types;
pub mod util;
pub mod varint;

// Re-export main types and traits
pub use codec::{Codec, Decode, Encode, SizedCodec, SizedDecode, SizedEncode, SizedInfo};
pub use error::Error;
pub use types::{net, primitives};
