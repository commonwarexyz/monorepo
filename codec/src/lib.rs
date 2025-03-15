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
//! use commonware_codec::{Codec, Reader, Writer, Error};
//!
//! // Define a custom struct
//! #[derive(Debug, Clone, PartialEq)]
//! struct Point {
//!     xy: (u64, u64),
//!     z: Option<u32>,
//!     metadata: [u8; 11],
//! }
//!
//! // Implement the Codec trait
//! impl Codec for Point {
//!     fn write(&self, writer: &mut impl Writer) {
//!         // Basic types can be written by inferring the type
//!         self.xy.write(writer);
//!         self.z.write(writer);
//!         self.metadata.write(writer);
//!     }
//!
//!     fn read(reader: &mut impl Reader) -> Result<Self, Error> {
//!         // Basic types can be inferred by the return type
//!         let xy = <(u64, u64)>::read(reader)?;
//!         let z = <Option<u32>>::read(reader)?;
//!         let metadata = <[u8; 11]>::read(reader)?;
//!         Ok(Self { xy, z, metadata })
//!     }
//!
//!     fn len_encoded(&self) -> usize {
//!       self.xy.len_encoded() + self.z.len_encoded() + self.metadata.len_encoded()
//!     }
//! }
//! ```

pub mod buffer;
pub mod codec;
pub mod error;
pub mod types;
pub mod varint;

// Re-export main types and traits
pub use buffer::{ReadBuffer, WriteBuffer};
pub use codec::{Codec, Reader, SizedCodec, Writer};
pub use error::Error;
