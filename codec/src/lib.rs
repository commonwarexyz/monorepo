//! Serialize structured data.
//!
//! This crate provides a binary serialization framework with strong safety guarantees,
//! better performance, and a more ergonomic API.
//!
//! # Endianness
//!
//! All multi-byte values are encoded in network byte order (big-endian).
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
//!         writer.write(&self.xy);
//!         writer.write(&self.z);
//!         writer.write(&self.metadata);
//!     }
//!
//!     fn read(reader: &mut impl Reader) -> Result<Self, Error> {
//!         // Basic types can be inferred by the return type
//!         let xy = reader.read()?;
//!         let z = reader.read()?;
//!         let metadata = reader.read()?;
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
