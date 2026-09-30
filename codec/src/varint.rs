//! Variable-length integer encoding and decoding
//!
//! # Overview
//!
//! This module implements Google's Protocol Buffers variable-length integer encoding.
//! Each byte uses:
//! - 7 bits for the value
//! - 1 "continuation" bit to indicate if more bytes follow
//!
//! `u8` and `i8` are omitted since those types do not benefit from varint encoding.
//!
//! `usize` and `isize` are omitted to prevent behavior from depending on the target architecture.
//!
//! # Usage Example
//!
//! ```rust
//! use commonware_codec::{Encode, DecodeExt, varint::{UInt, SInt}};
//!
//! // Unsigned example
//! let one = UInt(42u128).encode();
//! assert_eq!(one.len(), 1); // 42 fits in a single byte
//! let decoded: u128 = UInt::decode(one).unwrap().into();
//! assert_eq!(decoded, 42);
//!
//! // Signed example (ZigZag)
//! let neg = SInt(-3i32).encode();
//! assert_eq!(neg.len(), 1);
//! let decoded: i32 = SInt::decode(neg).unwrap().into();
//! assert_eq!(decoded, -3);
//! ```

// The verified module (sandblaster module mode, DESIGN.md §2.1): the code of this
// module is `sandblaster/varint/varint.rs` (this file's original body, as-is), which
// build.rs verifies against `sandblaster/varint/LAWS.rs` and writes to OUT_DIR.
// build.rs checks that this file is exactly these docs and the include line.
include!(concat!(env!("OUT_DIR"), "/varint.rs"));
