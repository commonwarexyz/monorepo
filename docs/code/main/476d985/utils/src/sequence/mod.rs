use commonware_codec::{Codec, EncodeFixed};
use core::{
    cmp::{Ord, PartialOrd},
    error::Error as CoreError,
    fmt::{Debug, Display},
    hash::Hash,
    ops::Deref,
};
use thiserror::Error;

pub mod fixed_bytes;
pub use fixed_bytes::FixedBytes;
pub mod u64;
pub use u64::U64;
pub mod prefixed_u64;
pub mod u32;
pub use u32::U32;
pub mod unit;
pub use unit::Unit;

/// Errors returned by the `Array` trait's functions.
#[derive(Error, Debug, PartialEq)]
pub enum Error<E: CoreError + Send + Sync + 'static> {
    #[error("invalid bytes")]
    InsufficientBytes,
    #[error("other: {0}")]
    Other(E),
}

/// Types that can be read from a variable-size byte sequence.
///
/// `Span` is typically used to parse things like requests from an untrusted
/// network connection (with variable-length fields). Once parsed, these types
/// are assumed to be well-formed (which prevents duplicate validation).
pub trait Span:
    Clone
    + Send
    + Sync
    + 'static
    + Eq
    + PartialEq
    + Ord
    + PartialOrd
    + Debug
    + Hash
    + Display
    + Codec<Cfg = ()>
{
}

impl Span for u8 {}
impl Span for u16 {}
impl Span for u32 {}
impl Span for u64 {}
impl Span for u128 {}
impl Span for i8 {}
impl Span for i16 {}
impl Span for i32 {}
impl Span for i64 {}
impl Span for i128 {}

/// Types that can be fallibly read from a fixed-size byte sequence.
///
/// `Array` is typically used to parse things like `PublicKeys` and `Signatures`
/// from an untrusted network connection. Once parsed, these types are assumed
/// to be well-formed (which prevents duplicate validation).
pub trait Array: Span + EncodeFixed + AsRef<[u8]> + Deref<Target = [u8]> {}
