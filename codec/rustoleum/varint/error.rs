//! Host interface: `commonware_codec::Error` (codec/src/error.rs), the
//! variants `varint.rs` builds. The others (`Invalid`, `Wrapped`, ...) carry
//! `&'static str` or boxed errors and are never built by varint, so they are
//! not modeled; the laws only compare against these two.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// `Error::EndOfBuffer`.
    EndOfBuffer,
    /// `Error::InvalidVarint(usize)`: the byte width of the target type.
    InvalidVarint(usize),
}
