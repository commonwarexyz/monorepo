//! The buffer model in Rust (TCB item "buffer model", DESIGN.md §1.1): the
//! `bytes` crate as the lift conformance harness links it
//! (`sandblaster_front::conform`). It is compiled as the crate `bytes`, so the
//! lifted source's `use bytes::BufMut;` and the host shim's `bytes::Buf`
//! resolve here. Only the calls the lift models are provided (a source that
//! calls another is refused by the lift before the harness exists):
//!
//! | call | meaning (the same as `crate::__lift_model`) |
//! | --- | --- |
//! | `BufMut::put_u8(n)` | append `n` |
//! | `BufMut::put_slice(s)` | append `s` |
//! | `Buf::try_get_u8()` | the first byte, consumed; `Err` (consuming nothing) when empty |
//! | `Buf::remaining()` | the number of bytes not yet read |
//!
//! Each body follows the corresponding `bytes` 1.x default method on a
//! `Vec<u8>` (`BufMut`) and a `&[u8]` (`Buf`). The pilot's `vshim` binary
//! compares this file with the real `bytes` crate on random operation
//! sequences (`pilots/codec-varint/vshim`).

/// `bytes::TryGetError`: the requested and available byte counts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TryGetError {
    pub requested: usize,
    pub available: usize,
}

/// `bytes::Buf` (the calls the lift models).
pub trait Buf {
    /// Bytes not yet read.
    fn remaining(&self) -> usize;
    /// The unread bytes (one contiguous chunk: every model buffer is one).
    fn chunk(&self) -> &[u8];
    /// Consumes `n` bytes; panics when fewer remain (as `bytes`).
    fn advance(&mut self, n: usize);

    /// `bytes::Buf::try_get_u8`.
    fn try_get_u8(&mut self) -> Result<u8, TryGetError> {
        if self.remaining() < 1 {
            return Err(TryGetError { requested: 1, available: self.remaining() });
        }
        let b = self.chunk()[0];
        self.advance(1);
        Ok(b)
    }
}

impl Buf for &[u8] {
    fn remaining(&self) -> usize {
        self.len()
    }
    fn chunk(&self) -> &[u8] {
        self
    }
    fn advance(&mut self, n: usize) {
        if self.len() < n {
            panic!("cannot advance past `remaining`: {:?} <= {:?}", n, self.len());
        }
        *self = &self[n..];
    }
}

/// `bytes::BufMut` (the calls the lift models).
pub trait BufMut {
    /// `bytes::BufMut::put_u8`.
    fn put_u8(&mut self, n: u8);
    /// `bytes::BufMut::put_slice`.
    fn put_slice(&mut self, src: &[u8]);
}

impl BufMut for Vec<u8> {
    fn put_u8(&mut self, n: u8) {
        self.push(n);
    }
    fn put_slice(&mut self, src: &[u8]) {
        self.extend_from_slice(src);
    }
}
