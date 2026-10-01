//! A small codec in the shape of commonware-codec's varint.

use crate::{Buf, Error};
use bytes::BufMut;
use sealed::SPrim;

mod sealed {
    pub trait SPrim: Copy {
        fn zz(self) -> u32;
    }
    impl SPrim for i32 {
        fn zz(self) -> u32 {
            ((self << 1) ^ (self >> 31)) as u32
        }
    }
    impl SPrim for i16 {
        fn zz(self) -> u32 {
            (((self << 1) ^ (self >> 15)) as u16) as u32
        }
    }
}

/// An accumulator of at most 100 bytes.
#[derive(Debug, Clone)]
pub struct Acc {
    total: u32,
    count: u8,
}

impl Acc {
    pub fn new() -> Self {
        Self { total: 0, count: 0 }
    }

    pub fn add(&mut self, b: u8) -> bool {
        if self.count >= 100 {
            return false;
        }
        self.total = self.total.wrapping_add(b as u32);
        self.count += 1;
        true
    }
}

/// Writes `a`, `b` and, when `a` has its top bit set, `a ^ b`.
pub fn put_pair(a: u8, b: u8, buf: &mut impl BufMut) {
    let bytes = [a, b, a ^ b];
    let n: usize = if a < 128 { 1 } else { 2 };
    buf.put_slice(&bytes[..=n]);
}

/// Reads a big-endian `u16`.
pub fn take2(buf: &mut impl Buf) -> Result<u16, Error> {
    let hi = buf.try_get_u8().map_err(|_| Error::EndOfBuffer)?;
    let lo = buf.try_get_u8().map_err(|_| Error::EndOfBuffer)?;
    Ok(((hi as u16) << 8) | lo as u16)
}

/// ZigZag of a signed value.
pub fn zigzag<S: SPrim>(x: S) -> u32 {
    x.zz()
}
