//! Byte decoding.
use sandblaster::prelude::*;

#[requires(off <= s.len() && s.len() - off >= 4)]
fn read4(s: &[u8], off: usize) -> [u8; 4] {
    [s[off], s[off + 1], s[off + 2], s[off + 3]]
}

pub fn read_u32_be(s: &[u8]) -> Option<u32> {
    if s.len() < 4 {
        return None;
    }
    let b = read4(s, 0);
    Some(u32::from_be_bytes(b))
}
