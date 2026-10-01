//! Buffer writes, the obvious way.
use bytes::BufMut;

/// The low three bits, clamped to 7.
fn low3(x: u8) -> u8 {
    let y = x & 7;
    if y > 7 { 7 } else { y }
}

/// `low3(x)`, then a marker.
pub fn put_low3(x: u8, buf: &mut impl BufMut) {
    buf.put_u8(low3(x));
    buf.put_u8(0xFF);
}

/// A byte and a masked byte (nothing cheaper).
pub fn put_pair(a: u8, b: u8, buf: &mut impl BufMut) {
    buf.put_u8(a);
    buf.put_u8(b & 15);
}
