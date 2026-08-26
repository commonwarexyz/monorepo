//! Compact encoding for ordered, extensible mode values.

use crate::{EncodeSize, Error, Read, ReadExt, Write};
use bytes::{Buf, BufMut};

/// A canonical packet of ordered mode values.
///
/// Each mode supports values from 0 through 127. The high bit indicates that
/// another mode follows, and trailing zero-valued modes are omitted. Appending
/// a new mode with value zero therefore preserves the existing encoding. A
/// `Modes` value denotes a present packet. An all-zero list denotes no packet.
///
/// # Examples
///
/// ```
/// use commonware_codec::{DecodeExt, Encode, Modes};
///
/// let modes = Modes::new([1, 0, 2]).unwrap();
/// let encoded = modes.encode();
/// assert_eq!(encoded.as_ref(), &[0x81, 0x80, 0x02]);
/// assert_eq!(Modes::<3>::decode(encoded).unwrap(), modes);
/// ```
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Modes<const N: usize> {
    encoded: [u8; N],
    len: usize,
}

impl<const N: usize> Modes<N> {
    // The high bit is framing rather than value data; when set, another mode follows.
    const CONTINUATION_BIT: u8 = 1 << 7;

    /// Creates a canonical packet from `modes`.
    ///
    /// Returns `None` when every mode is zero. Callers must represent this as an
    /// absent packet rather than an empty packet.
    ///
    /// # Panics
    ///
    /// Panics if any mode uses the reserved high bit.
    pub fn new(mut modes: [u8; N]) -> Option<Self> {
        assert!(
            modes.iter().all(|&mode| mode < Self::CONTINUATION_BIT),
            "mode must fit in seven bits"
        );
        let last = modes.iter().rposition(|&mode| mode != 0)?;
        for mode in &mut modes[..last] {
            *mode |= Self::CONTINUATION_BIT;
        }
        Some(Self {
            encoded: modes,
            len: last + 1,
        })
    }
}

impl<const N: usize> Write for Modes<N> {
    fn write(&self, buf: &mut impl BufMut) {
        buf.put_slice(&self.encoded[..self.len]);
    }
}

impl<const N: usize> EncodeSize for Modes<N> {
    fn encode_size(&self) -> usize {
        self.len
    }
}

impl<const N: usize> Read for Modes<N> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, Error> {
        if N == 0 {
            return Err(Error::Invalid("Modes", "no mode values configured"));
        }

        // Preserve framing bits in the stored representation while locating the
        // canonical non-zero terminator.
        let mut encoded = [0; N];
        for index in 0..N {
            let byte = u8::read(buf)?;
            encoded[index] = byte;
            if byte & Self::CONTINUATION_BIT == 0 {
                if byte == 0 {
                    return Err(Error::Invalid("Modes", "trailing mode must be non-zero"));
                }
                return Ok(Self {
                    encoded,
                    len: index + 1,
                });
            }
        }

        Err(Error::Invalid("Modes", "too many mode values"))
    }
}

#[cfg(feature = "arbitrary")]
impl<'a, const N: usize> arbitrary::Arbitrary<'a> for Modes<N> {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        if N == 0 {
            return Err(arbitrary::Error::IncorrectFormat);
        }

        let len = u.int_in_range(1..=N)?;
        let mut modes = [0; N];
        for mode in &mut modes[..len - 1] {
            *mode = u.int_in_range(0..=0x7f)?;
        }
        modes[len - 1] = u.int_in_range(1..=0x7f)?;
        Self::new(modes).ok_or(arbitrary::Error::IncorrectFormat)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DecodeExt, Encode};

    fn assert_encoding<const N: usize>(modes: [u8; N], expected: &[u8]) {
        let modes = Modes::new(modes).unwrap();
        assert_eq!(modes.encode_size(), expected.len());
        let encoded = modes.encode();
        assert_eq!(encoded.as_ref(), expected);
        assert_eq!(Modes::<N>::decode(encoded).unwrap(), modes);
    }

    #[test]
    fn encodes_continuations() {
        // Empty and all-default mode lists have no packet.
        assert!(Modes::<0>::new([]).is_none());
        assert!(Modes::new([0, 0]).is_none());

        // A trailing default is absent, preserving the shorter encoding.
        assert_encoding([1, 0], &[0x01]);

        // Defaults before or between later values remain positionally encoded.
        assert_encoding([0, 1], &[0x80, 0x01]);
        assert_encoding([1, 0, 1], &[0x81, 0x80, 0x01]);

        // The largest mode value remains valid while continuation uses its high bit.
        assert_encoding([0x7f, 0x7f], &[0xff, 0x7f]);
    }

    #[test]
    #[should_panic(expected = "mode must fit in seven bits")]
    fn reserved_bit_panics() {
        let _ = Modes::new([0, 0x80]);
    }

    #[test]
    fn rejects_truncated_and_oversized_packets() {
        assert!(matches!(
            Modes::<0>::decode(&[][..]),
            Err(Error::Invalid("Modes", _))
        ));
        assert!(matches!(
            Modes::<2>::decode(&[][..]),
            Err(Error::EndOfBuffer)
        ));
        assert!(matches!(
            Modes::<2>::decode(&[0x80][..]),
            Err(Error::EndOfBuffer)
        ));
        assert!(matches!(
            Modes::<1>::decode(&[0x80][..]),
            Err(Error::Invalid("Modes", _))
        ));
        assert!(matches!(
            Modes::<2>::decode(&[0x80, 0x80][..]),
            Err(Error::Invalid("Modes", _))
        ));
        assert!(matches!(
            Modes::<2>::decode(&[0x80, 0x80, 0x01][..]),
            Err(Error::Invalid("Modes", _))
        ));
    }

    #[test]
    fn rejects_non_canonical_packets() {
        assert!(matches!(
            Modes::<1>::decode(&[0x00][..]),
            Err(Error::Invalid("Modes", _))
        ));
        assert!(matches!(
            Modes::<2>::decode(&[0x80, 0x00][..]),
            Err(Error::Invalid("Modes", _))
        ));
        assert!(matches!(
            Modes::<2>::decode(&[0x81, 0x00][..]),
            Err(Error::Invalid("Modes", _))
        ));
    }

    #[test]
    fn read_stops_at_packet_boundary() {
        let mut encoded = &[0x01, 0x02][..];
        let modes = Modes::<2>::read(&mut encoded).unwrap();
        assert_eq!(modes.encode().as_ref(), &[0x01]);
        assert_eq!(encoded, &[0x02]);
        assert!(matches!(
            Modes::<2>::decode(&[0x01, 0x02][..]),
            Err(Error::ExtraData(1))
        ));
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::*;
        use crate::conformance::CodecConformance;

        commonware_conformance::conformance_tests! {
            CodecConformance<Modes<1>>,
            CodecConformance<Modes<2>>,
        }
    }
}
