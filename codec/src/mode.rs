//! Compact encoding for ordered, extensible mode values.

use crate::{EncodeSize, Error, Read, ReadExt, Write};
use bytes::{Buf, BufMut};

// The high bit is packet framing rather than mode value data.
const CONTINUATION_BIT: u8 = 1 << 7;

/// Error returned when a value cannot be represented as a [`Mode`].
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("mode value must fit in seven bits")]
pub struct InvalidMode;

/// A seven-bit value in an ordered [`Modes`] packet.
///
/// The high bit is reserved for packet framing and cannot be represented by this type.
///
/// # Examples
///
/// ```
/// use commonware_codec::Mode;
///
/// let mode = Mode::new(0x7f).unwrap();
/// assert_eq!(u8::from(mode), 0x7f);
/// assert!(Mode::new(0x80).is_none());
/// ```
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Mode(u8);

impl Mode {
    /// Creates a mode value, or returns `None` when the reserved high bit is set.
    pub const fn new(value: u8) -> Option<Self> {
        if value < CONTINUATION_BIT {
            Some(Self(value))
        } else {
            None
        }
    }
}

impl TryFrom<u8> for Mode {
    type Error = InvalidMode;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Self::new(value).ok_or(InvalidMode)
    }
}

impl From<Mode> for u8 {
    fn from(mode: Mode) -> Self {
        mode.0
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> arbitrary::Arbitrary<'a> for Mode {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self(u.int_in_range(0..=(CONTINUATION_BIT - 1))?))
    }
}

/// Creates a [`Mode`] from a `u8` literal or expression.
///
/// Literals are validated at compile time. Expressions are validated at runtime.
///
/// # Panics
///
/// The expression form panics if the reserved high bit is set. Use [`Mode::new`] or
/// [`Mode::try_from`] to validate untrusted values without panicking.
///
/// # Examples
///
/// ```
/// use commonware_codec::{Mode, mode};
///
/// const ENABLED: Mode = mode!(1);
/// assert_eq!(u8::from(ENABLED), 1);
/// ```
///
/// ```compile_fail
/// use commonware_codec::{Mode, mode};
///
/// const INVALID: Mode = mode!(0x80);
/// ```
#[cfg(not(any(
    commonware_stability_GAMMA,
    commonware_stability_DELTA,
    commonware_stability_EPSILON,
    commonware_stability_RESERVED
)))] // BETA
#[macro_export]
macro_rules! mode {
    ($value:literal) => {
        const { $crate::Mode::new($value).expect("mode value must fit in seven bits") }
    };
    ($value:expr) => {
        $crate::Mode::new($value).expect("mode value must fit in seven bits")
    };
}

/// Creates a canonical [`Modes`] packet from values convertible to [`Mode`].
///
/// Each expression is converted independently before the packet is constructed, so mode values
/// may have different source types. Returns `None` when every converted value is zero.
///
/// # Examples
///
/// ```
/// use commonware_codec::{Encode, mode, modes};
///
/// let modes = modes![mode!(1), mode!(1)].unwrap();
/// assert_eq!(modes.encode().as_ref(), &[0x81, 0x01]);
/// ```
///
/// ```compile_fail
/// use commonware_codec::modes;
///
/// let _ = modes![1u8];
/// ```
#[cfg(not(any(
    commonware_stability_GAMMA,
    commonware_stability_DELTA,
    commonware_stability_EPSILON,
    commonware_stability_RESERVED
)))] // BETA
#[macro_export]
macro_rules! modes {
    ($($mode:expr),* $(,)?) => {
        $crate::Modes::new([
            $(::core::convert::Into::<$crate::Mode>::into($mode)),*
        ])
    };
}

/// A canonical packet of ordered mode values.
///
/// `N` is the maximum number of modes and must be greater than zero.
///
/// The high bit indicates that another mode follows, and trailing zero-valued
/// modes are omitted. Appending a new mode with value zero therefore preserves
/// the existing encoding. A `Modes` value denotes a present packet. An all-zero
/// list denotes no packet.
///
/// # Examples
///
/// ```
/// use commonware_codec::{DecodeExt, Encode, Modes, mode};
///
/// let modes = Modes::new([mode!(1), mode!(0), mode!(2)]).unwrap();
/// let encoded = modes.encode();
/// assert_eq!(encoded.as_ref(), &[0x81, 0x80, 0x02]);
/// assert_eq!(Modes::<3>::decode(encoded).unwrap(), modes);
/// ```
///
/// ```compile_fail
/// use commonware_codec::Modes;
///
/// let _ = Modes::<0>::new([]);
/// ```
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Modes<const N: usize> {
    encoded: [u8; N],
    len: usize,
}

impl<const N: usize> Modes<N> {
    /// Creates a canonical packet from `modes`.
    ///
    /// Returns `None` when every mode is zero. Callers must represent this as an
    /// absent packet rather than an empty packet.
    ///
    pub fn new(modes: [Mode; N]) -> Option<Self> {
        const {
            assert!(N > 0, "N must be greater than 0");
        }

        let mut encoded = modes.map(u8::from);
        let last = encoded.iter().rposition(|&mode| mode != 0)?;
        for mode in &mut encoded[..last] {
            *mode |= CONTINUATION_BIT;
        }
        Some(Self {
            encoded,
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
        const {
            assert!(N > 0, "N must be greater than 0");
        }

        // Preserve framing bits in the stored representation while locating the
        // canonical non-zero terminator.
        let mut encoded = [0; N];
        for index in 0..N {
            let byte = u8::read(buf)?;
            encoded[index] = byte;
            if byte & CONTINUATION_BIT == 0 {
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
        const {
            assert!(N > 0, "N must be greater than 0");
        }

        let len = u.int_in_range(1..=N)?;
        let mut modes = [Mode(0); N];
        for mode in &mut modes[..len - 1] {
            *mode = u.arbitrary()?;
        }
        modes[len - 1] = Mode(u.int_in_range(1..=(CONTINUATION_BIT - 1))?);
        Self::new(modes).ok_or(arbitrary::Error::IncorrectFormat)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DecodeExt, Encode};

    fn assert_encoding<const N: usize>(modes: [u8; N], expected: &[u8]) {
        let modes = Modes::new(modes.map(|value| mode!(value))).unwrap();
        assert_eq!(modes.encode_size(), expected.len());
        let encoded = modes.encode();
        assert_eq!(encoded.as_ref(), expected);
        assert_eq!(Modes::<N>::decode(encoded).unwrap(), modes);
    }

    #[test]
    fn encodes_continuations() {
        // All-default mode lists have no packet.
        assert!(Modes::new([mode!(0), mode!(0)]).is_none());

        // A trailing default is absent, preserving the shorter encoding.
        assert_encoding([1, 0], &[0x01]);

        // Defaults before or between later values remain positionally encoded.
        assert_encoding([0, 1], &[0x80, 0x01]);
        assert_encoding([1, 0, 1], &[0x81, 0x80, 0x01]);

        // The largest mode value remains valid while continuation uses its high bit.
        assert_encoding([0x7f, 0x7f], &[0xff, 0x7f]);
    }

    #[test]
    fn macro_converts_heterogeneous_values() {
        struct Enabled;

        impl From<Enabled> for Mode {
            fn from(_: Enabled) -> Self {
                mode!(1)
            }
        }

        let modes = modes![Enabled, mode!(0), Enabled].unwrap();
        assert_eq!(modes.encode().as_ref(), &[0x81, 0x80, 0x01]);
    }

    #[test]
    fn mode_enforces_seven_bit_values() {
        for value in [0, 0x7f] {
            let mode = Mode::new(value).unwrap();
            assert_eq!(u8::from(mode), value);
            assert_eq!(Mode::try_from(value), Ok(mode));
        }

        for value in [0x80, 0xff] {
            assert_eq!(Mode::new(value), None);
            assert_eq!(Mode::try_from(value), Err(InvalidMode));
        }
    }

    #[test]
    fn mode_macro_constructs_literals_and_expressions() {
        const MAX: Mode = mode!(0x7f);
        let value = 1u8;

        assert_eq!(u8::from(MAX), 0x7f);
        assert_eq!(mode!(value), mode!(1));
    }

    #[test]
    #[should_panic(expected = "mode value must fit in seven bits")]
    fn mode_macro_rejects_invalid_expressions() {
        let value = 0x80u8;
        let _ = mode!(value);
    }

    #[test]
    fn rejects_truncated_and_oversized_packets() {
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
