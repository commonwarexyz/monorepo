//! Non-empty [`Range`] type that guarantees at least one element.

use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Error as CodecError, Read, Write};
use core::{fmt, ops::Range};

/// Error returned when attempting to create a non-empty range from an empty range.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("range is empty")]
pub struct EmptyRange;

/// A non-empty [`Range`] (`start..end`) where `start < end` is guaranteed.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct NonEmptyRange<Idx>(Range<Idx>);

impl<Idx: fmt::Debug> fmt::Debug for NonEmptyRange<Idx> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl<Idx: PartialOrd> NonEmptyRange<Idx> {
    /// Creates a `NonEmptyRange` if `start < end`.
    pub fn new(range: Range<Idx>) -> Result<Self, EmptyRange> {
        (range.start < range.end)
            .then_some(Self(range))
            .ok_or(EmptyRange)
    }
}

impl<Idx: Copy> NonEmptyRange<Idx> {
    /// Returns the start of the range.
    pub const fn start(&self) -> Idx {
        self.0.start
    }

    /// Returns the end of the range (exclusive).
    pub const fn end(&self) -> Idx {
        self.0.end
    }
}

impl<Idx: PartialOrd> TryFrom<Range<Idx>> for NonEmptyRange<Idx> {
    type Error = EmptyRange;

    fn try_from(range: Range<Idx>) -> Result<Self, Self::Error> {
        Self::new(range)
    }
}

impl<Idx> From<NonEmptyRange<Idx>> for Range<Idx> {
    fn from(r: NonEmptyRange<Idx>) -> Self {
        r.0
    }
}

impl<Idx> IntoIterator for NonEmptyRange<Idx>
where
    Range<Idx>: Iterator,
{
    type Item = <Range<Idx> as Iterator>::Item;
    type IntoIter = Range<Idx>;

    fn into_iter(self) -> Self::IntoIter {
        self.0
    }
}

impl<Idx: Write + PartialOrd> Write for NonEmptyRange<Idx> {
    #[inline]
    fn write(&self, buf: &mut impl BufMut) {
        self.0.write(buf);
    }
}

impl<Idx: EncodeSize> EncodeSize for NonEmptyRange<Idx> {
    #[inline]
    fn encode_size(&self) -> usize {
        self.0.encode_size()
    }
}

impl<Idx: Read + PartialOrd> Read for NonEmptyRange<Idx> {
    type Cfg = Idx::Cfg;

    #[inline]
    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        let range = Range::<Idx>::read_cfg(buf, cfg)?;
        if !range
            .start
            .partial_cmp(&range.end)
            .is_some_and(|o| o.is_lt())
        {
            return Err(CodecError::Invalid("NonEmptyRange", "start must be < end"));
        }
        Ok(Self(range))
    }
}

#[cfg(feature = "arbitrary")]
impl<'a, Idx: arbitrary::Arbitrary<'a> + Ord> arbitrary::Arbitrary<'a> for NonEmptyRange<Idx> {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let a = Idx::arbitrary(u)?;
        let b = Idx::arbitrary(u)?;
        let (start, end) = if a < b {
            (a, b)
        } else if b < a {
            (b, a)
        } else {
            return Err(arbitrary::Error::IncorrectFormat);
        };
        Ok(Self(start..end))
    }
}

/// A macro to create a [`NonEmptyRange`] from a range expression, panicking if the range is empty.
#[macro_export]
macro_rules! non_empty_range {
    ($start:expr, $end:expr) => {
        $crate::range::NonEmptyRange::new($start..$end).expect("range must be non-empty")
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::{DecodeExt, Encode};

    #[test]
    fn test_non_empty_range_valid() {
        let r = NonEmptyRange::new(0u32..5).unwrap();
        assert_eq!(r.start(), 0);
        assert_eq!(r.end(), 5);
        assert_eq!(Range::from(r), 0..5);
    }

    #[test]
    fn test_non_empty_range_single_element() {
        let r = NonEmptyRange::new(3u32..4).unwrap();
        assert_eq!(r.start(), 3);
        assert_eq!(r.end(), 4);
    }

    #[test]
    fn test_non_empty_range_empty() {
        assert_eq!(NonEmptyRange::new(5u32..5), Err(EmptyRange));
        #[allow(clippy::reversed_empty_ranges)]
        let reversed = NonEmptyRange::new(5u32..3);
        assert_eq!(reversed, Err(EmptyRange));
    }

    #[test]
    fn test_non_empty_range_into() {
        let r = NonEmptyRange::new(1u32..10).unwrap();
        let range: Range<u32> = r.into();
        assert_eq!(range, 1..10);
    }

    #[test]
    fn test_non_empty_range_debug() {
        let r = NonEmptyRange::new(1u32..5).unwrap();
        assert_eq!(format!("{r:?}"), "1..5");
    }

    #[test]
    fn test_non_empty_range_iter() {
        let r = NonEmptyRange::new(0u32..4).unwrap();
        let items: Vec<_> = r.into_iter().collect();
        assert_eq!(items, vec![0, 1, 2, 3]);
    }

    #[test]
    fn test_non_empty_range_encode_decode() {
        let r = NonEmptyRange::new(10u32..20).unwrap();
        let encoded = r.encode();
        let decoded = NonEmptyRange::<u32>::decode(encoded).unwrap();
        assert_eq!(r, decoded);
    }

    #[test]
    fn test_non_empty_range_decode_invalid() {
        // Manually encode start=20, end=10 to bypass the Range write panic
        let mut buf = Vec::new();
        buf.extend_from_slice(&20u32.to_be_bytes());
        buf.extend_from_slice(&10u32.to_be_bytes());
        assert!(NonEmptyRange::<u32>::decode(bytes::Bytes::from(buf)).is_err());

        // start == end is valid for Range but not for NonEmptyRange
        let empty = Range {
            start: 5u32,
            end: 5u32,
        };
        let encoded = empty.encode();
        assert!(NonEmptyRange::<u32>::decode(encoded).is_err());
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::*;
        use commonware_codec::conformance::CodecConformance;

        commonware_conformance::conformance_tests! {
            CodecConformance<NonEmptyRange<u32>>,
            CodecConformance<NonEmptyRange<u64>>,
        }
    }
}
