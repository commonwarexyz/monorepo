//! Utilities for linear ranges and cyclic spans.

use bytes::BufMut;
use commonware_codec::{Buf, BufsMut, EncodeSize, Error as CodecError, Read, Write};
use commonware_macros::stability;
#[stability(ALPHA)]
use core::ops::{
    Bound::{Excluded, Included, Unbounded},
    RangeBounds,
};
use core::{fmt, ops::Range};

/// Whether `key` is in the cyclic span described by the current bounds of `span`.
///
/// When both endpoints are bounded, a start greater than the end wraps around the key
/// domain. Equal endpoints span the entire domain, except for the endpoint itself when
/// both bounds exclude it. Unbounded endpoints use ordinary linear range semantics.
///
/// # Examples
///
/// ```
/// use commonware_utils::range::contains_cyclic;
/// use core::ops::Bound::{Excluded, Included};
///
/// assert!(contains_cyclic(2..6, &2));
/// assert!(!contains_cyclic(2..6, &6));
/// assert!(contains_cyclic((Excluded(2), Included(6)), &6));
/// assert!(contains_cyclic(6..2, &0));
/// assert!(contains_cyclic(3..3, &9));
/// ```
#[stability(ALPHA)]
pub fn contains_cyclic<K: Ord + ?Sized>(span: impl RangeBounds<K>, key: &K) -> bool {
    let start = span.start_bound();
    let end = span.end_bound();
    let after_start = match start {
        Included(start) => key >= start,
        Excluded(start) => key > start,
        Unbounded => true,
    };
    let before_end = match end {
        Included(end) => key <= end,
        Excluded(end) => key < end,
        Unbounded => true,
    };
    match (start, end) {
        (Included(start) | Excluded(start), Included(end) | Excluded(end)) if start >= end => {
            after_start || before_end
        }
        _ => after_start && before_end,
    }
}

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

impl<Idx> core::ops::Deref for NonEmptyRange<Idx> {
    type Target = Range<Idx>;

    fn deref(&self) -> &Self::Target {
        &self.0
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

impl<Idx: Write> Write for NonEmptyRange<Idx> {
    #[inline]
    fn write(&self, buf: &mut impl BufMut) {
        self.0.start.write(buf);
        self.0.end.write(buf);
    }

    #[inline]
    fn write_bufs(&self, buf: &mut impl BufsMut) {
        self.0.start.write_bufs(buf);
        self.0.end.write_bufs(buf);
    }
}

impl<Idx: EncodeSize> EncodeSize for NonEmptyRange<Idx> {
    #[inline]
    fn encode_size(&self) -> usize {
        self.0.start.encode_size() + self.0.end.encode_size()
    }

    #[inline]
    fn encode_inline_size(&self) -> usize {
        self.0.start.encode_inline_size() + self.0.end.encode_inline_size()
    }
}

impl<Idx: Read + PartialOrd> Read for NonEmptyRange<Idx> {
    type Cfg = Idx::Cfg;

    #[inline]
    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        let start = Idx::read_cfg(buf, cfg)?;
        let end = Idx::read_cfg(buf, cfg)?;
        if !start.partial_cmp(&end).is_some_and(|o| o.is_lt()) {
            return Err(CodecError::Invalid("NonEmptyRange", "start must be < end"));
        }
        Ok(Self(start..end))
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
    fn test_contains_cyclic_boundaries() {
        let cases: &[(_, &[u8])] = &[
            ((Included(2), Excluded(6)), &[2, 3, 4, 5]),
            ((Excluded(2), Included(6)), &[3, 4, 5, 6]),
            ((Included(2), Included(6)), &[2, 3, 4, 5, 6]),
            ((Excluded(2), Excluded(6)), &[3, 4, 5]),
            ((Included(6), Excluded(2)), &[0, 1, 6, 7]),
            ((Excluded(6), Included(2)), &[0, 1, 2, 7]),
            ((Included(6), Included(2)), &[0, 1, 2, 6, 7]),
            ((Excluded(6), Excluded(2)), &[0, 1, 7]),
            ((Included(3), Excluded(3)), &[0, 1, 2, 3, 4, 5, 6, 7]),
            ((Excluded(3), Included(3)), &[0, 1, 2, 3, 4, 5, 6, 7]),
            ((Included(3), Included(3)), &[0, 1, 2, 3, 4, 5, 6, 7]),
            ((Excluded(3), Excluded(3)), &[0, 1, 2, 4, 5, 6, 7]),
            ((Unbounded, Included(3)), &[0, 1, 2, 3]),
            ((Unbounded, Excluded(3)), &[0, 1, 2]),
            ((Included(3), Unbounded), &[3, 4, 5, 6, 7]),
            ((Excluded(3), Unbounded), &[4, 5, 6, 7]),
            ((Unbounded, Unbounded), &[0, 1, 2, 3, 4, 5, 6, 7]),
        ];
        for &(bounds, expected) in cases {
            let actual: Vec<_> = (0..=7).filter(|key| contains_cyclic(bounds, key)).collect();
            assert_eq!(actual, expected, "bounds: {bounds:?}");
        }
    }

    #[test]
    #[allow(clippy::reversed_empty_ranges)]
    fn test_contains_cyclic_extremes() {
        for key in u8::MIN..=u8::MAX {
            assert_eq!(contains_cyclic(u8::MAX..u8::MIN, &key), key == u8::MAX);
            assert_eq!(
                contains_cyclic((Excluded(u8::MAX), Included(u8::MIN)), &key),
                key == u8::MIN
            );
            assert!(contains_cyclic(u8::MIN..u8::MIN, &key));
            assert!(contains_cyclic(u8::MAX..u8::MAX, &key));
            assert!(!contains_cyclic(..u8::MIN, &key));
            assert!(!contains_cyclic((Excluded(u8::MAX), Unbounded), &key));
        }
    }

    #[test]
    fn test_contains_cyclic_range_syntax() {
        let start = String::from("a");
        let end = String::from("c");
        let key = String::from("b");
        assert!(contains_cyclic(&start..&end, &key));
        assert!(!contains_cyclic(&start..&end, &end));
        assert!(contains_cyclic(&start..=&end, &end));
        assert!(contains_cyclic(&start.., &key));
        assert!(!contains_cyclic(..&end, &end));
        assert!(contains_cyclic(..=&end, &end));
        assert!(contains_cyclic(.., &key));
        assert!(contains_cyclic((Excluded(&start), Included(&end)), &end));
        assert!(contains_cyclic(
            (Included(start.as_str()), Excluded(end.as_str())),
            key.as_str()
        ));
    }

    #[test]
    fn test_contains_cyclic_current_bounds() {
        let mut span = 2..=6;
        assert_eq!(span.next(), Some(2));
        assert_eq!(span.next_back(), Some(6));
        for key in 0..=7 {
            assert_eq!(contains_cyclic(span.clone(), &key), (3..=5).contains(&key));
        }
    }

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
        for (start, end) in [(20u32, 10u32), (5, 5)] {
            let mut buf = Vec::new();
            buf.extend_from_slice(&start.to_be_bytes());
            buf.extend_from_slice(&end.to_be_bytes());
            assert!(matches!(
                NonEmptyRange::<u32>::decode(buf),
                Err(CodecError::Invalid("NonEmptyRange", "start must be < end"))
            ));
        }
    }

    #[test]
    fn test_non_empty_range_deref() {
        let r = NonEmptyRange::new(0u32..5).unwrap();
        assert!(r.contains(&3));
        assert_eq!(r.len(), 5);
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
