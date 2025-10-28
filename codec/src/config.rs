//! Types for use as [crate::Read::Cfg].

use core::ops::{Bound, RangeBounds};

/// Configuration for limiting the range of a value.
///
/// This is often used to configure length limits for variable-length types or collections.
///
/// # Examples
///
/// ```
/// use commonware_codec::RangeCfg;
///
/// // Limit lengths to 0..=1024 (type inferred as usize)
/// let cfg = RangeCfg::new(0..=1024);
/// assert!(cfg.contains(&500));
/// assert!(!cfg.contains(&2000));
///
/// // Allow any length >= 1
/// let cfg_min = RangeCfg::from(1..);
/// assert!(cfg_min.contains(&1));
/// assert!(!cfg_min.contains(&0));
///
/// // Works with other integer types
/// let cfg_u8: RangeCfg<u8> = RangeCfg::new(0u8..=255u8);
/// assert!(cfg_u8.contains(&128));
///
/// let cfg_u32 = RangeCfg::new(0u32..1024u32);
/// assert!(cfg_u32.contains(&500));
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct RangeCfg<T: Copy + PartialOrd> {
    /// The lower bound of the range.
    start: Bound<T>,

    /// The upper bound of the range.
    end: Bound<T>,
}

impl<T: Copy + PartialOrd> From<core::ops::Range<T>> for RangeCfg<T> {
    fn from(r: core::ops::Range<T>) -> Self {
        Self::new(r)
    }
}

impl<T: Copy + PartialOrd> From<core::ops::RangeInclusive<T>> for RangeCfg<T> {
    fn from(r: core::ops::RangeInclusive<T>) -> Self {
        Self::new(r)
    }
}

impl<T: Copy + PartialOrd> From<core::ops::RangeFrom<T>> for RangeCfg<T> {
    fn from(r: core::ops::RangeFrom<T>) -> Self {
        Self::new(r)
    }
}

impl<T: Copy + PartialOrd> From<core::ops::RangeTo<T>> for RangeCfg<T> {
    fn from(r: core::ops::RangeTo<T>) -> Self {
        Self::new(r)
    }
}

impl<T: Copy + PartialOrd> From<core::ops::RangeToInclusive<T>> for RangeCfg<T> {
    fn from(r: core::ops::RangeToInclusive<T>) -> Self {
        Self::new(r)
    }
}

impl<T: Copy + PartialOrd> From<core::ops::RangeFull> for RangeCfg<T> {
    fn from(_: core::ops::RangeFull) -> Self {
        Self::new(..)
    }
}

impl<T: Copy + PartialOrd> RangeCfg<T> {
    /// Creates a new `RangeCfg` from any type implementing `RangeBounds<T>`.
    ///
    /// # Examples
    ///
    /// ```
    /// use commonware_codec::RangeCfg;
    ///
    /// let cfg = RangeCfg::new(0..=1024);
    /// assert!(cfg.contains(&500));
    /// ```
    pub fn new(r: impl RangeBounds<T>) -> Self {
        RangeCfg {
            start: r.start_bound().cloned(),
            end: r.end_bound().cloned(),
        }
    }

    /// Creates a `RangeCfg` that only accepts exactly `value`.
    pub fn exact(value: T) -> Self {
        Self {
            start: Bound::Included(value),
            end: Bound::Included(value),
        }
    }

    /// Returns true if the value is within this range.
    pub fn contains(&self, value: &T) -> bool {
        // Exclude by start bound
        match &self.start {
            Bound::Included(s) if value < s => return false,
            Bound::Excluded(s) if value <= s => return false,
            _ => {}
        }

        // Exclude by end bound
        match &self.end {
            Bound::Included(e) if value > e => return false,
            Bound::Excluded(e) if value >= e => return false,
            _ => {}
        }

        // If not excluded by either bound, the value is within the range
        true
    }
}

impl<T: Copy + PartialOrd> RangeBounds<T> for RangeCfg<T> {
    fn start_bound(&self) -> Bound<&T> {
        self.start.as_ref()
    }

    fn end_bound(&self) -> Bound<&T> {
        self.end.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ops::Bound::{Excluded, Included, Unbounded};

    #[test]
    fn test_range_cfg_from() {
        // Full range
        let cfg_full: RangeCfg<usize> = (..).into();
        assert_eq!(
            cfg_full,
            RangeCfg {
                start: Unbounded,
                end: Unbounded
            }
        );

        // Start bounded, end unbounded
        let cfg_start_incl: RangeCfg<usize> = (5..).into();
        assert_eq!(
            cfg_start_incl,
            RangeCfg {
                start: Included(5),
                end: Unbounded
            }
        );

        // Start unbounded, end bounded (exclusive)
        let cfg_end_excl: RangeCfg<usize> = (..10).into();
        assert_eq!(
            cfg_end_excl,
            RangeCfg {
                start: Unbounded,
                end: Excluded(10)
            }
        );

        // Start unbounded, end bounded (inclusive)
        let cfg_end_incl: RangeCfg<usize> = (..=10).into();
        assert_eq!(
            cfg_end_incl,
            RangeCfg {
                start: Unbounded,
                end: Included(10)
            }
        );

        // Fully bounded (inclusive start, exclusive end)
        let cfg_incl_excl: RangeCfg<usize> = (5..10).into();
        assert_eq!(
            cfg_incl_excl,
            RangeCfg {
                start: Included(5),
                end: Excluded(10)
            }
        );

        // Fully bounded (inclusive)
        let cfg_incl_incl: RangeCfg<usize> = (5..=10).into();
        assert_eq!(
            cfg_incl_incl,
            RangeCfg {
                start: Included(5),
                end: Included(10)
            }
        );

        // Fully bounded (exclusive start)
        struct ExclusiveStartRange(usize, usize);
        impl RangeBounds<usize> for ExclusiveStartRange {
            fn start_bound(&self) -> Bound<&usize> {
                Excluded(&self.0)
            }
            fn end_bound(&self) -> Bound<&usize> {
                Included(&self.1)
            }
        }
        let cfg_excl_incl = RangeCfg::new(ExclusiveStartRange(5, 10));
        assert_eq!(
            cfg_excl_incl,
            RangeCfg {
                start: Excluded(5),
                end: Included(10)
            }
        );
    }

    #[test]
    fn test_range_cfg_contains() {
        // Unbounded range (..)
        let cfg_unbounded: RangeCfg<usize> = (..).into();
        assert!(cfg_unbounded.contains(&0));
        assert!(cfg_unbounded.contains(&100));
        assert!(cfg_unbounded.contains(&usize::MAX));

        // Inclusive start (5..)
        let cfg_start_incl: RangeCfg<usize> = (5..).into();
        assert!(!cfg_start_incl.contains(&4));
        assert!(cfg_start_incl.contains(&5));
        assert!(cfg_start_incl.contains(&6));
        assert!(cfg_start_incl.contains(&usize::MAX));

        // Exclusive end (..10)
        let cfg_end_excl: RangeCfg<usize> = (..10).into();
        assert!(cfg_end_excl.contains(&0));
        assert!(cfg_end_excl.contains(&9));
        assert!(!cfg_end_excl.contains(&10));
        assert!(!cfg_end_excl.contains(&11));

        // Inclusive end (..=10)
        let cfg_end_incl: RangeCfg<usize> = (..=10).into();
        assert!(cfg_end_incl.contains(&0));
        assert!(cfg_end_incl.contains(&9));
        assert!(cfg_end_incl.contains(&10));
        assert!(!cfg_end_incl.contains(&11));

        // Inclusive start, exclusive end (5..10)
        let cfg_incl_excl: RangeCfg<usize> = (5..10).into();
        assert!(!cfg_incl_excl.contains(&4));
        assert!(cfg_incl_excl.contains(&5));
        assert!(cfg_incl_excl.contains(&9));
        assert!(!cfg_incl_excl.contains(&10));
        assert!(!cfg_incl_excl.contains(&11));

        // Inclusive start, inclusive end (5..=10)
        let cfg_incl_incl: RangeCfg<usize> = (5..=10).into();
        assert!(!cfg_incl_incl.contains(&4));
        assert!(cfg_incl_incl.contains(&5));
        assert!(cfg_incl_incl.contains(&9));
        assert!(cfg_incl_incl.contains(&10));
        assert!(!cfg_incl_incl.contains(&11));

        // Exclusive start, inclusive end (pseudo: >5 ..=10)
        let cfg_excl_incl = RangeCfg {
            start: Excluded(5),
            end: Included(10),
        };
        assert!(!cfg_excl_incl.contains(&4));
        assert!(!cfg_excl_incl.contains(&5)); // Excluded
        assert!(cfg_excl_incl.contains(&6));
        assert!(cfg_excl_incl.contains(&10)); // Included
        assert!(!cfg_excl_incl.contains(&11));

        // Exclusive start, exclusive end (pseudo: >5 .. <10)
        let cfg_excl_excl = RangeCfg {
            start: Excluded(5),
            end: Excluded(10),
        };
        assert!(!cfg_excl_excl.contains(&5)); // Excluded
        assert!(cfg_excl_excl.contains(&6));
        assert!(cfg_excl_excl.contains(&9));
        assert!(!cfg_excl_excl.contains(&10)); // Excluded
    }

    #[test]
    fn test_contains_empty_range() {
        // Empty range (e.g., 5..5)
        let cfg_empty_excl: RangeCfg<usize> = (5..5).into();
        assert!(!cfg_empty_excl.contains(&4));
        assert!(!cfg_empty_excl.contains(&5));
        assert!(!cfg_empty_excl.contains(&6));

        // Slightly less obvious empty range (e.g., 6..=5)
        #[allow(clippy::reversed_empty_ranges)]
        let cfg_empty_incl: RangeCfg<usize> = (6..=5).into();
        assert!(!cfg_empty_incl.contains(&5));
        assert!(!cfg_empty_incl.contains(&6));
    }

    #[test]
    fn test_range_cfg_u8() {
        // Test with u8 type
        let cfg = RangeCfg::new(0u8..=255u8);
        assert!(cfg.contains(&0));
        assert!(cfg.contains(&128));
        assert!(cfg.contains(&255));

        let cfg_partial = RangeCfg::new(10u8..20u8);
        assert!(!cfg_partial.contains(&9));
        assert!(cfg_partial.contains(&10));
        assert!(cfg_partial.contains(&19));
        assert!(!cfg_partial.contains(&20));
    }

    #[test]
    fn test_range_cfg_u16() {
        // Test with u16 type
        let cfg = RangeCfg::new(100u16..=1000u16);
        assert!(!cfg.contains(&99));
        assert!(cfg.contains(&100));
        assert!(cfg.contains(&500));
        assert!(cfg.contains(&1000));
        assert!(!cfg.contains(&1001));
    }

    #[test]
    fn test_range_cfg_u32() {
        // Test with u32 type
        let cfg = RangeCfg::new(0u32..1024u32);
        assert!(cfg.contains(&0));
        assert!(cfg.contains(&512));
        assert!(!cfg.contains(&1024));
        assert!(!cfg.contains(&2000));
    }

    #[test]
    fn test_range_cfg_u64() {
        // Test with u64 type
        let cfg = RangeCfg::new(1000u64..);
        assert!(!cfg.contains(&999));
        assert!(cfg.contains(&1000));
        assert!(cfg.contains(&u64::MAX));
    }

    #[test]
    fn test_type_inference() {
        // Type inference from range literal with explicit type suffixes
        let cfg = RangeCfg::new(0u8..10u8);
        assert!(cfg.contains(&5u8));

        // Type inference when assigning to typed variable
        let cfg: RangeCfg<u32> = RangeCfg::new(0..1000);
        assert!(cfg.contains(&500));
    }
}
