//! Types for use as [`crate::Read::Cfg`].

use std::ops::{Bound, RangeBounds};

/// Configuration for limiting the range of a [usize] value.
///
/// This is often used to configure length limits for variable-length types or collections.
///
/// # Example
///
/// ```
/// use commonware_codec::RangeCfg;
///
/// // Limit lengths to 0..=1024
/// let cfg = RangeCfg::from(0..=1024);
/// assert!(cfg.contains(&500));
/// assert!(!cfg.contains(&2000));
///
/// // Allow any length >= 1
/// let cfg_min = RangeCfg::from(1..);
/// assert!(cfg_min.contains(&1));
/// assert!(!cfg_min.contains(&0));
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct RangeCfg {
    /// The lower bound of the range.
    start: Bound<usize>,

    /// The upper bound of the range.
    end: Bound<usize>,
}

impl RangeCfg {
    /// Returns `true` if the given value is within the configured range.
    pub fn contains(&self, value: &usize) -> bool {
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

// Allow conversion from any type that implements `RangeBounds<usize>` to `RangeCfg`.
impl<R: RangeBounds<usize>> From<R> for RangeCfg {
    fn from(r: R) -> Self {
        fn own(b: Bound<&usize>) -> Bound<usize> {
            match b {
                Bound::Included(&v) => Bound::Included(v),
                Bound::Excluded(&v) => Bound::Excluded(v),
                Bound::Unbounded => Bound::Unbounded,
            }
        }

        RangeCfg {
            start: own(r.start_bound()),
            end: own(r.end_bound()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ops::Bound::{Excluded, Included, Unbounded};

    #[test]
    fn test_range_cfg_from() {
        // Full range
        let cfg_full: RangeCfg = (..).into();
        assert_eq!(
            cfg_full,
            RangeCfg {
                start: Unbounded,
                end: Unbounded
            }
        );

        // Start bounded, end unbounded
        let cfg_start_incl: RangeCfg = (5..).into();
        assert_eq!(
            cfg_start_incl,
            RangeCfg {
                start: Included(5),
                end: Unbounded
            }
        );

        // Start unbounded, end bounded (exclusive)
        let cfg_end_excl: RangeCfg = (..10).into();
        assert_eq!(
            cfg_end_excl,
            RangeCfg {
                start: Unbounded,
                end: Excluded(10)
            }
        );

        // Start unbounded, end bounded (inclusive)
        let cfg_end_incl: RangeCfg = (..=10).into();
        assert_eq!(
            cfg_end_incl,
            RangeCfg {
                start: Unbounded,
                end: Included(10)
            }
        );

        // Fully bounded (inclusive start, exclusive end)
        let cfg_incl_excl: RangeCfg = (5..10).into();
        assert_eq!(
            cfg_incl_excl,
            RangeCfg {
                start: Included(5),
                end: Excluded(10)
            }
        );

        // Fully bounded (inclusive)
        let cfg_incl_incl: RangeCfg = (5..=10).into();
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
        let cfg_excl_incl: RangeCfg = ExclusiveStartRange(5, 10).into();
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
        let cfg_unbounded: RangeCfg = (..).into();
        assert!(cfg_unbounded.contains(&0));
        assert!(cfg_unbounded.contains(&100));
        assert!(cfg_unbounded.contains(&usize::MAX));

        // Inclusive start (5..)
        let cfg_start_incl: RangeCfg = (5..).into();
        assert!(!cfg_start_incl.contains(&4));
        assert!(cfg_start_incl.contains(&5));
        assert!(cfg_start_incl.contains(&6));
        assert!(cfg_start_incl.contains(&usize::MAX));

        // Exclusive end (..10)
        let cfg_end_excl: RangeCfg = (..10).into();
        assert!(cfg_end_excl.contains(&0));
        assert!(cfg_end_excl.contains(&9));
        assert!(!cfg_end_excl.contains(&10));
        assert!(!cfg_end_excl.contains(&11));

        // Inclusive end (..=10)
        let cfg_end_incl: RangeCfg = (..=10).into();
        assert!(cfg_end_incl.contains(&0));
        assert!(cfg_end_incl.contains(&9));
        assert!(cfg_end_incl.contains(&10));
        assert!(!cfg_end_incl.contains(&11));

        // Inclusive start, exclusive end (5..10)
        let cfg_incl_excl: RangeCfg = (5..10).into();
        assert!(!cfg_incl_excl.contains(&4));
        assert!(cfg_incl_excl.contains(&5));
        assert!(cfg_incl_excl.contains(&9));
        assert!(!cfg_incl_excl.contains(&10));
        assert!(!cfg_incl_excl.contains(&11));

        // Inclusive start, inclusive end (5..=10)
        let cfg_incl_incl: RangeCfg = (5..=10).into();
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
        let cfg_empty_excl: RangeCfg = (5..5).into();
        assert!(!cfg_empty_excl.contains(&4));
        assert!(!cfg_empty_excl.contains(&5));
        assert!(!cfg_empty_excl.contains(&6));

        // Slightly less obvious empty range (e.g., 6..=5)
        #[allow(clippy::reversed_empty_ranges)]
        let cfg_empty_incl: RangeCfg = (6..=5).into();
        assert!(!cfg_empty_incl.contains(&5));
        assert!(!cfg_empty_incl.contains(&6));
    }
}
