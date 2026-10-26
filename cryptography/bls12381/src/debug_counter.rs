//! Debug-only upper bounds for nonnegative arithmetic intermediates.
//!
//! Bounds use caller-chosen units. Arithmetic contexts supply their own input limits,
//! subtraction biases, and output bounds after reduction. This counter does not inspect
//! field values or perform reductions.
//!
//! With debug assertions disabled, the counter is zero-sized and its operations are no-ops.
//! Arguments to these operations are still evaluated by the caller.

#![cfg_attr(
    not(test),
    expect(dead_code, reason = "Field arithmetic does not yet use this counter.")
)]

/// A conservative, inclusive upper bound that is checked only in debug builds.
///
/// Copies retain the bound. After a reduction, construct a new counter using the reduction's
/// proven output bound. Preserve counters alongside any stored arithmetic intermediates.
#[derive(Clone, Copy, Debug)]
pub struct DebugCounter {
    #[cfg(debug_assertions)]
    upper: u64,
}

impl DebugCounter {
    /// Returns whether bound tracking is enabled.
    const fn live() -> bool {
        cfg!(debug_assertions)
    }

    /// Creates a counter with the supplied upper bound.
    pub const fn new(upper: u64) -> Self {
        let _ = upper;
        Self {
            #[cfg(debug_assertions)]
            upper,
        }
    }

    /// Bounds `a + bias - b` by `a + bias`, checking that `b` is at most `bias`.
    ///
    /// This establishes nonnegativity for the represented integer. Separate limb or residue
    /// constraints remain the arithmetic context's responsibility.
    ///
    /// # Panics
    ///
    /// With debug assertions enabled, panics if the right-hand bound exceeds `bias` or the
    /// resulting bound exceeds [`u64::MAX`].
    pub fn sub_with_bias(&mut self, rhs: Self, bias: u64) {
        rhs.assert_le(bias);
        self.add(Self::new(bias));
    }

    /// Raises this bound to cover either input, for example after a conditional selection.
    pub fn max(&mut self, rhs: Self) {
        let _ = rhs;
        #[cfg(debug_assertions)]
        {
            self.upper = self.upper.max(rhs.upper);
        }
    }

    /// Checks that this bound is at most `limit`.
    ///
    /// # Panics
    ///
    /// With debug assertions enabled, panics if the bound exceeds `limit`.
    pub fn assert_le(&self, limit: u64) {
        let _ = limit;
        #[cfg(debug_assertions)]
        assert!(
            self.upper <= limit,
            "bound {} exceeds limit {limit}",
            self.upper
        );
    }

    /// Adds the right-hand bound to this bound.
    ///
    /// # Panics
    ///
    /// With debug assertions enabled, panics if the resulting bound exceeds [`u64::MAX`].
    pub const fn add(&mut self, rhs: Self) {
        let _ = rhs;
        #[cfg(debug_assertions)]
        {
            self.upper = self
                .upper
                .checked_add(rhs.upper)
                .expect("bound addition overflow");
        }
    }

    /// Multiplies this bound by the right-hand bound.
    ///
    /// The caller must account for the resulting units, such as `p^2` for two bounds in `p`.
    ///
    /// # Panics
    ///
    /// With debug assertions enabled, panics if the resulting bound exceeds [`u64::MAX`].
    pub const fn mul(&mut self, rhs: Self) {
        let _ = rhs;
        #[cfg(debug_assertions)]
        {
            self.upper = self
                .upper
                .checked_mul(rhs.upper)
                .expect("bound multiplication overflow");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::panic::catch_unwind;

    #[test]
    fn bounds_follow_a_formula() {
        if !DebugCounter::live() {
            return;
        }
        let a = DebugCounter::new(3);
        let b = DebugCounter::new(5);
        let mut result = a;
        result.add(b);
        result.sub_with_bias(b, 8);
        result.mul(a);
        result.max(DebugCounter::new(47));
        result.assert_le(48);
        assert!(catch_unwind(|| result.assert_le(47)).is_err());
        result.max(DebugCounter::new(49));
        result.assert_le(49);
        assert!(catch_unwind(|| result.assert_le(48)).is_err());
    }

    #[test]
    fn rejects_insufficient_subtraction_bias() {
        if !DebugCounter::live() {
            return;
        }
        assert!(
            catch_unwind(|| {
                DebugCounter::new(0).sub_with_bias(DebugCounter::new(9), 8);
            })
            .is_err()
        );
    }

    #[test]
    fn rejects_counter_addition_overflow() {
        if !DebugCounter::live() {
            return;
        }
        assert!(
            catch_unwind(|| {
                DebugCounter::new(u64::MAX).add(DebugCounter::new(1));
            })
            .is_err()
        );
    }

    #[test]
    fn rejects_counter_multiplication_overflow() {
        if !DebugCounter::live() {
            return;
        }
        assert!(
            catch_unwind(|| {
                DebugCounter::new(u64::MAX).mul(DebugCounter::new(2));
            })
            .is_err()
        );
    }

    #[test]
    fn disabled_counter_has_no_storage_or_checks() {
        if DebugCounter::live() {
            return;
        }
        assert_eq!(core::mem::size_of::<DebugCounter>(), 0);
        let a = DebugCounter::new(u64::MAX);
        let mut result = a;
        result.add(a);
        result.mul(a);
        result.sub_with_bias(a, 0);
        result.max(a);
        result.assert_le(0);
    }
}
