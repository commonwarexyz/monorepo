//! Consensus types shared across the crate.
//!
//! This module defines the core types used throughout the consensus implementation:
//!
//! - [`Epoch`]: Represents a distinct segment of a contiguous sequence of views. When the validator
//!   set changes, the epoch increments. Epochs provide reconfiguration boundaries for the consensus
//!   protocol.
//!
//! - [`View`]: A monotonically increasing counter within a single epoch, representing individual
//!   consensus rounds. Views advance as the protocol progresses through proposals and votes.
//!
//! - [`Round`]: Combines an epoch and view into a single identifier for a consensus round.
//!   Provides ordering across epoch boundaries.
//!
//! - [`Delta`]: A generic type representing offsets or durations for consensus types. Provides
//!   type safety to prevent mixing epoch and view deltas. Type aliases [`EpochDelta`] and
//!   [`ViewDelta`] are provided for convenience.
//!
//! # Arithmetic Safety
//!
//! Arithmetic operations avoid silent errors. Only `next()` panics on overflow. All other
//! operations either saturate or return `Option`.
//!
//! # Type Conversions
//!
//! Explicit type constructors (`Epoch::new()`, `View::new()`) are required to create instances
//! from raw integers. Implicit conversions via, e.g. `From<u64>` are intentionally not provided
//! to prevent accidental type misuse.

use bytes::{Buf, BufMut};
use commonware_codec::{varint::UInt, EncodeSize, Error, Read, ReadExt, Write};
use commonware_utils::sequence::U64;
use std::{
    fmt::{self, Display, Formatter},
    marker::PhantomData,
};

/// Represents a distinct segment of a contiguous sequence of views.
///
/// An epoch increments when the validator set changes, providing a reconfiguration boundary.
/// All consensus operations within an epoch use the same validator set.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Epoch(u64);

impl Epoch {
    /// Returns epoch zero.
    pub const fn zero() -> Self {
        Self(0)
    }

    /// Creates a new epoch from a u64 value.
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the underlying u64 value.
    pub const fn get(self) -> u64 {
        self.0
    }

    /// Returns true if this is epoch zero.
    pub const fn is_zero(self) -> bool {
        self.0 == 0
    }

    /// Returns the next epoch.
    ///
    /// # Panics
    ///
    /// Panics if the epoch would overflow u64::MAX. In practice, this is extremely unlikely
    /// to occur during normal operation.
    pub const fn next(self) -> Self {
        Self(self.0.checked_add(1).expect("epoch overflow"))
    }

    /// Returns the previous epoch, or `None` if this is epoch zero.
    ///
    /// Unlike `Epoch::next()`, this returns an Option since reaching epoch zero
    /// is common, whereas overflowing u64::MAX is not expected in normal
    /// operation.
    pub fn previous(self) -> Option<Self> {
        self.0.checked_sub(1).map(Self)
    }

    /// Adds a delta to this epoch, saturating at u64::MAX.
    pub const fn saturating_add(self, delta: EpochDelta) -> Self {
        Self(self.0.saturating_add(delta.0))
    }

    /// Subtracts a delta from this epoch, returning `None` if it would underflow.
    pub fn checked_sub(self, delta: EpochDelta) -> Option<Self> {
        self.0.checked_sub(delta.0).map(Self)
    }

    /// Subtracts a delta from this epoch, saturating at zero.
    pub const fn saturating_sub(self, delta: EpochDelta) -> Self {
        Self(self.0.saturating_sub(delta.0))
    }
}

impl Display for Epoch {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Read for Epoch {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _cfg: &Self::Cfg) -> Result<Self, Error> {
        let value: u64 = UInt::read(buf)?.into();
        Ok(Self(value))
    }
}

impl Write for Epoch {
    fn write(&self, buf: &mut impl BufMut) {
        UInt(self.0).write(buf);
    }
}

impl EncodeSize for Epoch {
    fn encode_size(&self) -> usize {
        UInt(self.0).encode_size()
    }
}

impl From<Epoch> for U64 {
    fn from(epoch: Epoch) -> Self {
        Self::from(epoch.get())
    }
}

/// A monotonically increasing counter within a single epoch.
///
/// Views represent individual consensus rounds within an epoch. Each view corresponds to
/// one attempt to reach consensus on a proposal.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct View(u64);

impl View {
    /// Returns view zero.
    pub const fn zero() -> Self {
        Self(0)
    }

    /// Creates a new view from a u64 value.
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the underlying u64 value.
    pub const fn get(self) -> u64 {
        self.0
    }

    /// Returns true if this is view zero.
    pub const fn is_zero(self) -> bool {
        self.0 == 0
    }

    /// Returns the next view.
    ///
    /// # Panics
    ///
    /// Panics if the view would overflow u64::MAX. In practice, this is extremely unlikely
    /// to occur during normal operation.
    pub const fn next(self) -> Self {
        Self(self.0.checked_add(1).expect("view overflow"))
    }

    /// Returns the previous view, or `None` if this is view zero.
    ///
    /// Unlike `View::next()`, this returns an Option since reaching view zero
    /// is common, whereas overflowing u64::MAX is not expected in normal
    /// operation.
    pub fn previous(self) -> Option<Self> {
        self.0.checked_sub(1).map(Self)
    }

    /// Adds a view delta, saturating at u64::MAX.
    pub const fn saturating_add(self, delta: ViewDelta) -> Self {
        Self(self.0.saturating_add(delta.0))
    }

    /// Subtracts a view delta, saturating at zero.
    pub const fn saturating_sub(self, delta: ViewDelta) -> Self {
        Self(self.0.saturating_sub(delta.0))
    }

    /// Returns an iterator over the range [start, end).
    ///
    /// If start >= end, returns an empty range.
    pub const fn range(start: Self, end: Self) -> ViewRange {
        ViewRange {
            inner: start.get()..end.get(),
        }
    }
}

impl Display for View {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Read for View {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _cfg: &Self::Cfg) -> Result<Self, Error> {
        let value: u64 = UInt::read(buf)?.into();
        Ok(Self(value))
    }
}

impl Write for View {
    fn write(&self, buf: &mut impl BufMut) {
        UInt(self.0).write(buf);
    }
}

impl EncodeSize for View {
    fn encode_size(&self) -> usize {
        UInt(self.0).encode_size()
    }
}

impl From<View> for U64 {
    fn from(view: View) -> Self {
        Self::from(view.get())
    }
}

/// A generic type representing offsets or durations for consensus types.
///
/// `Delta<T>` is semantically distinct from point-in-time types like `Epoch` or `View` -
/// it represents a duration or distance rather than a specific moment.
///
/// For convenience, type aliases [`EpochDelta`] and [`ViewDelta`] are provided and should
/// be preferred in most code.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Delta<T>(u64, PhantomData<T>);

impl<T> Delta<T> {
    /// Returns a delta of zero.
    pub const fn zero() -> Self {
        Self(0, PhantomData)
    }

    /// Creates a new delta from a u64 value.
    pub const fn new(value: u64) -> Self {
        Self(value, PhantomData)
    }

    /// Returns the underlying u64 value.
    pub const fn get(self) -> u64 {
        self.0
    }

    /// Returns true if this delta is zero.
    pub const fn is_zero(self) -> bool {
        self.0 == 0
    }
}

impl<T> Display for Delta<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Type alias for epoch offsets and durations.
///
/// `EpochDelta` represents a distance between epochs or a duration measured in epochs.
/// It is used for epoch arithmetic operations and defining epoch bounds for data retention.
pub type EpochDelta = Delta<Epoch>;

/// Type alias for view offsets and durations.
///
/// `ViewDelta` represents a distance between views or a duration measured in views.
/// It is commonly used for timeouts, activity tracking windows, and view arithmetic.
pub type ViewDelta = Delta<View>;

/// A unique identifier combining epoch and view for a consensus round.
///
/// Round provides a total ordering across epoch boundaries, where rounds are
/// ordered first by epoch, then by view within that epoch.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Round {
    epoch: Epoch,
    view: View,
}

impl Round {
    /// Creates a new round from an epoch and view.
    pub const fn new(epoch: Epoch, view: View) -> Self {
        Self { epoch, view }
    }

    /// Returns round zero, i.e. epoch zero and view zero.
    pub const fn zero() -> Self {
        Self::new(Epoch::zero(), View::zero())
    }

    /// Returns the epoch of this round.
    pub const fn epoch(self) -> Epoch {
        self.epoch
    }

    /// Returns the view of this round.
    pub const fn view(self) -> View {
        self.view
    }
}

impl From<(Epoch, View)> for Round {
    fn from((epoch, view): (Epoch, View)) -> Self {
        Self { epoch, view }
    }
}

impl From<Round> for (Epoch, View) {
    fn from(round: Round) -> Self {
        (round.epoch, round.view)
    }
}

impl Read for Round {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _cfg: &Self::Cfg) -> Result<Self, Error> {
        Ok(Self {
            epoch: Epoch::read(buf)?,
            view: View::read(buf)?,
        })
    }
}

impl Write for Round {
    fn write(&self, buf: &mut impl BufMut) {
        self.epoch.write(buf);
        self.view.write(buf);
    }
}

impl EncodeSize for Round {
    fn encode_size(&self) -> usize {
        self.epoch.encode_size() + self.view.encode_size()
    }
}

impl Display for Round {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "({}, {})", self.epoch, self.view)
    }
}

/// An iterator over a range of views.
///
/// Created by [`View::range`]. Iterates from start (inclusive) to end (exclusive).
pub struct ViewRange {
    inner: std::ops::Range<u64>,
}

impl Iterator for ViewRange {
    type Item = View;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().map(View::new)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}

impl DoubleEndedIterator for ViewRange {
    fn next_back(&mut self) -> Option<Self::Item> {
        self.inner.next_back().map(View::new)
    }
}

impl ExactSizeIterator for ViewRange {
    fn len(&self) -> usize {
        self.size_hint().0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::{DecodeExt, Encode, EncodeSize};

    #[test]
    fn test_epoch_constructors() {
        assert_eq!(Epoch::zero().get(), 0);
        assert_eq!(Epoch::new(42).get(), 42);
        assert_eq!(Epoch::default().get(), 0);
    }

    #[test]
    fn test_epoch_is_zero() {
        assert!(Epoch::zero().is_zero());
        assert!(Epoch::new(0).is_zero());
        assert!(!Epoch::new(1).is_zero());
        assert!(!Epoch::new(100).is_zero());
    }

    #[test]
    fn test_epoch_next() {
        assert_eq!(Epoch::zero().next().get(), 1);
        assert_eq!(Epoch::new(5).next().get(), 6);
        assert_eq!(Epoch::new(999).next().get(), 1000);
    }

    #[test]
    #[should_panic(expected = "epoch overflow")]
    fn test_epoch_next_overflow() {
        Epoch::new(u64::MAX).next();
    }

    #[test]
    fn test_epoch_previous() {
        assert_eq!(Epoch::zero().previous(), None);
        assert_eq!(Epoch::new(1).previous(), Some(Epoch::zero()));
        assert_eq!(Epoch::new(5).previous(), Some(Epoch::new(4)));
        assert_eq!(Epoch::new(1000).previous(), Some(Epoch::new(999)));
    }

    #[test]
    fn test_epoch_saturating_add() {
        assert_eq!(Epoch::zero().saturating_add(EpochDelta::new(5)).get(), 5);
        assert_eq!(Epoch::new(10).saturating_add(EpochDelta::new(20)).get(), 30);
        assert_eq!(
            Epoch::new(u64::MAX)
                .saturating_add(EpochDelta::new(1))
                .get(),
            u64::MAX
        );
        assert_eq!(
            Epoch::new(u64::MAX - 5)
                .saturating_add(EpochDelta::new(10))
                .get(),
            u64::MAX
        );
    }

    #[test]
    fn test_epoch_checked_sub() {
        assert_eq!(
            Epoch::new(10).checked_sub(EpochDelta::new(5)),
            Some(Epoch::new(5))
        );
        assert_eq!(
            Epoch::new(5).checked_sub(EpochDelta::new(5)),
            Some(Epoch::zero())
        );
        assert_eq!(Epoch::new(5).checked_sub(EpochDelta::new(10)), None);
        assert_eq!(Epoch::zero().checked_sub(EpochDelta::new(1)), None);
    }

    #[test]
    fn test_epoch_saturating_sub() {
        assert_eq!(Epoch::new(10).saturating_sub(EpochDelta::new(5)).get(), 5);
        assert_eq!(Epoch::new(5).saturating_sub(EpochDelta::new(5)).get(), 0);
        assert_eq!(Epoch::new(5).saturating_sub(EpochDelta::new(10)).get(), 0);
        assert_eq!(Epoch::zero().saturating_sub(EpochDelta::new(100)).get(), 0);
    }

    #[test]
    fn test_epoch_display() {
        assert_eq!(format!("{}", Epoch::zero()), "0");
        assert_eq!(format!("{}", Epoch::new(42)), "42");
        assert_eq!(format!("{}", Epoch::new(1000)), "1000");
    }

    #[test]
    fn test_epoch_ordering() {
        assert!(Epoch::zero() < Epoch::new(1));
        assert!(Epoch::new(5) < Epoch::new(10));
        assert!(Epoch::new(10) > Epoch::new(5));
        assert_eq!(Epoch::new(42), Epoch::new(42));
    }

    #[test]
    fn test_epoch_encode_decode() {
        let cases = vec![0u64, 1, 127, 128, 255, 256, u64::MAX];
        for value in cases {
            let epoch = Epoch::new(value);
            let encoded = epoch.encode();
            assert_eq!(encoded.len(), epoch.encode_size());
            let decoded = Epoch::decode(encoded).unwrap();
            assert_eq!(epoch, decoded);
        }
    }

    #[test]
    fn test_view_constructors() {
        assert_eq!(View::zero().get(), 0);
        assert_eq!(View::new(42).get(), 42);
        assert_eq!(View::new(100).get(), 100);
        assert_eq!(View::default().get(), 0);
    }

    #[test]
    fn test_view_is_zero() {
        assert!(View::zero().is_zero());
        assert!(View::new(0).is_zero());
        assert!(!View::new(1).is_zero());
        assert!(!View::new(100).is_zero());
    }

    #[test]
    fn test_view_next() {
        assert_eq!(View::zero().next().get(), 1);
        assert_eq!(View::new(5).next().get(), 6);
        assert_eq!(View::new(999).next().get(), 1000);
    }

    #[test]
    #[should_panic(expected = "view overflow")]
    fn test_view_next_overflow() {
        View::new(u64::MAX).next();
    }

    #[test]
    fn test_view_previous() {
        assert_eq!(View::zero().previous(), None);
        assert_eq!(View::new(1).previous(), Some(View::zero()));
        assert_eq!(View::new(5).previous(), Some(View::new(4)));
        assert_eq!(View::new(1000).previous(), Some(View::new(999)));
    }

    #[test]
    fn test_view_saturating_add() {
        let delta5 = ViewDelta::new(5);
        let delta100 = ViewDelta::new(100);
        assert_eq!(View::zero().saturating_add(delta5).get(), 5);
        assert_eq!(View::new(10).saturating_add(delta100).get(), 110);
        assert_eq!(
            View::new(u64::MAX).saturating_add(ViewDelta::new(1)).get(),
            u64::MAX
        );
    }

    #[test]
    fn test_view_saturating_sub() {
        let delta5 = ViewDelta::new(5);
        let delta100 = ViewDelta::new(100);
        assert_eq!(View::new(10).saturating_sub(delta5).get(), 5);
        assert_eq!(View::new(5).saturating_sub(delta5).get(), 0);
        assert_eq!(View::new(5).saturating_sub(delta100).get(), 0);
        assert_eq!(View::zero().saturating_sub(delta100).get(), 0);
    }

    #[test]
    fn test_view_display() {
        assert_eq!(format!("{}", View::zero()), "0");
        assert_eq!(format!("{}", View::new(42)), "42");
        assert_eq!(format!("{}", View::new(1000)), "1000");
    }

    #[test]
    fn test_view_ordering() {
        assert!(View::zero() < View::new(1));
        assert!(View::new(5) < View::new(10));
        assert!(View::new(10) > View::new(5));
        assert_eq!(View::new(42), View::new(42));
    }

    #[test]
    fn test_view_encode_decode() {
        let cases = vec![0u64, 1, 127, 128, 255, 256, u64::MAX];
        for value in cases {
            let view = View::new(value);
            let encoded = view.encode();
            assert_eq!(encoded.len(), view.encode_size());
            let decoded = View::decode(encoded).unwrap();
            assert_eq!(view, decoded);
        }
    }

    #[test]
    fn test_view_delta_constructors() {
        assert_eq!(ViewDelta::zero().get(), 0);
        assert_eq!(ViewDelta::new(42).get(), 42);
        assert_eq!(ViewDelta::new(100).get(), 100);
        assert_eq!(ViewDelta::default().get(), 0);
    }

    #[test]
    fn test_view_delta_is_zero() {
        assert!(ViewDelta::zero().is_zero());
        assert!(ViewDelta::new(0).is_zero());
        assert!(!ViewDelta::new(1).is_zero());
        assert!(!ViewDelta::new(100).is_zero());
    }

    #[test]
    fn test_view_delta_display() {
        assert_eq!(format!("{}", ViewDelta::zero()), "0");
        assert_eq!(format!("{}", ViewDelta::new(42)), "42");
        assert_eq!(format!("{}", ViewDelta::new(1000)), "1000");
    }

    #[test]
    fn test_view_delta_ordering() {
        assert!(ViewDelta::zero() < ViewDelta::new(1));
        assert!(ViewDelta::new(5) < ViewDelta::new(10));
        assert!(ViewDelta::new(10) > ViewDelta::new(5));
        assert_eq!(ViewDelta::new(42), ViewDelta::new(42));
    }

    #[test]
    fn test_round_cmp() {
        assert!(Round::new(Epoch::new(1), View::new(2)) < Round::new(Epoch::new(1), View::new(3)));
        assert!(Round::new(Epoch::new(1), View::new(2)) < Round::new(Epoch::new(2), View::new(1)));
    }

    #[test]
    fn test_round_encode_decode_roundtrip() {
        let r: Round = (Epoch::new(42), View::new(1_000_000)).into();
        let encoded = r.encode();
        assert_eq!(encoded.len(), r.encode_size());
        let decoded = Round::decode(encoded).unwrap();
        assert_eq!(r, decoded);
    }

    #[test]
    fn test_round_conversions() {
        let r: Round = (Epoch::new(5), View::new(6)).into();
        assert_eq!(r.epoch(), Epoch::new(5));
        assert_eq!(r.view(), View::new(6));
        let tuple: (Epoch, View) = r.into();
        assert_eq!(tuple, (Epoch::new(5), View::new(6)));
    }

    #[test]
    fn test_round_new() {
        let r = Round::new(Epoch::new(10), View::new(20));
        assert_eq!(r.epoch(), Epoch::new(10));
        assert_eq!(r.view(), View::new(20));

        let r2 = Round::new(Epoch::new(5), View::new(15));
        assert_eq!(r2.epoch(), Epoch::new(5));
        assert_eq!(r2.view(), View::new(15));
    }

    #[test]
    fn test_round_display() {
        let r = Round::new(Epoch::new(5), View::new(100));
        assert_eq!(format!("{r}"), "(5, 100)");
    }

    #[test]
    fn view_range_iterates() {
        let collected: Vec<_> = View::range(View::new(3), View::new(6))
            .map(View::get)
            .collect();
        assert_eq!(collected, vec![3, 4, 5]);
    }

    #[test]
    fn view_range_empty() {
        let collected: Vec<_> = View::range(View::new(5), View::new(5)).collect();
        assert_eq!(collected, vec![]);

        let collected: Vec<_> = View::range(View::new(10), View::new(5)).collect();
        assert_eq!(collected, vec![]);
    }

    #[test]
    fn view_range_single() {
        let collected: Vec<_> = View::range(View::new(5), View::new(6))
            .map(View::get)
            .collect();
        assert_eq!(collected, vec![5]);
    }

    #[test]
    fn view_range_size_hint() {
        let range = View::range(View::new(3), View::new(10));
        assert_eq!(range.size_hint(), (7, Some(7)));
        assert_eq!(range.len(), 7);

        let empty = View::range(View::new(5), View::new(5));
        assert_eq!(empty.size_hint(), (0, Some(0)));
        assert_eq!(empty.len(), 0);
    }

    #[test]
    fn view_range_collect() {
        let views: Vec<View> = View::range(View::new(0), View::new(3)).collect();
        assert_eq!(views, vec![View::zero(), View::new(1), View::new(2)]);
    }

    #[test]
    fn view_range_iterator_next() {
        let mut range = View::range(View::new(5), View::new(8));
        assert_eq!(range.next(), Some(View::new(5)));
        assert_eq!(range.next(), Some(View::new(6)));
        assert_eq!(range.next(), Some(View::new(7)));
        assert_eq!(range.next(), None);
        assert_eq!(range.next(), None); // Multiple None
    }

    #[test]
    fn view_range_exact_size_iterator() {
        let range = View::range(View::new(10), View::new(15));
        assert_eq!(range.len(), 5);
        assert_eq!(range.size_hint(), (5, Some(5)));

        let mut range = View::range(View::new(10), View::new(15));
        assert_eq!(range.len(), 5);
        range.next();
        assert_eq!(range.len(), 4);
        range.next();
        assert_eq!(range.len(), 3);
    }

    #[test]
    fn view_range_rev() {
        // Use .rev() to iterate in descending order
        let collected: Vec<_> = View::range(View::new(3), View::new(7))
            .rev()
            .map(View::get)
            .collect();
        assert_eq!(collected, vec![6, 5, 4, 3]);
    }

    #[test]
    fn view_range_double_ended() {
        // Mixed next() and next_back() calls
        let mut range = View::range(View::new(5), View::new(10));
        assert_eq!(range.next(), Some(View::new(5)));
        assert_eq!(range.next_back(), Some(View::new(9)));
        assert_eq!(range.next(), Some(View::new(6)));
        assert_eq!(range.next_back(), Some(View::new(8)));
        assert_eq!(range.len(), 1);
        assert_eq!(range.next(), Some(View::new(7)));
        assert_eq!(range.next(), None);
        assert_eq!(range.next_back(), None);
    }
}
