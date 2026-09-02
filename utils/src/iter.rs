//! Iterator types with additional invariants.

use core::iter::{Chain, Once, once};

/// An iterator source guaranteed to yield at least one item.
///
/// # Examples
///
/// ```
/// use commonware_utils::iter::NonEmpty;
///
/// let items = NonEmpty::try_new([1, 2, 3].into_iter()).expect("items are non-empty");
/// assert_eq!(items.into_iter().collect::<Vec<_>>(), vec![1, 2, 3]);
/// ```
#[derive(Clone, Debug)]
pub struct NonEmpty<I: Iterator> {
    first: I::Item,
    rest: I,
}

impl<I: Iterator> NonEmpty<I> {
    /// Creates a non-empty iterator from a first item and the remaining items.
    pub const fn new(first: I::Item, rest: I) -> Self {
        Self { first, rest }
    }

    /// Creates a non-empty iterator from `items`, or returns `None` when it is empty.
    pub fn try_new(mut items: I) -> Option<Self> {
        let first = items.next()?;
        Some(Self::new(first, items))
    }

    /// Consumes this source, returning its first item and remaining iterator.
    pub fn into_parts(self) -> (I::Item, I) {
        (self.first, self.rest)
    }
}

impl<I: Iterator> IntoIterator for NonEmpty<I> {
    type Item = I::Item;
    type IntoIter = Chain<Once<I::Item>, I>;

    fn into_iter(self) -> Self::IntoIter {
        once(self.first).chain(self.rest)
    }
}

/// Creates a [`NonEmpty`] iterator from one or more items.
///
/// # Examples
///
/// ```
/// use commonware_utils::non_empty;
///
/// let items = non_empty![1, 2, 3];
/// assert_eq!(items.into_iter().collect::<Vec<_>>(), vec![1, 2, 3]);
///
/// let items = non_empty![@1..4];
/// assert_eq!(items.into_iter().collect::<Vec<_>>(), vec![1, 2, 3]);
/// ```
///
/// ```compile_fail
/// use commonware_utils::non_empty;
///
/// let empty = non_empty![];
/// ```
///
/// # Panics
///
/// The `@` form panics if the provided iterator is empty.
#[cfg(not(any(
    commonware_stability_GAMMA,
    commonware_stability_DELTA,
    commonware_stability_EPSILON,
    commonware_stability_RESERVED
)))] // BETA
#[macro_export]
macro_rules! non_empty {
    (@$items:expr) => {{
        $crate::iter::NonEmpty::try_new(::core::iter::IntoIterator::into_iter($items))
            .expect("iterator must be non-empty")
    }};
    ($first:expr $(, $rest:expr)* $(,)?) => {
        $crate::iter::NonEmpty::new(
            $first,
            ::core::iter::IntoIterator::into_iter([$($rest),*]),
        )
    };
}

/// Zips two iterators, panicking if one is exhausted before the other.
///
/// Use this over [`Iterator::zip`] when equal lengths are an invariant: `zip` silently truncates
/// to the shorter side, hiding the mismatch.
///
/// # Examples
///
/// ```
/// use commonware_utils::iter::zip_eq;
///
/// let pairs: Vec<_> = zip_eq([1, 2], ["a", "b"]).collect();
/// assert_eq!(pairs, vec![(1, "a"), (2, "b")]);
/// ```
pub fn zip_eq<A: IntoIterator, B: IntoIterator>(a: A, b: B) -> ZipEq<A::IntoIter, B::IntoIter> {
    ZipEq {
        a: a.into_iter(),
        b: b.into_iter(),
    }
}

/// See [`zip_eq`].
#[derive(Clone, Debug)]
pub struct ZipEq<A, B> {
    a: A,
    b: B,
}

impl<A: Iterator, B: Iterator> Iterator for ZipEq<A, B> {
    type Item = (A::Item, B::Item);

    fn next(&mut self) -> Option<Self::Item> {
        match (self.a.next(), self.b.next()) {
            (Some(a), Some(b)) => Some((a, b)),
            (None, None) => None,
            (Some(_), None) => panic!("zip_eq: right iterator exhausted first"),
            (None, Some(_)) => panic!("zip_eq: left iterator exhausted first"),
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let (a_low, a_high) = self.a.size_hint();
        let (b_low, b_high) = self.b.size_hint();
        let high = match (a_high, b_high) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (Some(a), None) => Some(a),
            (None, Some(b)) => Some(b),
            (None, None) => None,
        };
        (a_low.min(b_low), high)
    }
}

impl<A: ExactSizeIterator, B: ExactSizeIterator> ExactSizeIterator for ZipEq<A, B> {}

#[cfg(test)]
mod tests {
    use super::{NonEmpty, zip_eq};

    #[test]
    fn try_new_rejects_empty() {
        assert!(NonEmpty::try_new(core::iter::empty::<u8>()).is_none());
    }

    #[test]
    fn iteration_preserves_every_item() {
        let items = NonEmpty::try_new([1, 2, 3].into_iter()).expect("items are non-empty");
        assert_eq!(items.into_iter().collect::<Vec<_>>(), vec![1, 2, 3]);
    }

    #[test]
    fn into_parts_separates_first_from_rest() {
        let items = NonEmpty::new(1, [2, 3].into_iter());
        let (first, rest) = items.into_parts();

        assert_eq!(first, 1);
        assert_eq!(rest.collect::<Vec<_>>(), vec![2, 3]);
    }

    #[test]
    fn macro_constructs_non_empty_iterators() {
        assert_eq!(non_empty![1].into_iter().collect::<Vec<_>>(), vec![1]);
        assert_eq!(
            non_empty![1, 2, 3].into_iter().collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
        assert_eq!(
            non_empty![@1..4].into_iter().collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
    }

    #[test]
    fn zip_eq_pairs_equal_lengths() {
        let pairs: Vec<_> = zip_eq([1, 2, 3], ["a", "b", "c"]).collect();

        assert_eq!(pairs, vec![(1, "a"), (2, "b"), (3, "c")]);
    }

    #[test]
    #[should_panic(expected = "right iterator exhausted first")]
    fn zip_eq_panics_when_right_is_shorter() {
        zip_eq([1, 2], [1]).count();
    }

    #[test]
    #[should_panic(expected = "left iterator exhausted first")]
    fn zip_eq_panics_when_left_is_shorter() {
        zip_eq([1], [1, 2]).count();
    }

    #[test]
    #[should_panic(expected = "iterator must be non-empty")]
    fn macro_rejects_empty_iterators() {
        let _ = non_empty![@core::iter::empty::<u8>()];
    }

    mod colliding_method {
        trait CollidingIntoIterator {
            fn into_iter(self);
        }

        impl<T, const N: usize> CollidingIntoIterator for [T; N] {
            fn into_iter(self) {}
        }

        #[test]
        fn macro_ignores_colliding_into_iterator_methods() {
            CollidingIntoIterator::into_iter([0]);

            assert_eq!(
                non_empty![1, 2, 3].into_iter().collect::<Vec<_>>(),
                vec![1, 2, 3]
            );
            assert_eq!(
                non_empty![@[1, 2, 3]].into_iter().collect::<Vec<_>>(),
                vec![1, 2, 3]
            );
        }
    }
}
