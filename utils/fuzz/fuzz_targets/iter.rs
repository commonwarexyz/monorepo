#![no_main]

//! Check [zip_eq] against [Iterator::zip], and [NonEmpty] against the items it is built from.
//!
//! Over sides of equal length, [zip_eq] must yield exactly the pairs [Iterator::zip] yields,
//! with a size hint that bounds the pairs left at every step, and an exact length when both
//! sides know theirs. Over sides of unequal length, it must yield the pairs of the common
//! prefix and then panic. Each side reports a fuzzed size hint that stays a valid bound, with
//! or without an upper bound. [NonEmpty] must build exactly from non-empty sources and yield
//! their items in order, whole or split into its first item and the rest.

use arbitrary::Arbitrary;
use commonware_utils::{
    iter::{NonEmpty, zip_eq},
    non_empty,
};
use libfuzzer_sys::fuzz_target;
use std::{
    panic::{self, AssertUnwindSafe},
    vec,
};

/// How far a side's size hint strays from the items it has left.
#[derive(Arbitrary, Clone, Copy, Debug)]
struct Hint {
    /// How far the lower bound falls short.
    below: u8,
    /// How far the upper bound exceeds, or `None` for no upper bound.
    above: Option<u8>,
}

/// Yields `items` while reporting a size hint loosened by `hint`.
struct Side {
    hint: Hint,
    items: vec::IntoIter<u8>,
}

impl Side {
    fn new(hint: Hint, items: Vec<u8>) -> Self {
        Self {
            hint,
            items: items.into_iter(),
        }
    }
}

impl Iterator for Side {
    type Item = u8;

    fn next(&mut self) -> Option<u8> {
        self.items.next()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let left = self.items.len();
        let low = left.saturating_sub(usize::from(self.hint.below));
        let high = self.hint.above.map(|above| left + usize::from(above));
        (low, high)
    }
}

#[derive(Arbitrary, Debug)]
enum FuzzInput {
    /// Zip sides of equal length.
    ZipEqual {
        left: Hint,
        right: Hint,
        pairs: Vec<(u8, u8)>,
    },
    /// Zip sides of any length.
    Zip {
        left: Hint,
        right: Hint,
        left_items: Vec<u8>,
        right_items: Vec<u8>,
    },
    /// Build a [NonEmpty] from any items.
    NonEmpty { items: Vec<u8> },
}

/// Whether `f` panics, without aborting.
fn panics(f: impl FnOnce()) -> bool {
    let hook = panic::take_hook();
    panic::set_hook(Box::new(|_| {}));
    let result = panic::catch_unwind(AssertUnwindSafe(f));
    panic::set_hook(hook);
    result.is_err()
}

/// Whether the size hint `(low, high)` bounds `left` items.
fn bounds((low, high): (usize, Option<usize>), left: usize) -> bool {
    low <= left && high.is_none_or(|high| left <= high)
}

fn check_zip(left: Hint, left_items: Vec<u8>, right: Hint, right_items: Vec<u8>) {
    let expected: Vec<(u8, u8)> = left_items
        .iter()
        .copied()
        .zip(right_items.iter().copied())
        .collect();
    let mut zipped = zip_eq(
        Side::new(left, left_items.clone()),
        Side::new(right, right_items.clone()),
    );

    if left_items.len() != right_items.len() {
        let mut yielded = Vec::new();
        assert!(
            panics(|| zipped.for_each(|pair| yielded.push(pair))),
            "zip_eq over unequal lengths must panic"
        );
        assert_eq!(yielded, expected);
        return;
    }

    let mut exact = zip_eq(left_items, right_items);
    for (taken, pair) in expected.iter().enumerate() {
        let left = expected.len() - taken;
        assert!(bounds(zipped.size_hint(), left), "size hint misses length");
        assert_eq!(exact.len(), left);
        assert_eq!(zipped.next(), Some(*pair));
        assert_eq!(exact.next(), Some(*pair));
    }
    assert!(bounds(zipped.size_hint(), 0), "size hint misses length");
    assert_eq!(exact.len(), 0);
    assert_eq!(zipped.next(), None);
    assert_eq!(exact.next(), None);
}

fn check_non_empty(items: Vec<u8>) {
    let Some(built) = NonEmpty::try_new(items.clone().into_iter()) else {
        assert!(items.is_empty());
        return;
    };
    assert_eq!(built.clone().into_iter().collect::<Vec<_>>(), items);

    let (first, rest) = built.into_parts();
    assert_eq!(first, items[0]);
    assert_eq!(rest.as_slice(), &items[1..]);
    let rebuilt = NonEmpty::new(first, rest);
    assert_eq!(rebuilt.into_iter().collect::<Vec<_>>(), items);

    let from_macro = non_empty![@items.iter().copied()];
    assert_eq!(from_macro.into_iter().collect::<Vec<_>>(), items);
    let last = items[items.len() - 1];
    let listed = non_empty![first, last];
    assert_eq!(listed.into_iter().collect::<Vec<_>>(), [first, last]);
}

fuzz_target!(|inputs: Vec<FuzzInput>| {
    for input in inputs {
        match input {
            FuzzInput::ZipEqual { left, right, pairs } => {
                let (left_items, right_items) = pairs.into_iter().unzip();
                check_zip(left, left_items, right, right_items);
            }
            FuzzInput::Zip {
                left,
                right,
                left_items,
                right_items,
            } => check_zip(left, left_items, right, right_items),
            FuzzInput::NonEmpty { items } => check_non_empty(items),
        }
    }
});
