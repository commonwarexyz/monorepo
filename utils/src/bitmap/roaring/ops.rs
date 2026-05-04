//! Set operations for roaring bitmaps.
//!
//! Provides union, intersection, and difference operations with optional early termination
//! when a result limit is reached, along with the boolean predicates `is_subset` and
//! `intersects` which short-circuit on first conclusive observation.

#[cfg(test)]
use super::container::Container;
use super::Bitmap;
#[cfg(not(feature = "std"))]
use alloc::collections::BTreeMap;
use core::cmp::Ordering;
#[cfg(feature = "std")]
use std::collections::BTreeMap;

impl Bitmap {
    /// Computes the union of two bitmaps, returning at most `limit` values.
    ///
    /// Pass `u64::MAX` for unlimited results.
    pub fn union(&self, other: &Self, limit: u64) -> Self {
        let mut result = BTreeMap::new();
        let mut remaining = limit;

        let mut a_iter = self.containers.iter().peekable();
        let mut b_iter = other.containers.iter().peekable();

        while remaining > 0 {
            let a_key = a_iter.peek().map(|(&key, _)| key);
            let b_key = b_iter.peek().map(|(&key, _)| key);
            let Some(key) = next_key(a_key, b_key) else {
                break;
            };

            let (container, count) = match (a_key == Some(key), b_key == Some(key)) {
                (true, true) => {
                    let (_, a_container) = a_iter.next().unwrap();
                    let (_, b_container) = b_iter.next().unwrap();
                    a_container.union(b_container, remaining)
                }
                (true, false) => {
                    let (_, container) = a_iter.next().unwrap();
                    container.limit(remaining)
                }
                (false, true) => {
                    let (_, container) = b_iter.next().unwrap();
                    container.limit(remaining)
                }
                (false, false) => unreachable!("next_key returned a key from neither iterator"),
            };

            if count > 0 {
                result.insert(key, container);
                remaining -= count;
            }
        }

        Self { containers: result }
    }

    /// Computes the intersection of two bitmaps, returning at most `limit` values.
    ///
    /// Pass `u64::MAX` for unlimited results.
    pub fn intersection(&self, other: &Self, limit: u64) -> Self {
        let mut result = BTreeMap::new();
        let mut remaining = limit;

        for (&key, container) in self.containers.iter() {
            if remaining == 0 {
                break;
            }

            if let Some(other_container) = other.containers.get(&key) {
                let (container, count) = container.intersection(other_container, remaining);
                if count > 0 {
                    result.insert(key, container);
                    remaining -= count;
                }
            }
        }

        Self { containers: result }
    }

    /// Computes the difference `self - other`, returning at most `limit` values.
    ///
    /// Pass `u64::MAX` for unlimited results.
    pub fn difference(&self, other: &Self, limit: u64) -> Self {
        let mut result = BTreeMap::new();
        let mut remaining = limit;

        for (&key, container) in self.containers.iter() {
            if remaining == 0 {
                break;
            }

            let (container, count) = other.containers.get(&key).map_or_else(
                || container.limit(remaining),
                |other_container| container.difference(other_container, remaining),
            );

            if count > 0 {
                result.insert(key, container);
                remaining -= count;
            }
        }

        Self { containers: result }
    }

    /// Returns `true` if every value in this bitmap is present in `other`.
    pub fn is_subset(&self, other: &Self) -> bool {
        if self.len() > other.len() {
            return false;
        }

        self.containers.iter().all(|(key, container)| {
            other
                .containers
                .get(key)
                .is_some_and(|other_container| container.is_subset(other_container))
        })
    }

    /// Returns `true` if the bitmaps share at least one value.
    pub fn intersects(&self, other: &Self) -> bool {
        let (smaller, larger) = if self.containers.len() <= other.containers.len() {
            (&self.containers, &other.containers)
        } else {
            (&other.containers, &self.containers)
        };

        smaller.iter().any(|(key, container)| {
            larger
                .get(key)
                .is_some_and(|other_container| container.intersects(other_container))
        })
    }
}

fn next_key(a: Option<u64>, b: Option<u64>) -> Option<u64> {
    match a.cmp(&b) {
        Ordering::Equal => a,
        Ordering::Less => a.or(b),
        Ordering::Greater => b.or(a),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bitmap::BitMap as Reference;

    fn reference_len(a: &Bitmap, b: &Bitmap) -> u64 {
        a.iter().chain(b.iter()).max().map_or(0, |value| value + 1)
    }

    fn build_reference(bitmap: &Bitmap, len: u64) -> Reference {
        let mut reference = Reference::zeroes(len);
        for value in bitmap.iter() {
            reference.set(value, true);
        }
        reference
    }

    fn expected_values(reference: &Reference, limit: u64) -> Vec<u64> {
        if limit == 0 {
            return Vec::new();
        }

        let mut values = Vec::new();
        for value in 0..reference.len() {
            if reference.get(value) {
                values.push(value);
                if values.len() as u64 == limit {
                    break;
                }
            }
        }
        values
    }

    fn assert_matches_reference(result: &Bitmap, reference: &Reference, limit: u64, op: &str) {
        let actual: Vec<_> = result.iter().collect();
        let expected = expected_values(reference, limit);
        assert_eq!(actual, expected, "{op} mismatch");
        assert_eq!(result.len(), expected.len() as u64, "{op} length mismatch");
    }

    fn assert_union_matches_reference(a: &Bitmap, b: &Bitmap, limit: u64) -> Bitmap {
        let len = reference_len(a, b);
        let mut reference = build_reference(a, len);
        reference.or(&build_reference(b, len));

        let result = a.union(b, limit);
        assert_matches_reference(&result, &reference, limit, "union");
        result
    }

    fn assert_intersection_matches_reference(a: &Bitmap, b: &Bitmap, limit: u64) -> Bitmap {
        let len = reference_len(a, b);
        let mut reference = build_reference(a, len);
        reference.and(&build_reference(b, len));

        let result = a.intersection(b, limit);
        assert_matches_reference(&result, &reference, limit, "intersection");
        result
    }

    fn assert_difference_matches_reference(a: &Bitmap, b: &Bitmap, limit: u64) -> Bitmap {
        let len = reference_len(a, b);
        let mut reference = build_reference(a, len);
        for value in b.iter() {
            reference.set(value, false);
        }

        let result = a.difference(b, limit);
        assert_matches_reference(&result, &reference, limit, "difference");
        result
    }

    fn assert_is_subset_matches_reference(a: &Bitmap, b: &Bitmap) -> bool {
        let len = reference_len(a, b);
        let a_reference = build_reference(a, len);
        let b_reference = build_reference(b, len);
        let expected = (0..len).all(|value| !a_reference.get(value) || b_reference.get(value));
        let result = a.is_subset(b);
        assert_eq!(result, expected, "is_subset mismatch");
        result
    }

    fn assert_intersects_matches_reference(a: &Bitmap, b: &Bitmap) -> bool {
        let len = reference_len(a, b);
        let a_reference = build_reference(a, len);
        let b_reference = build_reference(b, len);
        let expected = (0..len).any(|value| a_reference.get(value) && b_reference.get(value));
        let result = a.intersects(b);
        assert_eq!(result, expected, "intersects mismatch");
        result
    }

    #[test]
    fn test_union_basic() {
        let a = Bitmap::from_iter([1, 2, 3]);
        let b = Bitmap::from_iter([2, 3, 4, 5]);

        assert_union_matches_reference(&a, &b, u64::MAX);
    }

    #[test]
    fn test_union_with_limit() {
        let a = Bitmap::from_iter([1, 2, 3]);
        let b = Bitmap::from_iter([4, 5, 6]);

        assert_union_matches_reference(&a, &b, 4);
    }

    #[test]
    fn test_union_empty() {
        let a = Bitmap::new();
        let b = Bitmap::from_iter([1, 2, 3]);

        assert_union_matches_reference(&a, &b, u64::MAX);
    }

    #[test]
    fn test_union_a_key_less_than_b() {
        // a's container at key 0, b's at key 1. Exercises the `a_key < b_key` branch
        // in `union` for a's container, then the trailing `(None, Some)` branch picks
        // up b's container.
        let a = Bitmap::from_iter([1, 2, 3]);
        let b = Bitmap::from_iter([65_536, 65_537, 65_538]);
        assert_union_matches_reference(&a, &b, u64::MAX);
    }

    #[test]
    fn test_union_b_key_less_than_a() {
        // a's container at key 1, b's at key 0. Exercises the `b_key < a_key` branch.
        let a = Bitmap::from_iter([65_536, 65_537, 65_538]);
        let b = Bitmap::from_iter([1, 2, 3]);
        assert_union_matches_reference(&a, &b, u64::MAX);
    }

    #[test]
    fn test_union_alternating_keys() {
        // Containers interleave: a at keys 0, 2; b at keys 1, 3. The outer merge loop
        // hits both `a_key < b_key` and `b_key < a_key` branches multiple times.
        let mut a = Bitmap::new();
        a.insert(10); // key 0
        a.insert(2 * 65_536 + 10); // key 2

        let mut b = Bitmap::new();
        b.insert(65_536 + 20); // key 1
        b.insert(3 * 65_536 + 20); // key 3

        let result = assert_union_matches_reference(&a, &b, u64::MAX);
        assert_eq!(result.container_count(), 4);
    }

    #[test]
    fn test_union_disjoint_keys_with_limit() {
        // Disjoint containers + limit smaller than a's container. Exercises the
        // `a_key < b_key` branch through `Container::limit` truncation.
        let a = Bitmap::from_iter([1, 2, 3]);
        let b = Bitmap::from_iter([65_536, 65_537, 65_538]);
        assert_union_matches_reference(&a, &b, 2);
    }

    #[test]
    fn test_container_union_array_array_promotes_to_bitmap_when_oversized() {
        use commonware_codec::{Decode, Encode};

        let mut a = Bitmap::new();
        let mut b = Bitmap::new();
        // 4000 even + 4000 odd values in shelf 0; each side stays in Array variant.
        for i in 0..4000u64 {
            a.insert(i * 2);
            b.insert(i * 2 + 1);
        }
        assert!(matches!(
            a.containers().get(&0).unwrap(),
            Container::Array(_)
        ));
        assert!(matches!(
            b.containers().get(&0).unwrap(),
            Container::Array(_)
        ));

        let result = assert_union_matches_reference(&a, &b, u64::MAX);

        // Result must promote to Bitmap.
        assert!(
            matches!(result.containers().get(&0).unwrap(), Container::Bitmap(_)),
            "oversized array union must promote to Bitmap variant"
        );

        // Roundtrip exercises the codec, which would reject an oversized Array.
        let bytes = result.encode();
        let decoded = Bitmap::decode_cfg(bytes, &(..=10usize).into()).unwrap();
        assert_eq!(result, decoded);
    }

    #[test]
    fn test_container_union_bitmap_bitmap_fast_path() {
        // Both containers in `Bitmap` variant at the same key. Exercises the
        // bitmap-bitmap fast path in `Container::union` (`Bitmap::or_new`).
        // Inserting alternating values past the Array threshold yields a Bitmap with
        // many isolated runs, well above the Bitmap→Run threshold so it stays Bitmap.
        let mut a = Bitmap::new();
        let mut b = Bitmap::new();
        for i in 0..4097u64 {
            a.insert(i * 2); // even values 0, 2, ..., 8192
            b.insert(i * 2 + 1); // odd values 1, 3, ..., 8193
        }
        assert!(matches!(
            a.containers().get(&0).unwrap(),
            Container::Bitmap(_)
        ));
        assert!(matches!(
            b.containers().get(&0).unwrap(),
            Container::Bitmap(_)
        ));

        assert_union_matches_reference(&a, &b, u64::MAX);
    }

    #[test]
    fn test_container_union_bitmap_bitmap_limit_truncates() {
        // Same setup as above but with a small limit, forcing the bitmap-bitmap fast
        // path through `Container::limit` after the OR is computed.
        let mut a = Bitmap::new();
        let mut b = Bitmap::new();
        for i in 0..4097u64 {
            a.insert(i * 2);
            b.insert(i * 2 + 1);
        }

        assert_union_matches_reference(&a, &b, 100);
    }

    #[test]
    fn test_container_union_mixed_variants_general_path() {
        // a's container is `Array`, b's is `Bitmap`, both at key 0. Neither fast path
        // applies, so `Container::union` falls through to the general iterator-merge
        // case.
        let mut a = Bitmap::new();
        a.insert(1);
        a.insert(50);
        a.insert(100);

        let mut b = Bitmap::new();
        for i in 0..4097u64 {
            b.insert(i * 2 + 200); // alternating values starting at 200
        }
        assert!(matches!(
            a.containers().get(&0).unwrap(),
            Container::Array(_)
        ));
        assert!(matches!(
            b.containers().get(&0).unwrap(),
            Container::Bitmap(_)
        ));

        assert_union_matches_reference(&a, &b, u64::MAX);
    }

    #[test]
    fn test_intersection_basic() {
        let a = Bitmap::from_iter([1, 2, 3, 4]);
        let b = Bitmap::from_iter([2, 3, 4, 5]);

        assert_intersection_matches_reference(&a, &b, u64::MAX);
    }

    #[test]
    fn test_intersection_with_limit() {
        let a = Bitmap::from_iter([1, 2, 3, 4, 5]);
        let b = Bitmap::from_iter([1, 2, 3, 4, 5]);

        assert_intersection_matches_reference(&a, &b, 3);
    }

    #[test]
    fn test_intersection_disjoint() {
        let a = Bitmap::from_iter([1, 2, 3]);
        let b = Bitmap::from_iter([4, 5, 6]);

        assert_intersection_matches_reference(&a, &b, u64::MAX);
    }

    #[test]
    fn test_intersection_containers_bitmap_bitmap_fast_path() {
        // Both containers in `Bitmap` variant at the same key. Exercises the
        // bitmap-bitmap fast path in `Container::intersection` (`Bitmap::and_new`).
        let mut a = Bitmap::new();
        let mut b = Bitmap::new();
        // a: even values 0, 2, ..., 8192 (4097 alternating)
        // b: every fourth value 0, 4, 8, ..., 16384 (4097 values)
        // Common values: 0, 4, 8, ..., 8192 (the multiples of 4 in [0, 8193]).
        for i in 0..4097u64 {
            a.insert(i * 2);
            b.insert(i * 4);
        }
        assert!(matches!(
            a.containers().get(&0).unwrap(),
            Container::Bitmap(_)
        ));
        assert!(matches!(
            b.containers().get(&0).unwrap(),
            Container::Bitmap(_)
        ));

        assert_intersection_matches_reference(&a, &b, u64::MAX);
    }

    #[test]
    fn test_intersection_containers_bitmap_bitmap_limit_truncates() {
        // Same setup as above but a small limit forces the bitmap-bitmap fast path
        // through `Container::limit` after `Bitmap::and_new` is computed.
        let mut a = Bitmap::new();
        let mut b = Bitmap::new();
        for i in 0..4097u64 {
            a.insert(i * 2);
            b.insert(i * 4);
        }

        assert_intersection_matches_reference(&a, &b, 50);
    }

    #[test]
    fn test_intersection_containers_mixed_variants_general_path() {
        // a's container is `Array`, b's is `Bitmap`. Neither fast path applies, so
        // `Container::intersection` falls through to the general "iterate smaller"
        // case. With a.len() (3) < b.len() (4097), the loop iterates a's values.
        let mut a = Bitmap::new();
        a.insert(1);
        a.insert(50);
        a.insert(200); // value 200 is in b's set (200 = 0*2 + 200; b has even+200 series)

        let mut b = Bitmap::new();
        for i in 0..4097u64 {
            b.insert(i * 2 + 200);
        }
        assert!(matches!(
            a.containers().get(&0).unwrap(),
            Container::Array(_)
        ));
        assert!(matches!(
            b.containers().get(&0).unwrap(),
            Container::Bitmap(_)
        ));

        assert_intersection_matches_reference(&a, &b, u64::MAX);
    }

    #[test]
    fn test_difference_basic() {
        let a = Bitmap::from_iter([1, 2, 3, 4]);
        let b = Bitmap::from_iter([2, 3]);

        assert_difference_matches_reference(&a, &b, u64::MAX);
    }

    #[test]
    fn test_difference_with_limit() {
        let a = Bitmap::from_iter([1, 2, 3, 4, 5]);
        let b = Bitmap::from_iter([2, 4]);

        assert_difference_matches_reference(&a, &b, 2);
    }

    #[test]
    fn test_difference_all_removed() {
        let a = Bitmap::from_iter([1, 2, 3]);
        let b = Bitmap::from_iter([1, 2, 3, 4, 5]);

        assert_difference_matches_reference(&a, &b, u64::MAX);
    }

    #[test]
    fn test_container_difference_bitmap_bitmap_fast_path() {
        // Both containers in `Bitmap` variant at the same key. Exercises the
        // bitmap-bitmap fast path in `Container::difference` (`Bitmap::and_not_new`).
        let mut a = Bitmap::new();
        let mut b = Bitmap::new();
        // a: even values 0, 2, ..., 8192 (4097 values)
        // b: multiples of 4 from 0, 4, ..., 16384 (4097 values)
        // a − b: even values not divisible by 4 in [0, 8192] = {2, 6, 10, ..., 8190}
        for i in 0..4097u64 {
            a.insert(i * 2);
            b.insert(i * 4);
        }
        assert!(matches!(
            a.containers().get(&0).unwrap(),
            Container::Bitmap(_)
        ));
        assert!(matches!(
            b.containers().get(&0).unwrap(),
            Container::Bitmap(_)
        ));

        assert_difference_matches_reference(&a, &b, u64::MAX);
    }

    #[test]
    fn test_container_difference_bitmap_bitmap_limit_truncates() {
        // Same setup but a small limit forces the fast path through
        // `Container::limit` after `Bitmap::and_not_new` is computed.
        let mut a = Bitmap::new();
        let mut b = Bitmap::new();
        for i in 0..4097u64 {
            a.insert(i * 2);
            b.insert(i * 4);
        }

        assert_difference_matches_reference(&a, &b, 30);
    }

    #[test]
    fn test_container_difference_mixed_variants_general_path() {
        // a's container is `Array`, b's is `Bitmap`. Neither fast path applies, so
        // `Container::difference` falls through to the general "iterate a, skip values in b"
        // case.
        let mut a = Bitmap::new();
        a.insert(1);
        a.insert(50);
        a.insert(200);

        let mut b = Bitmap::new();
        for i in 0..4097u64 {
            b.insert(i * 2 + 200); // 200, 202, ..., 8392
        }
        assert!(matches!(
            a.containers().get(&0).unwrap(),
            Container::Array(_)
        ));
        assert!(matches!(
            b.containers().get(&0).unwrap(),
            Container::Bitmap(_)
        ));

        assert_difference_matches_reference(&a, &b, u64::MAX);
    }

    #[test]
    fn test_union_multiple_containers() {
        let mut a = Bitmap::new();
        let mut b = Bitmap::new();

        // Values in different containers
        a.insert(100);
        a.insert(65536 + 100); // Second container

        b.insert(200);
        b.insert(65536 + 200); // Second container

        assert_union_matches_reference(&a, &b, u64::MAX);
    }

    #[test]
    fn test_intersection_multiple_containers() {
        let mut a = Bitmap::new();
        let mut b = Bitmap::new();

        a.insert(100);
        a.insert(200);
        a.insert(65536 + 100);

        b.insert(200);
        b.insert(300);
        b.insert(65536 + 100);

        assert_intersection_matches_reference(&a, &b, u64::MAX);
    }

    #[test]
    fn test_operations_with_zero_limit() {
        let a = Bitmap::from_iter([1, 2, 3]);
        let b = Bitmap::from_iter([2, 3, 4]);

        assert_union_matches_reference(&a, &b, 0);
        assert_intersection_matches_reference(&a, &b, 0);
        assert_difference_matches_reference(&a, &b, 0);
    }

    // ---- is_subset ----

    #[test]
    fn test_is_subset_proper() {
        let a = Bitmap::from_iter([1, 2, 3]);
        let b = Bitmap::from_iter([1, 2, 3, 4, 5]);
        assert!(assert_is_subset_matches_reference(&a, &b));
        assert!(!assert_is_subset_matches_reference(&b, &a));
    }

    #[test]
    fn test_is_subset_equal() {
        let a = Bitmap::from_iter([1, 2, 3]);
        let b = Bitmap::from_iter([1, 2, 3]);
        assert!(assert_is_subset_matches_reference(&a, &b));
        assert!(assert_is_subset_matches_reference(&b, &a));
    }

    #[test]
    fn test_is_subset_empty() {
        let empty = Bitmap::new();
        let nonempty = Bitmap::from_iter([1, 2, 3]);
        // Empty is subset of any set, including itself.
        assert!(assert_is_subset_matches_reference(&empty, &nonempty));
        assert!(assert_is_subset_matches_reference(&empty, &empty));
        // Non-empty is not a subset of empty.
        assert!(!assert_is_subset_matches_reference(&nonempty, &empty));
    }

    #[test]
    fn test_is_subset_missing_value_same_container() {
        let a = Bitmap::from_iter([1, 2, 3]);
        let b = Bitmap::from_iter([1, 3]); // missing 2
        assert!(!assert_is_subset_matches_reference(&a, &b));
    }

    #[test]
    fn test_is_subset_missing_container() {
        // a has values in container 1; b has only container 0.
        let a = Bitmap::from_iter([1, 65536 + 100]);
        let b = Bitmap::from_iter([1, 2, 3]);
        assert!(!assert_is_subset_matches_reference(&a, &b));
    }

    #[test]
    fn test_is_subset_multi_container() {
        let mut a = Bitmap::new();
        let mut b = Bitmap::new();
        a.insert(100);
        a.insert(65536 + 50);
        a.insert(131_072 + 7);

        b.insert(50);
        b.insert(100);
        b.insert(65536 + 50);
        b.insert(65536 + 100);
        b.insert(131_072 + 7);
        b.insert(131_072 + 8);

        assert!(assert_is_subset_matches_reference(&a, &b));
        assert!(!assert_is_subset_matches_reference(&b, &a));
    }

    #[test]
    fn test_is_subset_cardinality_short_circuit() {
        // |a| > |b| means a can't be subset; should return false without checking values.
        let a = Bitmap::from_iter([1, 2, 3, 4]);
        let b = Bitmap::from_iter([1, 2]);
        assert!(!assert_is_subset_matches_reference(&a, &b));
    }

    // ---- intersects ----

    #[test]
    fn test_intersects_overlap() {
        let a = Bitmap::from_iter([1, 2, 3]);
        let b = Bitmap::from_iter([3, 4, 5]);
        assert!(assert_intersects_matches_reference(&a, &b));
        assert!(assert_intersects_matches_reference(&b, &a));
    }

    #[test]
    fn test_intersects_disjoint() {
        let a = Bitmap::from_iter([1, 2, 3]);
        let b = Bitmap::from_iter([4, 5, 6]);
        assert!(!assert_intersects_matches_reference(&a, &b));
        assert!(!assert_intersects_matches_reference(&b, &a));
    }

    #[test]
    fn test_intersects_one_empty() {
        let a = Bitmap::new();
        let b = Bitmap::from_iter([1, 2, 3]);
        assert!(!assert_intersects_matches_reference(&a, &b));
        assert!(!assert_intersects_matches_reference(&b, &a));
    }

    #[test]
    fn test_intersects_both_empty() {
        let a = Bitmap::new();
        let b = Bitmap::new();
        assert!(!assert_intersects_matches_reference(&a, &b));
    }

    #[test]
    fn test_intersects_self() {
        let a = Bitmap::from_iter([1, 2, 3]);
        assert!(assert_intersects_matches_reference(&a, &a));
    }

    #[test]
    fn test_intersects_multi_container_only_in_second() {
        // Containers 0 are disjoint, but container 1 has an overlap.
        let mut a = Bitmap::new();
        let mut b = Bitmap::new();
        a.insert(100);
        a.insert(65536 + 50);
        b.insert(200);
        b.insert(65536 + 50); // overlap here

        assert!(assert_intersects_matches_reference(&a, &b));
        assert!(assert_intersects_matches_reference(&b, &a));
    }

    #[test]
    fn test_intersects_multi_container_no_overlap() {
        // Same container keys but no shared values.
        let mut a = Bitmap::new();
        let mut b = Bitmap::new();
        a.insert(100);
        a.insert(65536 + 50);
        b.insert(200);
        b.insert(65536 + 99);

        assert!(!assert_intersects_matches_reference(&a, &b));
        assert!(!assert_intersects_matches_reference(&b, &a));
    }

    #[test]
    fn test_intersects_disjoint_keys() {
        // No container keys in common.
        let mut a = Bitmap::new();
        let mut b = Bitmap::new();
        a.insert(100);
        b.insert(65536 + 50);
        assert!(!assert_intersects_matches_reference(&a, &b));
    }

    // ---- relationships between ops (sanity checks) ----

    #[test]
    fn test_intersects_iff_intersection_nonempty() {
        // intersects(a, b) <=> !intersection(a, b).is_empty()
        let cases = [
            (vec![1, 2, 3], vec![3, 4, 5]),
            (vec![1, 2, 3], vec![4, 5, 6]),
            (vec![], vec![1, 2, 3]),
            (vec![1, 65536 + 50], vec![100, 65536 + 50]),
            (vec![1, 65536 + 50], vec![100, 65536 + 99]),
        ];
        for (a_vals, b_vals) in cases {
            let a = Bitmap::from_iter(a_vals.iter().copied());
            let b = Bitmap::from_iter(b_vals.iter().copied());
            let inter = assert_intersection_matches_reference(&a, &b, u64::MAX);
            assert_eq!(
                assert_intersects_matches_reference(&a, &b),
                !inter.is_empty(),
                "mismatch for a={a_vals:?} b={b_vals:?}"
            );
        }
    }

    #[test]
    fn test_is_subset_iff_difference_empty() {
        // is_subset(a, b) <=> difference(a, b).is_empty()
        let cases = [
            (vec![1, 2], vec![1, 2, 3]),
            (vec![1, 2, 3], vec![1, 2]),
            (vec![], vec![1, 2, 3]),
            (vec![1, 2, 3], vec![]),
            (vec![1, 65536 + 50], vec![1, 65536 + 50, 131_072]),
        ];
        for (a_vals, b_vals) in cases {
            let a = Bitmap::from_iter(a_vals.iter().copied());
            let b = Bitmap::from_iter(b_vals.iter().copied());
            let diff = assert_difference_matches_reference(&a, &b, u64::MAX);
            assert_eq!(
                assert_is_subset_matches_reference(&a, &b),
                diff.is_empty(),
                "mismatch for a={a_vals:?} b={b_vals:?}"
            );
        }
    }
}
