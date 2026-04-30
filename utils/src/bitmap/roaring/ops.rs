//! Set operations for roaring bitmaps.
//!
//! Provides union, intersection, and difference operations with optional early termination
//! when a result limit is reached, along with the boolean predicates `is_subset` and
//! `intersects` which short-circuit on first conclusive observation.

use super::{
    container::{self, Container},
    Bitmap,
};
#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, collections::BTreeMap};
#[cfg(feature = "std")]
use std::collections::BTreeMap;

/// Computes the union of two bitmaps, returning at most `limit` values.
///
/// Pass `u64::MAX` for unlimited results.
///
/// Uses early termination: once `limit` values are collected, processing stops.
#[inline]
pub fn union(a: &Bitmap, b: &Bitmap, limit: u64) -> Bitmap {
    if limit == 0 {
        return Bitmap::new();
    }

    let a_containers = a.containers();
    let b_containers = b.containers();

    // Fast path: single container with same key (common case)
    if a_containers.len() == 1 && b_containers.len() == 1 {
        let (&a_key, a_container) = a_containers.first_key_value().unwrap();
        let (&b_key, b_container) = b_containers.first_key_value().unwrap();
        if a_key == b_key {
            let (new_container, _) = union_containers(a_container, b_container, limit);
            return Bitmap::from_single_container(a_key, new_container);
        }
    }

    let mut result = BTreeMap::new();
    let mut count = 0u64;

    let mut a_iter = a_containers.iter().peekable();
    let mut b_iter = b_containers.iter().peekable();

    while count < limit {
        match (a_iter.peek(), b_iter.peek()) {
            (Some((&a_key, _)), Some((&b_key, _))) => {
                if a_key < b_key {
                    let (key, container) = a_iter.next().unwrap();
                    let (new_container, new_count) =
                        copy_container_with_limit(container, limit - count);
                    if new_count > 0 {
                        result.insert(*key, new_container);
                        count += new_count;
                    }
                } else if b_key < a_key {
                    let (key, container) = b_iter.next().unwrap();
                    let (new_container, new_count) =
                        copy_container_with_limit(container, limit - count);
                    if new_count > 0 {
                        result.insert(*key, new_container);
                        count += new_count;
                    }
                } else {
                    // Keys are equal - union the containers
                    let (key, a_container) = a_iter.next().unwrap();
                    let (_, b_container) = b_iter.next().unwrap();
                    let (new_container, new_count) =
                        union_containers(a_container, b_container, limit - count);
                    if new_count > 0 {
                        result.insert(*key, new_container);
                        count += new_count;
                    }
                }
            }
            (Some(_), None) => {
                let (key, container) = a_iter.next().unwrap();
                let (new_container, new_count) =
                    copy_container_with_limit(container, limit - count);
                if new_count > 0 {
                    result.insert(*key, new_container);
                    count += new_count;
                }
            }
            (None, Some(_)) => {
                let (key, container) = b_iter.next().unwrap();
                let (new_container, new_count) =
                    copy_container_with_limit(container, limit - count);
                if new_count > 0 {
                    result.insert(*key, new_container);
                    count += new_count;
                }
            }
            (None, None) => break,
        }
    }

    Bitmap::from(result)
}

/// Computes the intersection of two bitmaps, returning at most `limit` values.
///
/// Pass `u64::MAX` for unlimited results.
///
/// Uses early termination: once `limit` values are collected, processing stops.
#[inline]
pub fn intersection(a: &Bitmap, b: &Bitmap, limit: u64) -> Bitmap {
    if limit == 0 {
        return Bitmap::new();
    }

    let a_containers = a.containers();
    let b_containers = b.containers();

    // Fast path: single container with same key (common case)
    if a_containers.len() == 1 && b_containers.len() == 1 {
        let (&a_key, a_container) = a_containers.first_key_value().unwrap();
        let (&b_key, b_container) = b_containers.first_key_value().unwrap();
        if a_key == b_key {
            let (new_container, count) = intersect_containers(a_container, b_container, limit);
            if count > 0 {
                return Bitmap::from_single_container(a_key, new_container);
            }
            return Bitmap::new();
        }
        return Bitmap::new();
    }

    let mut result = BTreeMap::new();
    let mut count = 0u64;

    // Only process keys that exist in both
    for (&key, a_container) in a_containers.iter() {
        if count >= limit {
            break;
        }

        if let Some(b_container) = b_containers.get(&key) {
            let (new_container, new_count) =
                intersect_containers(a_container, b_container, limit - count);
            if new_count > 0 {
                result.insert(key, new_container);
                count += new_count;
            }
        }
    }

    Bitmap::from(result)
}

/// Computes the difference (a - b), returning at most `limit` values.
///
/// Pass `u64::MAX` for unlimited results.
///
/// Uses early termination: once `limit` values are collected, processing stops.
#[inline]
pub fn difference(a: &Bitmap, b: &Bitmap, limit: u64) -> Bitmap {
    if limit == 0 {
        return Bitmap::new();
    }

    let a_containers = a.containers();
    let b_containers = b.containers();

    // Fast path: single container with same key (common case)
    if a_containers.len() == 1 && b_containers.len() == 1 {
        let (&a_key, a_container) = a_containers.first_key_value().unwrap();
        let (&b_key, b_container) = b_containers.first_key_value().unwrap();
        if a_key == b_key {
            let (new_container, count) = diff_containers(a_container, b_container, limit);
            if count > 0 {
                return Bitmap::from_single_container(a_key, new_container);
            }
            return Bitmap::new();
        }
    }

    let mut result = BTreeMap::new();
    let mut count = 0u64;

    for (&key, a_container) in a_containers.iter() {
        if count >= limit {
            break;
        }

        let (new_container, new_count) = b_containers.get(&key).map_or_else(
            || copy_container_with_limit(a_container, limit - count),
            |b_container| diff_containers(a_container, b_container, limit - count),
        );

        if new_count > 0 {
            result.insert(key, new_container);
            count += new_count;
        }
    }

    Bitmap::from(result)
}

/// Returns `true` if every value in `a` is also in `b` (i.e. `a ⊆ b`).
///
/// Short-circuits on the first value in `a` not present in `b`. Trivially `true` if `a`
/// is empty.
#[inline]
pub fn is_subset(a: &Bitmap, b: &Bitmap) -> bool {
    let a_containers = a.containers();
    let b_containers = b.containers();

    // Cardinality check: |a| > |b| can't be a subset.
    if a.len() > b.len() {
        return false;
    }

    for (&key, a_container) in a_containers.iter() {
        match b_containers.get(&key) {
            None => return false,
            Some(b_container) => {
                if !container_is_subset(a_container, b_container) {
                    return false;
                }
            }
        }
    }
    true
}

/// Returns `true` if `a` and `b` share at least one value.
///
/// Short-circuits on the first common value found. Trivially `false` if either bitmap is
/// empty.
#[inline]
pub fn intersects(a: &Bitmap, b: &Bitmap) -> bool {
    let a_containers = a.containers();
    let b_containers = b.containers();

    // Iterate the side with fewer container entries to minimize hash lookups.
    let (smaller, larger) = if a_containers.len() <= b_containers.len() {
        (a_containers, b_containers)
    } else {
        (b_containers, a_containers)
    };

    for (&key, smaller_container) in smaller.iter() {
        if let Some(larger_container) = larger.get(&key) {
            if containers_intersect(smaller_container, larger_container) {
                return true;
            }
        }
    }
    false
}

/// Copies a container, limiting the number of values.
#[inline]
fn copy_container_with_limit(container: &Container, limit: u64) -> (Container, u64) {
    let len = container.len() as u64;
    if len <= limit {
        return (container.clone(), len);
    }

    // Need to limit - iterate and collect
    let mut new_container = Container::new();
    let mut count = 0u64;
    for value in container.iter() {
        if count >= limit {
            break;
        }
        new_container.insert(value);
        count += 1;
    }
    (new_container, count)
}

/// Computes the union of two containers, limiting the number of values.
#[inline]
fn union_containers(a: &Container, b: &Container, limit: u64) -> (Container, u64) {
    // Fast path for array-array union.
    if let (Container::Array(a_arr), Container::Array(b_arr)) = (a, b) {
        let (result, count) = a_arr.union(b_arr, limit as usize);
        if result.len() > container::array::MAX_CARDINALITY {
            let bm = container::Bitmap::from(&result);
            return (Container::Bitmap(Box::new(bm)), count as u64);
        }
        return (Container::Array(result), count as u64);
    }

    // Fast path for bitmap-bitmap union
    if let (Container::Bitmap(a_bm), Container::Bitmap(b_bm)) = (a, b) {
        let result = container::Bitmap::or_new(a_bm, b_bm);
        let len = result.len() as u64;
        if len <= limit {
            return (Container::Bitmap(Box::new(result)), len);
        }
        return copy_container_with_limit(&Container::Bitmap(Box::new(result)), limit);
    }

    // General case: iterate both in sorted order
    let mut result = Container::new();
    let mut count = 0u64;

    let mut a_iter = a.iter().peekable();
    let mut b_iter = b.iter().peekable();

    while count < limit {
        match (a_iter.peek(), b_iter.peek()) {
            (Some(&a_val), Some(&b_val)) => {
                if a_val < b_val {
                    result.insert(a_val);
                    a_iter.next();
                } else if b_val < a_val {
                    result.insert(b_val);
                    b_iter.next();
                } else {
                    result.insert(a_val);
                    a_iter.next();
                    b_iter.next();
                }
                count += 1;
            }
            (Some(&val), None) => {
                result.insert(val);
                a_iter.next();
                count += 1;
            }
            (None, Some(&val)) => {
                result.insert(val);
                b_iter.next();
                count += 1;
            }
            (None, None) => break,
        }
    }

    (result, count)
}

/// Computes the intersection of two containers, limiting the number of values.
#[inline]
fn intersect_containers(a: &Container, b: &Container, limit: u64) -> (Container, u64) {
    // Fast path for array-array intersection
    if let (Container::Array(a_arr), Container::Array(b_arr)) = (a, b) {
        let (result, count) = a_arr.intersection(b_arr, limit as usize);
        return (Container::Array(result), count as u64);
    }

    // Fast path for bitmap-bitmap intersection
    if let (Container::Bitmap(a_bm), Container::Bitmap(b_bm)) = (a, b) {
        let result = container::Bitmap::and_new(a_bm, b_bm);
        let len = result.len() as u64;
        if len <= limit {
            return (Container::Bitmap(Box::new(result)), len);
        }
        return copy_container_with_limit(&Container::Bitmap(Box::new(result)), limit);
    }

    // Optimization: iterate over the smaller container
    let (smaller, larger) = if a.len() <= b.len() { (a, b) } else { (b, a) };

    let mut result = Container::new();
    let mut count = 0u64;

    for value in smaller.iter() {
        if count >= limit {
            break;
        }
        if larger.contains(value) {
            result.insert(value);
            count += 1;
        }
    }

    (result, count)
}

/// Computes the difference of two containers (a - b), limiting the number of values.
#[inline]
fn diff_containers(a: &Container, b: &Container, limit: u64) -> (Container, u64) {
    // Fast path for array-array difference
    if let (Container::Array(a_arr), Container::Array(b_arr)) = (a, b) {
        let (result, count) = a_arr.difference(b_arr, limit as usize);
        return (Container::Array(result), count as u64);
    }

    // Fast path for bitmap-bitmap difference
    if let (Container::Bitmap(a_bm), Container::Bitmap(b_bm)) = (a, b) {
        let result = container::Bitmap::and_not_new(a_bm, b_bm);
        let len = result.len() as u64;
        if len <= limit {
            return (Container::Bitmap(Box::new(result)), len);
        }
        return copy_container_with_limit(&Container::Bitmap(Box::new(result)), limit);
    }

    // General case
    let mut result = Container::new();
    let mut count = 0u64;

    for value in a.iter() {
        if count >= limit {
            break;
        }
        if !b.contains(value) {
            result.insert(value);
            count += 1;
        }
    }

    (result, count)
}

/// Returns `true` if every value in `a` is also in `b`.
///
/// Short-circuits on the first miss.
#[inline]
fn container_is_subset(a: &Container, b: &Container) -> bool {
    if a.len() > b.len() {
        return false;
    }
    for value in a.iter() {
        if !b.contains(value) {
            return false;
        }
    }
    true
}

/// Returns `true` if `a` and `b` share at least one value.
///
/// Iterates the smaller container and short-circuits on first hit.
#[inline]
fn containers_intersect(a: &Container, b: &Container) -> bool {
    let (smaller, larger) = if a.len() <= b.len() { (a, b) } else { (b, a) };
    for value in smaller.iter() {
        if larger.contains(value) {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_union_basic() {
        let a = Bitmap::from_iter([1, 2, 3]);
        let b = Bitmap::from_iter([2, 3, 4, 5]);

        let result = union(&a, &b, u64::MAX);
        let values: Vec<_> = result.iter().collect();
        assert_eq!(values, vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_union_with_limit() {
        let a = Bitmap::from_iter([1, 2, 3]);
        let b = Bitmap::from_iter([4, 5, 6]);

        let result = union(&a, &b, 4);
        assert_eq!(result.len(), 4);
        let values: Vec<_> = result.iter().collect();
        assert_eq!(values, vec![1, 2, 3, 4]);
    }

    #[test]
    fn test_union_empty() {
        let a = Bitmap::new();
        let b = Bitmap::from_iter([1, 2, 3]);

        let result = union(&a, &b, u64::MAX);
        let values: Vec<_> = result.iter().collect();
        assert_eq!(values, vec![1, 2, 3]);
    }

    #[test]
    fn test_union_a_key_less_than_b() {
        // a's container at key 0, b's at key 1. Exercises the `a_key < b_key` branch
        // in `union` for a's container, then the trailing `(None, Some)` branch picks
        // up b's container.
        let a = Bitmap::from_iter([1, 2, 3]);
        let b = Bitmap::from_iter([65_536, 65_537, 65_538]);
        let result = union(&a, &b, u64::MAX);
        let values: Vec<_> = result.iter().collect();
        assert_eq!(values, vec![1, 2, 3, 65_536, 65_537, 65_538]);
    }

    #[test]
    fn test_union_b_key_less_than_a() {
        // a's container at key 1, b's at key 0. Exercises the `b_key < a_key` branch.
        let a = Bitmap::from_iter([65_536, 65_537, 65_538]);
        let b = Bitmap::from_iter([1, 2, 3]);
        let result = union(&a, &b, u64::MAX);
        let values: Vec<_> = result.iter().collect();
        assert_eq!(values, vec![1, 2, 3, 65_536, 65_537, 65_538]);
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

        let result = union(&a, &b, u64::MAX);
        assert_eq!(result.container_count(), 4);
        let values: Vec<_> = result.iter().collect();
        assert_eq!(
            values,
            vec![10, 65_536 + 20, 2 * 65_536 + 10, 3 * 65_536 + 20]
        );
    }

    #[test]
    fn test_union_disjoint_keys_with_limit() {
        // Disjoint containers + limit smaller than a's container. Exercises the
        // `a_key < b_key` branch through `copy_container_with_limit` truncation.
        let a = Bitmap::from_iter([1, 2, 3]);
        let b = Bitmap::from_iter([65_536, 65_537, 65_538]);
        let result = union(&a, &b, 2);
        assert_eq!(result.len(), 2);
        let values: Vec<_> = result.iter().collect();
        assert_eq!(values, vec![1, 2]);
    }

    #[test]
    fn test_union_containers_array_array_promotes_to_bitmap_when_oversized() {
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

        let result = union(&a, &b, u64::MAX);
        assert_eq!(result.len(), 8000);

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
    fn test_union_containers_bitmap_bitmap_fast_path() {
        // Both containers in `Bitmap` variant at the same key. Exercises the
        // bitmap-bitmap fast path in `union_containers` (`Bitmap::or_new`).
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

        let result = union(&a, &b, u64::MAX);
        // Expected: every integer in [0, 8194).
        assert_eq!(result.len(), 8194);
        for i in 0..8194 {
            assert!(result.contains(i));
        }
    }

    #[test]
    fn test_union_containers_bitmap_bitmap_limit_truncates() {
        // Same setup as above but with a small limit, forcing the bitmap-bitmap fast
        // path through `copy_container_with_limit` after the OR is computed.
        let mut a = Bitmap::new();
        let mut b = Bitmap::new();
        for i in 0..4097u64 {
            a.insert(i * 2);
            b.insert(i * 2 + 1);
        }

        let result = union(&a, &b, 100);
        assert_eq!(result.len(), 100);
        let values: Vec<_> = result.iter().collect();
        assert_eq!(values, (0u64..100).collect::<Vec<_>>());
    }

    #[test]
    fn test_union_containers_mixed_variants_general_path() {
        // a's container is `Array`, b's is `Bitmap`, both at key 0. Neither fast path
        // applies, so `union_containers` falls through to the general iterator-merge
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

        let result = union(&a, &b, u64::MAX);
        // 3 from a + 4097 from b, no overlap.
        assert_eq!(result.len(), 4100);
        assert!(result.contains(1));
        assert!(result.contains(50));
        assert!(result.contains(100));
        assert!(result.contains(200));
        assert!(result.contains(8392));
    }

    #[test]
    fn test_intersection_basic() {
        let a = Bitmap::from_iter([1, 2, 3, 4]);
        let b = Bitmap::from_iter([2, 3, 4, 5]);

        let result = intersection(&a, &b, u64::MAX);
        let values: Vec<_> = result.iter().collect();
        assert_eq!(values, vec![2, 3, 4]);
    }

    #[test]
    fn test_intersection_with_limit() {
        let a = Bitmap::from_iter([1, 2, 3, 4, 5]);
        let b = Bitmap::from_iter([1, 2, 3, 4, 5]);

        let result = intersection(&a, &b, 3);
        assert_eq!(result.len(), 3);
        let values: Vec<_> = result.iter().collect();
        assert_eq!(values, vec![1, 2, 3]);
    }

    #[test]
    fn test_intersection_disjoint() {
        let a = Bitmap::from_iter([1, 2, 3]);
        let b = Bitmap::from_iter([4, 5, 6]);

        let result = intersection(&a, &b, u64::MAX);
        assert!(result.is_empty());
    }

    #[test]
    fn test_intersection_containers_bitmap_bitmap_fast_path() {
        // Both containers in `Bitmap` variant at the same key. Exercises the
        // bitmap-bitmap fast path in `intersect_containers` (`Bitmap::and_new`).
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

        let result = intersection(&a, &b, u64::MAX);
        // Multiples of 4 from 0 through 8192, inclusive: 0, 4, ..., 8192.
        let expected_count = (8192 / 4) + 1; // 2049
        assert_eq!(result.len(), expected_count as u64);
        assert!(result.contains(0));
        assert!(result.contains(4));
        assert!(result.contains(8192));
        assert!(!result.contains(2));
    }

    #[test]
    fn test_intersection_containers_bitmap_bitmap_limit_truncates() {
        // Same setup as above but a small limit forces the bitmap-bitmap fast path
        // through `copy_container_with_limit` after `Bitmap::and_new` is computed.
        let mut a = Bitmap::new();
        let mut b = Bitmap::new();
        for i in 0..4097u64 {
            a.insert(i * 2);
            b.insert(i * 4);
        }

        let result = intersection(&a, &b, 50);
        assert_eq!(result.len(), 50);
        // First 50 multiples of 4 starting at 0.
        let values: Vec<_> = result.iter().collect();
        assert_eq!(values, (0u64..50).map(|i| i * 4).collect::<Vec<_>>());
    }

    #[test]
    fn test_intersection_containers_mixed_variants_general_path() {
        // a's container is `Array`, b's is `Bitmap`. Neither fast path applies, so
        // `intersect_containers` falls through to the general "iterate smaller"
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

        let result = intersection(&a, &b, u64::MAX);
        // a ∩ b: only 200 is in both.
        assert_eq!(result.len(), 1);
        assert!(result.contains(200));
    }

    #[test]
    fn test_difference_basic() {
        let a = Bitmap::from_iter([1, 2, 3, 4]);
        let b = Bitmap::from_iter([2, 3]);

        let result = difference(&a, &b, u64::MAX);
        let values: Vec<_> = result.iter().collect();
        assert_eq!(values, vec![1, 4]);
    }

    #[test]
    fn test_difference_with_limit() {
        let a = Bitmap::from_iter([1, 2, 3, 4, 5]);
        let b = Bitmap::from_iter([2, 4]);

        let result = difference(&a, &b, 2);
        assert_eq!(result.len(), 2);
        let values: Vec<_> = result.iter().collect();
        assert_eq!(values, vec![1, 3]);
    }

    #[test]
    fn test_difference_all_removed() {
        let a = Bitmap::from_iter([1, 2, 3]);
        let b = Bitmap::from_iter([1, 2, 3, 4, 5]);

        let result = difference(&a, &b, u64::MAX);
        assert!(result.is_empty());
    }

    #[test]
    fn test_diff_containers_bitmap_bitmap_fast_path() {
        // Both containers in `Bitmap` variant at the same key. Exercises the
        // bitmap-bitmap fast path in `diff_containers` (`Bitmap::and_not_new`).
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

        let result = difference(&a, &b, u64::MAX);
        assert_eq!(result.len(), 2048);
        assert!(result.contains(2));
        assert!(result.contains(6));
        assert!(result.contains(8190));
        assert!(!result.contains(0)); // in b
        assert!(!result.contains(4)); // in b
    }

    #[test]
    fn test_diff_containers_bitmap_bitmap_limit_truncates() {
        // Same setup but a small limit forces the fast path through
        // `copy_container_with_limit` after `Bitmap::and_not_new` is computed.
        let mut a = Bitmap::new();
        let mut b = Bitmap::new();
        for i in 0..4097u64 {
            a.insert(i * 2);
            b.insert(i * 4);
        }

        let result = difference(&a, &b, 30);
        assert_eq!(result.len(), 30);
        // First 30 values of {2, 6, 10, ...}: 2 + 4k for k in 0..30 → up to 118.
        let values: Vec<_> = result.iter().collect();
        assert_eq!(values, (0u64..30).map(|k| 2 + 4 * k).collect::<Vec<_>>());
    }

    #[test]
    fn test_diff_containers_mixed_variants_general_path() {
        // a's container is `Array`, b's is `Bitmap`. Neither fast path applies, so
        // `diff_containers` falls through to the general "iterate a, skip values in b"
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

        let result = difference(&a, &b, u64::MAX);
        // a − b: 200 is in b, so {1, 50} remain.
        assert_eq!(result.len(), 2);
        assert!(result.contains(1));
        assert!(result.contains(50));
        assert!(!result.contains(200));
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

        let result = union(&a, &b, u64::MAX);
        assert_eq!(result.len(), 4);
        assert!(result.contains(100));
        assert!(result.contains(200));
        assert!(result.contains(65536 + 100));
        assert!(result.contains(65536 + 200));
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

        let result = intersection(&a, &b, u64::MAX);
        assert_eq!(result.len(), 2);
        assert!(result.contains(200));
        assert!(result.contains(65536 + 100));
    }

    #[test]
    fn test_operations_with_zero_limit() {
        let a = Bitmap::from_iter([1, 2, 3]);
        let b = Bitmap::from_iter([2, 3, 4]);

        assert!(union(&a, &b, 0).is_empty());
        assert!(intersection(&a, &b, 0).is_empty());
        assert!(difference(&a, &b, 0).is_empty());
    }

    // ---- is_subset ----

    #[test]
    fn test_is_subset_proper() {
        let a = Bitmap::from_iter([1, 2, 3]);
        let b = Bitmap::from_iter([1, 2, 3, 4, 5]);
        assert!(is_subset(&a, &b));
        assert!(!is_subset(&b, &a));
    }

    #[test]
    fn test_is_subset_equal() {
        let a = Bitmap::from_iter([1, 2, 3]);
        let b = Bitmap::from_iter([1, 2, 3]);
        assert!(is_subset(&a, &b));
        assert!(is_subset(&b, &a));
    }

    #[test]
    fn test_is_subset_empty() {
        let empty = Bitmap::new();
        let nonempty = Bitmap::from_iter([1, 2, 3]);
        // Empty is subset of any set, including itself.
        assert!(is_subset(&empty, &nonempty));
        assert!(is_subset(&empty, &empty));
        // Non-empty is not a subset of empty.
        assert!(!is_subset(&nonempty, &empty));
    }

    #[test]
    fn test_is_subset_missing_value_same_container() {
        let a = Bitmap::from_iter([1, 2, 3]);
        let b = Bitmap::from_iter([1, 3]); // missing 2
        assert!(!is_subset(&a, &b));
    }

    #[test]
    fn test_is_subset_missing_container() {
        // a has values in container 1; b has only container 0.
        let a = Bitmap::from_iter([1, 65536 + 100]);
        let b = Bitmap::from_iter([1, 2, 3]);
        assert!(!is_subset(&a, &b));
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

        assert!(is_subset(&a, &b));
        assert!(!is_subset(&b, &a));
    }

    #[test]
    fn test_is_subset_cardinality_short_circuit() {
        // |a| > |b| means a can't be subset; should return false without checking values.
        let a = Bitmap::from_iter([1, 2, 3, 4]);
        let b = Bitmap::from_iter([1, 2]);
        assert!(!is_subset(&a, &b));
    }

    // ---- intersects ----

    #[test]
    fn test_intersects_overlap() {
        let a = Bitmap::from_iter([1, 2, 3]);
        let b = Bitmap::from_iter([3, 4, 5]);
        assert!(intersects(&a, &b));
        assert!(intersects(&b, &a));
    }

    #[test]
    fn test_intersects_disjoint() {
        let a = Bitmap::from_iter([1, 2, 3]);
        let b = Bitmap::from_iter([4, 5, 6]);
        assert!(!intersects(&a, &b));
        assert!(!intersects(&b, &a));
    }

    #[test]
    fn test_intersects_one_empty() {
        let a = Bitmap::new();
        let b = Bitmap::from_iter([1, 2, 3]);
        assert!(!intersects(&a, &b));
        assert!(!intersects(&b, &a));
    }

    #[test]
    fn test_intersects_both_empty() {
        let a = Bitmap::new();
        let b = Bitmap::new();
        assert!(!intersects(&a, &b));
    }

    #[test]
    fn test_intersects_self() {
        let a = Bitmap::from_iter([1, 2, 3]);
        assert!(intersects(&a, &a));
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

        assert!(intersects(&a, &b));
        assert!(intersects(&b, &a));
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

        assert!(!intersects(&a, &b));
        assert!(!intersects(&b, &a));
    }

    #[test]
    fn test_intersects_disjoint_keys() {
        // No container keys in common.
        let mut a = Bitmap::new();
        let mut b = Bitmap::new();
        a.insert(100);
        b.insert(65536 + 50);
        assert!(!intersects(&a, &b));
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
            let inter = intersection(&a, &b, u64::MAX);
            assert_eq!(
                intersects(&a, &b),
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
            let diff = difference(&a, &b, u64::MAX);
            assert_eq!(
                is_subset(&a, &b),
                diff.is_empty(),
                "mismatch for a={a_vals:?} b={b_vals:?}"
            );
        }
    }
}
