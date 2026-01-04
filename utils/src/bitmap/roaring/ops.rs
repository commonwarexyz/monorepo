//! Set operations for roaring bitmaps.
//!
//! Provides union, intersection, and difference operations with optional
//! early termination when a result limit is reached.

use super::{
    container::{Bitmap, Container},
    RoaringBitmap,
};
#[cfg(not(feature = "std"))]
use alloc::{collections::BTreeMap, vec::Vec};
#[cfg(feature = "std")]
use std::collections::BTreeMap;

/// Computes the union of two bitmaps, returning at most `limit` values.
///
/// Pass `u64::MAX` for unlimited results.
///
/// Uses early termination: once `limit` values are collected, processing stops.
#[inline]
pub fn union(a: &RoaringBitmap, b: &RoaringBitmap, limit: u64) -> RoaringBitmap {
    if limit == 0 {
        return RoaringBitmap::new();
    }

    let a_containers = a.containers();
    let b_containers = b.containers();

    // Fast path: single container with same key (common case)
    if a_containers.len() == 1 && b_containers.len() == 1 {
        let (&a_key, a_container) = a_containers.first_key_value().unwrap();
        let (&b_key, b_container) = b_containers.first_key_value().unwrap();
        if a_key == b_key {
            let (new_container, _) = union_containers(a_container, b_container, limit);
            return RoaringBitmap::from_single_container(a_key, new_container);
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

    RoaringBitmap::from_containers(result)
}

/// Computes the intersection of two bitmaps, returning at most `limit` values.
///
/// Pass `u64::MAX` for unlimited results.
///
/// Uses early termination: once `limit` values are collected, processing stops.
#[inline]
pub fn intersection(a: &RoaringBitmap, b: &RoaringBitmap, limit: u64) -> RoaringBitmap {
    if limit == 0 {
        return RoaringBitmap::new();
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
                return RoaringBitmap::from_single_container(a_key, new_container);
            }
            return RoaringBitmap::new();
        }
        return RoaringBitmap::new();
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

    RoaringBitmap::from_containers(result)
}

/// Computes the difference (a - b), returning at most `limit` values.
///
/// Pass `u64::MAX` for unlimited results.
///
/// Uses early termination: once `limit` values are collected, processing stops.
#[inline]
pub fn difference(a: &RoaringBitmap, b: &RoaringBitmap, limit: u64) -> RoaringBitmap {
    if limit == 0 {
        return RoaringBitmap::new();
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
                return RoaringBitmap::from_single_container(a_key, new_container);
            }
            return RoaringBitmap::new();
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

    RoaringBitmap::from_containers(result)
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
    // Fast path for array-array union
    if let (Container::Array(a_arr), Container::Array(b_arr)) = (a, b) {
        let (result, count) = a_arr.union(b_arr, limit as usize);
        return (Container::Array(result), count as u64);
    }

    // Fast path for bitmap-bitmap union
    if let (Container::Bitmap(a_bm), Container::Bitmap(b_bm)) = (a, b) {
        let result = Bitmap::or_new(a_bm, b_bm);
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
        let result = Bitmap::and_new(a_bm, b_bm);
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
        let result = Bitmap::and_not_new(a_bm, b_bm);
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

#[cfg(test)]
mod tests {
    use super::*;

    fn bitmap_from_iter(values: impl IntoIterator<Item = u64>) -> RoaringBitmap {
        let mut bitmap = RoaringBitmap::new();
        for v in values {
            bitmap.insert(v);
        }
        bitmap
    }

    #[test]
    fn test_union_basic() {
        let a = bitmap_from_iter([1, 2, 3]);
        let b = bitmap_from_iter([2, 3, 4, 5]);

        let result = union(&a, &b, u64::MAX);
        let values: Vec<_> = result.iter().collect();
        assert_eq!(values, vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_union_with_limit() {
        let a = bitmap_from_iter([1, 2, 3]);
        let b = bitmap_from_iter([4, 5, 6]);

        let result = union(&a, &b, 4);
        assert_eq!(result.len(), 4);
        let values: Vec<_> = result.iter().collect();
        assert_eq!(values, vec![1, 2, 3, 4]);
    }

    #[test]
    fn test_union_empty() {
        let a = RoaringBitmap::new();
        let b = bitmap_from_iter([1, 2, 3]);

        let result = union(&a, &b, u64::MAX);
        let values: Vec<_> = result.iter().collect();
        assert_eq!(values, vec![1, 2, 3]);
    }

    #[test]
    fn test_intersection_basic() {
        let a = bitmap_from_iter([1, 2, 3, 4]);
        let b = bitmap_from_iter([2, 3, 4, 5]);

        let result = intersection(&a, &b, u64::MAX);
        let values: Vec<_> = result.iter().collect();
        assert_eq!(values, vec![2, 3, 4]);
    }

    #[test]
    fn test_intersection_with_limit() {
        let a = bitmap_from_iter([1, 2, 3, 4, 5]);
        let b = bitmap_from_iter([1, 2, 3, 4, 5]);

        let result = intersection(&a, &b, 3);
        assert_eq!(result.len(), 3);
        let values: Vec<_> = result.iter().collect();
        assert_eq!(values, vec![1, 2, 3]);
    }

    #[test]
    fn test_intersection_disjoint() {
        let a = bitmap_from_iter([1, 2, 3]);
        let b = bitmap_from_iter([4, 5, 6]);

        let result = intersection(&a, &b, u64::MAX);
        assert!(result.is_empty());
    }

    #[test]
    fn test_difference_basic() {
        let a = bitmap_from_iter([1, 2, 3, 4]);
        let b = bitmap_from_iter([2, 3]);

        let result = difference(&a, &b, u64::MAX);
        let values: Vec<_> = result.iter().collect();
        assert_eq!(values, vec![1, 4]);
    }

    #[test]
    fn test_difference_with_limit() {
        let a = bitmap_from_iter([1, 2, 3, 4, 5]);
        let b = bitmap_from_iter([2, 4]);

        let result = difference(&a, &b, 2);
        assert_eq!(result.len(), 2);
        let values: Vec<_> = result.iter().collect();
        assert_eq!(values, vec![1, 3]);
    }

    #[test]
    fn test_difference_all_removed() {
        let a = bitmap_from_iter([1, 2, 3]);
        let b = bitmap_from_iter([1, 2, 3, 4, 5]);

        let result = difference(&a, &b, u64::MAX);
        assert!(result.is_empty());
    }

    #[test]
    fn test_union_multiple_containers() {
        let mut a = RoaringBitmap::new();
        let mut b = RoaringBitmap::new();

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
        let mut a = RoaringBitmap::new();
        let mut b = RoaringBitmap::new();

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
        let a = bitmap_from_iter([1, 2, 3]);
        let b = bitmap_from_iter([2, 3, 4]);

        assert!(union(&a, &b, 0).is_empty());
        assert!(intersection(&a, &b, 0).is_empty());
        assert!(difference(&a, &b, 0).is_empty());
    }
}
