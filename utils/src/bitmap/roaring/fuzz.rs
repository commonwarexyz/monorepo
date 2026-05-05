//! Property-style fuzz harness for roaring bitmaps.
//!
//! Defines a [`Plan`] enum whose variants describe the scenarios we want to drive
//! random inputs through, plus a [`Plan::run`] body that asserts the relevant
//! invariants for each scenario. The same [`Plan`] is consumed by both:
//!
//! - The in-process `minifuzz` harness via a `#[test]` entry point at the bottom of
//!   this file, which runs as part of `cargo test` and exercises hundreds-to-thousands
//!   of random plans per invocation.
//! - The external `cargo-fuzz` target at `utils/fuzz/fuzz_targets/roaring.rs`, which
//!   parses a [`Plan`] from raw fuzzer bytes and calls [`Plan::run`] on it.
//!
//! Sharing the harness body means a regression caught by the long-running
//! coverage-guided fuzzer is also catchable by the regular test suite, and a
//! reproduction reported by `minifuzz` (a hex `MINIFUZZ_BRANCH` token) can be
//! replayed deterministically against the same code path.

use super::{super::BitMap, Bitmap, Prunable};
use arbitrary::{Arbitrary, Unstructured};
use bytes::Bytes;
use commonware_codec::{Decode, Encode, EncodeSize, Read, Write};

const MAX_VALUES: usize = 10_000;
const MAX_CONTAINERS: usize = 100;

/// Maximum value that keeps us within `MAX_CONTAINERS` containers. Each container
/// covers 65536 values (2^16), so we cap at `MAX_CONTAINERS * 65536` to prevent
/// pathological inputs (e.g. `u64::MAX`) from blowing up memory at fuzz time.
const MAX_VALUE: u64 = (MAX_CONTAINERS as u64) << 16;

/// A `u64` value constrained to stay within `MAX_CONTAINERS` containers.
#[derive(Debug, Clone, Copy)]
pub struct BoundedU64(u64);

impl<'a> Arbitrary<'a> for BoundedU64 {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let v: u64 = u.arbitrary()?;
        Ok(Self(v % MAX_VALUE))
    }
}

impl From<BoundedU64> for u64 {
    fn from(v: BoundedU64) -> Self {
        v.0
    }
}

/// Operation against a `Bitmap`, used by the `MixedOperations` variant to
/// drive interleaved mutate / query sequences.
#[derive(Arbitrary, Debug)]
pub enum MixedOp {
    Insert(BoundedU64),
    InsertRange { start: BoundedU64, len: u8 },
    Contains(BoundedU64),
}

/// Operation scoped to a single 16-bit shelf (single `Container`). Used by the
/// `ConcentratedShelf` variant to cross the Array->Bitmap and Bitmap↔Run
/// auto-conversion thresholds repeatedly within one container's lifetime.
#[derive(Arbitrary, Debug)]
pub enum ShelfOp {
    Insert(u16),
    InsertRange { start: u16, len: u16 },
}

/// Operation against a `Prunable`. Used by the `PrunableOps` variant.
#[derive(Arbitrary, Debug)]
pub enum PrunableOp {
    Insert(BoundedU64),
    InsertRange { start: BoundedU64, len: u16 },
    PruneBelow(BoundedU64),
}

/// Scenarios driven by random inputs. Each variant's [`Plan::run`] body asserts
/// an invariant that should hold for that operation.
#[derive(Arbitrary, Debug)]
pub enum Plan {
    Insert {
        values: Vec<BoundedU64>,
    },
    InsertRange {
        start: BoundedU64,
        len: u16,
    },
    Contains {
        values: Vec<BoundedU64>,
        query: BoundedU64,
    },
    Codec {
        values: Vec<BoundedU64>,
    },
    CodecRange {
        start: BoundedU64,
        len: u16,
    },
    Union {
        values_a: Vec<BoundedU64>,
        values_b: Vec<BoundedU64>,
        limit: u64,
    },
    Intersection {
        values_a: Vec<BoundedU64>,
        values_b: Vec<BoundedU64>,
        limit: u64,
    },
    Difference {
        values_a: Vec<BoundedU64>,
        values_b: Vec<BoundedU64>,
        limit: u64,
    },
    Iterator {
        values: Vec<BoundedU64>,
    },
    IterRange {
        values: Vec<BoundedU64>,
        start: BoundedU64,
        end: BoundedU64,
    },
    MinMax {
        values: Vec<BoundedU64>,
    },
    MultipleRanges {
        ranges: Vec<(BoundedU64, u16)>,
    },
    MixedOperations {
        ops: Vec<MixedOp>,
    },
    /// Concentrate many inserts inside a single 16-bit shelf so that
    /// Array->Bitmap->Run and Run->Bitmap auto-conversion paths get crossed
    /// repeatedly within one container's lifetime. Codec roundtrip at the end
    /// implicitly verifies `Bitmap::run_count` correctness (decode recomputes
    /// from `words`).
    ConcentratedShelf {
        shelf: u8,
        ops: Vec<ShelfOp>,
    },
    /// Drive a `Prunable` through interleaved inserts and `prune_below` calls.
    /// Inserts are guarded against the panic-on-access-below-watermark
    /// invariant; codec roundtrip implicitly validates that `prune_below`
    /// leaves no straggler containers below the watermark (decode rejects such
    /// states).
    PrunableOps {
        ops: Vec<PrunableOp>,
    },
}

fn build_bitmap(values: &[BoundedU64]) -> Bitmap {
    let mut bitmap = Bitmap::new();
    for v in values.iter().take(MAX_VALUES) {
        bitmap.insert(v.0);
    }
    bitmap
}

fn reference_len(groups: &[&[BoundedU64]]) -> u64 {
    groups
        .iter()
        .flat_map(|values| values.iter().take(MAX_VALUES))
        .map(|value| value.0)
        .max()
        .map_or(0, |value| value + 1)
}

fn set_reference(reference: &mut BitMap, values: &[BoundedU64]) {
    for value in values.iter().take(MAX_VALUES) {
        if value.0 < reference.len() {
            reference.set(value.0, true);
        }
    }
}

fn build_reference(values: &[BoundedU64], len: u64) -> BitMap {
    let mut reference = BitMap::zeroes(len);
    set_reference(&mut reference, values);
    reference
}

fn expected_values(reference: &BitMap, limit: u64) -> Vec<u64> {
    if limit == 0 {
        return Vec::new();
    }

    let mut expected = Vec::new();
    for value in 0..reference.len() {
        if reference.get(value) {
            expected.push(value);
            if expected.len() as u64 == limit {
                break;
            }
        }
    }
    expected
}

fn assert_matches_reference(result: &Bitmap, reference: &BitMap, limit: u64, op: &str) {
    let actual: Vec<_> = result.iter().collect();
    let expected = expected_values(reference, limit);
    assert_eq!(actual, expected, "{op} mismatch");
}

impl Plan {
    pub fn run(self, _u: &mut Unstructured<'_>) -> arbitrary::Result<()> {
        match self {
            Self::Insert { values } => {
                let mut bitmap = Bitmap::new();
                let mut expected_len = 0u64;
                for v in values.iter().take(MAX_VALUES) {
                    let v = v.0;
                    let was_new = bitmap.insert(v);
                    if was_new {
                        expected_len += 1;
                    }
                    assert!(bitmap.contains(v));
                }
                assert_eq!(bitmap.len(), expected_len);
            }

            Self::InsertRange { start, len } => {
                if len == 0 {
                    return Ok(());
                }
                let start = start.0;
                let end = start.saturating_add(len as u64).min(MAX_VALUE);
                let expected_len = end - start;
                if expected_len == 0 {
                    return Ok(());
                }
                let mut bitmap = Bitmap::new();
                let inserted = bitmap.insert_range(start..end);
                assert_eq!(inserted, expected_len);
                assert_eq!(bitmap.len(), expected_len);
                for i in start..end {
                    assert!(bitmap.contains(i), "missing value {}", i);
                }
                if start > 0 {
                    assert!(!bitmap.contains(start - 1));
                }
                if end < MAX_VALUE {
                    assert!(!bitmap.contains(end));
                }
            }

            Self::Contains { values, query } => {
                let bitmap = build_bitmap(&values);
                let query = query.0;
                let expected = values.iter().take(MAX_VALUES).any(|v| v.0 == query);
                assert_eq!(bitmap.contains(query), expected);
            }

            Self::Codec { values } => {
                let bitmap = build_bitmap(&values);
                let encoded_size = bitmap.encode_size();
                assert!(encoded_size > 0 || bitmap.is_empty());

                let mut buf = Vec::new();
                bitmap.write(&mut buf);

                let mut cursor = std::io::Cursor::new(buf.clone());
                let decoded = Bitmap::read_cfg(&mut cursor, &(..=MAX_CONTAINERS).into()).unwrap();
                assert_eq!(bitmap.len(), decoded.len());
                assert_eq!(bitmap, decoded);

                let decoded2 =
                    Bitmap::decode_cfg(Bytes::from(buf), &(..=MAX_CONTAINERS).into()).unwrap();
                assert_eq!(bitmap, decoded2);

                let encoded2 = decoded.encode();
                let encoded1 = bitmap.encode();
                assert_eq!(encoded1, encoded2);
            }

            Self::CodecRange { start, len } => {
                if len == 0 {
                    return Ok(());
                }
                let start = start.0;
                let end = start.saturating_add(len as u64).min(MAX_VALUE);
                if start >= end {
                    return Ok(());
                }
                let mut bitmap = Bitmap::new();
                bitmap.insert_range(start..end);

                let encoded = bitmap.encode();
                let decoded =
                    Bitmap::decode_cfg(encoded.clone(), &(..=MAX_CONTAINERS).into()).unwrap();
                assert_eq!(bitmap.len(), decoded.len());
                assert_eq!(bitmap, decoded);
                for i in start..end {
                    assert!(decoded.contains(i), "decoded missing value {}", i);
                }
                let re_encoded = decoded.encode();
                assert_eq!(encoded, re_encoded);
            }

            Self::Union {
                values_a,
                values_b,
                limit,
            } => {
                let a = build_bitmap(&values_a);
                let b = build_bitmap(&values_b);
                let result = a.union(&b, limit);
                let len = reference_len(&[&values_a, &values_b]);
                let mut reference = build_reference(&values_a, len);
                set_reference(&mut reference, &values_b);
                assert_matches_reference(&result, &reference, limit, "union");

                if limit == u64::MAX {
                    for v in a.iter() {
                        assert!(result.contains(v), "union missing value from a: {}", v);
                    }
                    for v in b.iter() {
                        assert!(result.contains(v), "union missing value from b: {}", v);
                    }
                }
                assert!(result.len() <= limit);

                let values: Vec<_> = result.iter().collect();
                for window in values.windows(2) {
                    assert!(window[0] < window[1], "union not sorted");
                }
            }

            Self::Intersection {
                values_a,
                values_b,
                limit,
            } => {
                let a = build_bitmap(&values_a);
                let b = build_bitmap(&values_b);
                let result = a.intersection(&b, limit);
                let len = reference_len(&[&values_a, &values_b]);
                let b_reference = build_reference(&values_b, len);
                let mut reference = BitMap::zeroes(len);
                for value in values_a.iter().take(MAX_VALUES) {
                    if value.0 < len && b_reference.get(value.0) {
                        reference.set(value.0, true);
                    }
                }
                assert_matches_reference(&result, &reference, limit, "intersection");

                for v in result.iter() {
                    assert!(a.contains(v), "intersection contains value not in a: {}", v);
                    assert!(b.contains(v), "intersection contains value not in b: {}", v);
                }
                assert!(result.len() <= limit);

                let values: Vec<_> = result.iter().collect();
                for window in values.windows(2) {
                    assert!(window[0] < window[1], "intersection not sorted");
                }
            }

            Self::Difference {
                values_a,
                values_b,
                limit,
            } => {
                let a = build_bitmap(&values_a);
                let b = build_bitmap(&values_b);
                let result = a.difference(&b, limit);
                let len = reference_len(&[&values_a, &values_b]);
                let mut reference = build_reference(&values_a, len);
                for value in values_b.iter().take(MAX_VALUES) {
                    if value.0 < len {
                        reference.set(value.0, false);
                    }
                }
                assert_matches_reference(&result, &reference, limit, "difference");

                for v in result.iter() {
                    assert!(a.contains(v), "difference contains value not in a: {}", v);
                    assert!(!b.contains(v), "difference contains value in b: {}", v);
                }
                assert!(result.len() <= limit);

                let values: Vec<_> = result.iter().collect();
                for window in values.windows(2) {
                    assert!(window[0] < window[1], "difference not sorted");
                }
            }

            Self::Iterator { values } => {
                let bitmap = build_bitmap(&values);
                let collected: Vec<_> = bitmap.iter().collect();
                assert_eq!(collected.len() as u64, bitmap.len());
                for window in collected.windows(2) {
                    assert!(window[0] < window[1], "iterator not sorted");
                }
                for &v in &collected {
                    assert!(bitmap.contains(v));
                }
            }

            Self::IterRange { values, start, end } => {
                let start = start.0;
                let end = end.0;
                if start >= end {
                    return Ok(());
                }
                let bitmap = build_bitmap(&values);
                let collected: Vec<_> = bitmap.iter_range(start..end).collect();
                for &v in &collected {
                    assert!(
                        v >= start && v < end,
                        "value {} out of range [{}, {})",
                        v,
                        start,
                        end
                    );
                    assert!(bitmap.contains(v));
                }
                for window in collected.windows(2) {
                    assert!(window[0] < window[1], "iter_range not sorted");
                }
            }

            Self::MinMax { values } => {
                let bitmap = build_bitmap(&values);
                if bitmap.is_empty() {
                    assert_eq!(bitmap.min(), None);
                    assert_eq!(bitmap.max(), None);
                } else {
                    let min = bitmap.min().unwrap();
                    let max = bitmap.max().unwrap();
                    assert!(bitmap.contains(min));
                    assert!(bitmap.contains(max));
                    assert!(min <= max);
                    for v in bitmap.iter() {
                        assert!(v >= min);
                        assert!(v <= max);
                    }
                }
            }

            Self::MultipleRanges { ranges } => {
                let mut bitmap = Bitmap::new();
                for (start, len) in ranges.iter().take(100) {
                    if *len == 0 {
                        continue;
                    }
                    let start = start.0;
                    let end = start.saturating_add(*len as u64).min(MAX_VALUE);
                    if start < end {
                        bitmap.insert_range(start..end);
                    }
                }
                let encoded = bitmap.encode();
                let decoded = Bitmap::decode_cfg(encoded, &(..=MAX_CONTAINERS).into()).unwrap();
                assert_eq!(bitmap.len(), decoded.len());
                assert_eq!(bitmap, decoded);
            }

            Self::MixedOperations { ops } => {
                let mut bitmap = Bitmap::new();
                for op in ops.iter().take(1000) {
                    match op {
                        MixedOp::Insert(v) => {
                            let v = v.0;
                            bitmap.insert(v);
                            assert!(bitmap.contains(v));
                        }
                        MixedOp::InsertRange { start, len } => {
                            if *len > 0 {
                                let start = start.0;
                                let end = start.saturating_add(*len as u64).min(MAX_VALUE);
                                if start < end {
                                    bitmap.insert_range(start..end);
                                }
                            }
                        }
                        MixedOp::Contains(v) => {
                            let _ = bitmap.contains(v.0);
                        }
                    }
                }
                let encoded = bitmap.encode();
                let decoded = Bitmap::decode_cfg(encoded, &(..=MAX_CONTAINERS).into()).unwrap();
                assert_eq!(bitmap.len(), decoded.len());
                assert_eq!(bitmap, decoded);
            }

            Self::ConcentratedShelf { shelf, ops } => {
                let shelf = (shelf as u64) % (MAX_CONTAINERS as u64);
                let base = shelf << 16;

                let mut bitmap = Bitmap::new();
                for op in ops.iter().take(5000) {
                    match op {
                        ShelfOp::Insert(idx) => {
                            bitmap.insert(base + *idx as u64);
                        }
                        ShelfOp::InsertRange { start, len } => {
                            if *len == 0 {
                                continue;
                            }
                            let s = base + *start as u64;
                            let e = (s + *len as u64).min(base + 65536);
                            if s < e {
                                bitmap.insert_range(s..e);
                            }
                        }
                    }
                }

                // Codec roundtrip implicitly validates `Bitmap::run_count`: encode
                // writes only `words`; decode recomputes `run_count` via scan.
                // PartialEq compares run_count, so any drift in incremental tracking
                // surfaces as inequality.
                let encoded = bitmap.encode();
                let decoded = Bitmap::decode_cfg(encoded, &(..=MAX_CONTAINERS).into()).unwrap();
                assert_eq!(bitmap.len(), decoded.len());
                assert_eq!(bitmap, decoded);

                let collected: Vec<_> = bitmap.iter().collect();
                assert_eq!(collected.len() as u64, bitmap.len());
                for window in collected.windows(2) {
                    assert!(window[0] < window[1], "iterator not sorted");
                }
                for &v in &collected {
                    assert!(bitmap.contains(v));
                }
            }

            Self::PrunableOps { ops } => {
                let mut p = Prunable::new();
                for op in ops.iter().take(1000) {
                    match op {
                        PrunableOp::Insert(v) => {
                            let v = u64::from(*v);
                            if v >= p.pruned_below() {
                                p.insert(v);
                            }
                        }
                        PrunableOp::InsertRange { start, len } => {
                            if *len == 0 {
                                continue;
                            }
                            let s = u64::from(*start);
                            let e = s.saturating_add(*len as u64).min(MAX_VALUE);
                            if s >= p.pruned_below() && s < e {
                                p.insert_range(s..e);
                            }
                        }
                        PrunableOp::PruneBelow(threshold) => {
                            p.prune_below(u64::from(*threshold));
                        }
                    }
                }
                assert_eq!(p.pruned_below() % (1 << 16), 0);
                let encoded = p.encode();
                let decoded = Prunable::decode_cfg(encoded, &(..=MAX_CONTAINERS).into()).unwrap();
                assert_eq!(p, decoded);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::Plan;

    #[test]
    fn test_fuzz() {
        commonware_invariants::minifuzz::test(|u| u.arbitrary::<Plan>()?.run(u));
    }
}
