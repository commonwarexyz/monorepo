//! Container types for roaring bitmaps.
//!
//! Each container stores values in the range [0, 65535] using one of three
//! representations optimized for different data densities:
//!
//! - [`Array`]: Sorted array for sparse data (cardinality <= 4096)
//! - [`Bitmap`]: Fixed 8KB bit array for dense data (4096 < cardinality < 65536)
//! - [`Run`]: Run-length encoded for consecutive sequences (cardinality == 65536)
//!
//! Containers automatically convert between types during insertion to maintain
//! optimal memory usage.

pub mod array;
pub mod bitmap;
pub mod run;

#[cfg(not(feature = "std"))]
use alloc::boxed::Box;
pub use array::Array;
pub use bitmap::Bitmap;
use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Error as CodecError, Read, ReadExt, Write};
pub use run::Run;

/// A container that stores u16 values using the most efficient representation.
///
/// Automatically converts between container types during insertion:
/// - Array -> Bitmap when cardinality exceeds 4096
/// - Bitmap -> Run when container becomes fully saturated (65536 values)
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Container {
    /// Sparse container using a sorted array.
    Array(Array),
    /// Dense container using a fixed-size bit array (boxed to reduce enum size).
    Bitmap(Box<Bitmap>),
    /// Run-length encoded container for consecutive sequences.
    Run(Run),
}

impl Default for Container {
    fn default() -> Self {
        Self::Array(Array::new())
    }
}

impl Container {
    /// Creates a new empty container (as an Array).
    #[inline]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the cardinality (number of values) in the container.
    pub fn len(&self) -> u32 {
        match self {
            Self::Array(a) => a.len() as u32,
            Self::Bitmap(b) => b.len(),
            Self::Run(r) => r.len(),
        }
    }

    /// Returns whether the container is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        match self {
            Self::Array(a) => a.is_empty(),
            Self::Bitmap(b) => b.is_empty(),
            Self::Run(r) => r.is_empty(),
        }
    }

    /// Checks if the container contains the given value.
    #[inline]
    pub fn contains(&self, value: u16) -> bool {
        match self {
            Self::Array(a) => a.contains(value),
            Self::Bitmap(b) => b.contains(value),
            Self::Run(r) => r.contains(value),
        }
    }

    /// Inserts a value into the container.
    ///
    /// Returns `true` if the value was newly inserted, `false` if it already existed.
    ///
    /// Automatically converts the container type if needed:
    /// - Array -> Bitmap when cardinality exceeds 4096
    /// - Bitmap -> Run when container becomes fully saturated
    #[inline]
    pub fn insert(&mut self, value: u16) -> bool {
        match self {
            Self::Array(a) => {
                let inserted = a.insert(value);
                if a.is_full() {
                    self.convert_array_to_bitmap();
                }
                inserted
            }
            Self::Bitmap(b) => {
                let inserted = b.insert(value);
                if b.is_full() {
                    self.convert_bitmap_to_run();
                }
                inserted
            }
            Self::Run(r) => r.insert(value),
        }
    }

    /// Inserts a range of values [start, end) into the container.
    ///
    /// Returns the number of values newly inserted.
    ///
    /// Automatically converts the container type if needed.
    #[inline]
    pub fn insert_range(&mut self, start: u16, end: u16) -> u32 {
        if start >= end {
            return 0;
        }

        match self {
            Self::Array(a) => {
                let range_len = (end - start) as usize;

                // Fast path: empty array with consecutive range - use Run container
                // Run stores (start, end) pairs, so a single range is just 4 bytes
                // vs Array which would be 2 bytes per value
                if a.is_empty() && range_len >= 64 {
                    let mut run = Run::new();
                    let inserted = run.insert_range(start, end);
                    *self = Self::Run(run);
                    return inserted;
                }

                // If result would exceed array capacity, convert to bitmap
                if a.len() + range_len > array::MAX_CARDINALITY {
                    self.convert_array_to_bitmap();
                    return self.insert_range(start, end);
                }

                a.insert_range(start, end) as u32
            }
            Self::Bitmap(b) => {
                let inserted = b.insert_range(start, end);
                if b.is_full() {
                    self.convert_bitmap_to_run();
                }
                inserted
            }
            Self::Run(r) => r.insert_range(start, end),
        }
    }

    /// Returns an iterator over the values in sorted order.
    pub fn iter(&self) -> Iter<'_> {
        match self {
            Self::Array(a) => Iter::Array(a.iter()),
            Self::Bitmap(b) => Iter::Bitmap(b.iter()),
            Self::Run(r) => Iter::Run(r.iter()),
        }
    }

    /// Returns the minimum value in the container, if any.
    pub fn min(&self) -> Option<u16> {
        match self {
            Self::Array(a) => a.min(),
            Self::Bitmap(b) => b.min(),
            Self::Run(r) => r.min(),
        }
    }

    /// Returns the maximum value in the container, if any.
    pub fn max(&self) -> Option<u16> {
        match self {
            Self::Array(a) => a.max(),
            Self::Bitmap(b) => b.max(),
            Self::Run(r) => r.max(),
        }
    }

    /// Converts an Array container to a Bitmap container.
    fn convert_array_to_bitmap(&mut self) {
        if let Self::Array(a) = self {
            *self = Self::Bitmap(Box::new(Bitmap::from_array(a)));
        }
    }

    /// Converts a Bitmap container to a Run container.
    fn convert_bitmap_to_run(&mut self) {
        if let Self::Bitmap(b) = self {
            *self = Self::Run(Run::from_bitmap(b));
        }
    }
}

/// Iterator over values in a container.
pub enum Iter<'a> {
    /// Iterator over an Array container.
    Array(core::iter::Copied<core::slice::Iter<'a, u16>>),
    /// Iterator over a Bitmap container.
    Bitmap(bitmap::Iter<'a>),
    /// Iterator over a Run container.
    Run(run::Iter<'a>),
}

impl Iterator for Iter<'_> {
    type Item = u16;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::Array(iter) => iter.next(),
            Self::Bitmap(iter) => iter.next(),
            Self::Run(iter) => iter.next(),
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        match self {
            Self::Array(iter) => iter.size_hint(),
            Self::Bitmap(iter) => iter.size_hint(),
            Self::Run(iter) => iter.size_hint(),
        }
    }
}

impl ExactSizeIterator for Iter<'_> {}

/// Container type tags for serialization.
const CONTAINER_TYPE_ARRAY: u8 = 0;
const CONTAINER_TYPE_BITMAP: u8 = 1;
const CONTAINER_TYPE_RUN: u8 = 2;

impl Write for Container {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::Array(a) => {
                CONTAINER_TYPE_ARRAY.write(buf);
                a.write(buf);
            }
            Self::Bitmap(b) => {
                CONTAINER_TYPE_BITMAP.write(buf);
                b.write(buf);
            }
            Self::Run(r) => {
                CONTAINER_TYPE_RUN.write(buf);
                r.write(buf);
            }
        }
    }
}

impl EncodeSize for Container {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Array(a) => a.encode_size(),
            Self::Bitmap(b) => b.encode_size(),
            Self::Run(r) => r.encode_size(),
        }
    }
}

impl Read for Container {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _cfg: &Self::Cfg) -> Result<Self, CodecError> {
        let container_type = u8::read(buf)?;
        match container_type {
            CONTAINER_TYPE_ARRAY => Ok(Self::Array(Array::read(buf)?)),
            CONTAINER_TYPE_BITMAP => Ok(Self::Bitmap(Box::new(Bitmap::read(buf)?))),
            CONTAINER_TYPE_RUN => Ok(Self::Run(Run::read(buf)?)),
            _ => Err(CodecError::InvalidEnum(container_type)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_container() {
        let container = Container::new();
        assert!(container.is_empty());
        assert_eq!(container.len(), 0);
        assert!(matches!(container, Container::Array(_)));
    }

    #[test]
    fn test_insert_and_contains() {
        let mut container = Container::new();

        assert!(container.insert(5));
        assert!(container.insert(3));
        assert!(container.insert(7));
        assert!(!container.insert(5)); // Duplicate

        assert_eq!(container.len(), 3);
        assert!(container.contains(3));
        assert!(container.contains(5));
        assert!(container.contains(7));
        assert!(!container.contains(4));
    }

    #[test]
    fn test_auto_convert_array_to_bitmap() {
        let mut container = Container::new();

        // Insert values up to the threshold
        for i in 0..=array::MAX_CARDINALITY as u16 {
            container.insert(i);
        }

        // Should have converted to bitmap
        assert!(matches!(container, Container::Bitmap(_)));
        assert_eq!(container.len(), (array::MAX_CARDINALITY + 1) as u32);
    }

    #[test]
    fn test_auto_convert_bitmap_to_run() {
        let mut container = Container::Bitmap(Box::default());

        // Fill the entire container
        for i in 0..=u16::MAX {
            container.insert(i);
        }

        // Should have converted to run
        assert!(matches!(container, Container::Run(_)));
        assert_eq!(container.len(), 65536);
    }

    #[test]
    fn test_insert_range() {
        let mut container = Container::new();

        let inserted = container.insert_range(5, 10);
        assert_eq!(inserted, 5);
        assert_eq!(container.len(), 5);

        let values: Vec<_> = container.iter().collect();
        assert_eq!(values, vec![5, 6, 7, 8, 9]);
    }

    #[test]
    fn test_iterator() {
        let mut container = Container::new();
        container.insert(10);
        container.insert(5);
        container.insert(15);

        let values: Vec<_> = container.iter().collect();
        assert_eq!(values, vec![5, 10, 15]);
    }

    #[test]
    fn test_min_max() {
        let mut container = Container::new();
        assert_eq!(container.min(), None);
        assert_eq!(container.max(), None);

        container.insert(50);
        container.insert(10);
        container.insert(100);

        assert_eq!(container.min(), Some(10));
        assert_eq!(container.max(), Some(100));
    }
}
