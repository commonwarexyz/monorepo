//! Roaring Bitmap implementation.
//!
//! A roaring bitmap is a compressed bitmap that efficiently stores sets of 64-bit unsigned
//! integers. It divides the 64-bit space into containers of 2^16 integers each, using different
//! storage strategies based on container density:
//!
//! - **Array containers**: For sparse containers (fewer elements), stores the actual u16 values.
//! - **Bitmap containers**: For dense containers (many elements), uses a traditional 8KB bitmap.
//!
//! # Example
//!
//! ```
//! use commonware_utils::bitmap::RoaringBitmap;
//!
//! let mut bitmap = RoaringBitmap::new();
//! bitmap.insert(10);
//! bitmap.insert(1000);
//! bitmap.insert(100_000);
//! bitmap.insert(1_000_000_000_000); // Large u64 value
//!
//! assert!(bitmap.contains(10));
//! assert!(bitmap.contains(1000));
//! assert!(!bitmap.contains(50));
//! assert!(bitmap.contains(1_000_000_000_000));
//!
//! assert_eq!(bitmap.len(), 4);
//! ```

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use bytes::{Buf, BufMut};
use commonware_codec::{util::at_least, EncodeSize, Error as CodecError, Read, ReadExt, Write};
use core::fmt::{self, Formatter};

/// The threshold at which we switch from array to bitmap container.
/// Below this cardinality, an array container is more space-efficient.
/// At or above this cardinality, a bitmap container is more space-efficient.
///
/// Array container size: 2 bytes per element
/// Bitmap container size: 8192 bytes (fixed)
/// Crossover point: 8192 / 2 = 4096 elements
const ARRAY_TO_BITMAP_THRESHOLD: usize = 4096;

/// Size of a bitmap container in bytes (2^16 bits = 8192 bytes).
const BITMAP_CONTAINER_SIZE: usize = 8192;

/// A container that stores a subset of values within a 16-bit range.
#[derive(Clone, PartialEq, Eq, Hash)]
enum Container {
    /// Sorted array of u16 values. Used when cardinality < ARRAY_TO_BITMAP_THRESHOLD.
    Array(Vec<u16>),
    /// Bitmap with 2^16 bits. Used when cardinality >= ARRAY_TO_BITMAP_THRESHOLD.
    Bitmap(Vec<u64>),
}

impl Container {
    /// Creates a new empty array container.
    const fn new_array() -> Self {
        Self::Array(Vec::new())
    }

    /// Returns the number of elements in this container.
    fn len(&self) -> usize {
        match self {
            Self::Array(arr) => arr.len(),
            Self::Bitmap(bits) => bits.iter().map(|w| w.count_ones() as usize).sum(),
        }
    }

    /// Returns true if the container is empty.
    fn is_empty(&self) -> bool {
        match self {
            Self::Array(arr) => arr.is_empty(),
            Self::Bitmap(bits) => bits.iter().all(|&w| w == 0),
        }
    }

    /// Checks if the given value (low 16 bits) is present.
    fn contains(&self, value: u16) -> bool {
        match self {
            Self::Array(arr) => arr.binary_search(&value).is_ok(),
            Self::Bitmap(bits) => {
                let word_idx = value as usize / 64;
                let bit_idx = value as usize % 64;
                (bits[word_idx] & (1u64 << bit_idx)) != 0
            }
        }
    }

    /// Inserts a value (low 16 bits). Returns true if the value was newly inserted.
    fn insert(&mut self, value: u16) -> bool {
        match self {
            Self::Array(arr) => match arr.binary_search(&value) {
                Ok(_) => false, // Already present
                Err(pos) => {
                    arr.insert(pos, value);
                    true
                }
            },
            Self::Bitmap(bits) => {
                let word_idx = value as usize / 64;
                let bit_idx = value as usize % 64;
                let mask = 1u64 << bit_idx;
                let was_set = (bits[word_idx] & mask) != 0;
                bits[word_idx] |= mask;
                !was_set
            }
        }
    }

    /// Removes a value (low 16 bits). Returns true if the value was present.
    fn remove(&mut self, value: u16) -> bool {
        match self {
            Self::Array(arr) => arr.binary_search(&value).is_ok_and(|pos| {
                arr.remove(pos);
                true
            }),
            Self::Bitmap(bits) => {
                let word_idx = value as usize / 64;
                let bit_idx = value as usize % 64;
                let mask = 1u64 << bit_idx;
                let was_set = (bits[word_idx] & mask) != 0;
                bits[word_idx] &= !mask;
                was_set
            }
        }
    }

    /// Converts from array to bitmap if the threshold is exceeded.
    fn maybe_convert_to_bitmap(&mut self) {
        if let Self::Array(arr) = self {
            if arr.len() >= ARRAY_TO_BITMAP_THRESHOLD {
                let mut bits = vec![0u64; BITMAP_CONTAINER_SIZE / 8];
                for &value in arr.iter() {
                    let word_idx = value as usize / 64;
                    let bit_idx = value as usize % 64;
                    bits[word_idx] |= 1u64 << bit_idx;
                }
                *self = Self::Bitmap(bits);
            }
        }
    }

    /// Converts from bitmap to array if cardinality drops below threshold.
    fn maybe_convert_to_array(&mut self) {
        if let Self::Bitmap(bits) = self {
            let cardinality: usize = bits.iter().map(|w| w.count_ones() as usize).sum();
            if cardinality < ARRAY_TO_BITMAP_THRESHOLD {
                let mut arr = Vec::with_capacity(cardinality);
                for (word_idx, &word) in bits.iter().enumerate() {
                    if word == 0 {
                        continue;
                    }
                    for bit_idx in 0..64 {
                        if (word & (1u64 << bit_idx)) != 0 {
                            arr.push((word_idx * 64 + bit_idx) as u16);
                        }
                    }
                }
                *self = Self::Array(arr);
            }
        }
    }

    /// Returns an iterator over all values in this container.
    fn iter(&self) -> ContainerIter<'_> {
        match self {
            Self::Array(arr) => ContainerIter::Array(arr.iter()),
            Self::Bitmap(bits) => ContainerIter::Bitmap {
                bits,
                word_idx: 0,
                bit_idx: 0,
            },
        }
    }
}

/// Iterator over values in a container.
enum ContainerIter<'a> {
    Array(core::slice::Iter<'a, u16>),
    Bitmap {
        bits: &'a [u64],
        word_idx: usize,
        bit_idx: usize,
    },
}

impl Iterator for ContainerIter<'_> {
    type Item = u16;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            ContainerIter::Array(iter) => iter.next().copied(),
            ContainerIter::Bitmap {
                bits,
                word_idx,
                bit_idx,
            } => {
                while *word_idx < bits.len() {
                    while *bit_idx < 64 {
                        let current_bit = *bit_idx;
                        *bit_idx += 1;
                        if (bits[*word_idx] & (1u64 << current_bit)) != 0 {
                            return Some((*word_idx * 64 + current_bit) as u16);
                        }
                    }
                    *word_idx += 1;
                    *bit_idx = 0;
                }
                None
            }
        }
    }
}

impl fmt::Debug for Container {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Array(arr) => write!(f, "Array({} elements)", arr.len()),
            Self::Bitmap(_) => write!(f, "Bitmap({} elements)", self.len()),
        }
    }
}

/// A roaring bitmap for efficiently storing sets of 64-bit unsigned integers.
///
/// Roaring bitmaps partition the 64-bit integer space into containers of 2^16 values.
/// Each container uses either a sorted array (for sparse data) or a bitmap (for dense data)
/// based on the cardinality, ensuring optimal memory usage.
///
/// The high 48 bits of each value determine which container it belongs to, while the
/// low 16 bits determine its position within that container.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct RoaringBitmap {
    /// Containers indexed by the high 48 bits of the values they contain.
    /// Stored as (high_bits, container) pairs, sorted by high_bits.
    containers: Vec<(u64, Container)>,
}

impl RoaringBitmap {
    /// Creates a new empty roaring bitmap.
    pub const fn new() -> Self {
        Self {
            containers: Vec::new(),
        }
    }

    /// Creates a new empty roaring bitmap with the specified capacity.
    ///
    /// The capacity is the expected number of containers, not individual values.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            containers: Vec::with_capacity(capacity),
        }
    }

    /// Returns the number of values in the bitmap.
    pub fn len(&self) -> u64 {
        self.containers.iter().map(|(_, c)| c.len() as u64).sum()
    }

    /// Returns true if the bitmap contains no values.
    pub fn is_empty(&self) -> bool {
        self.containers.iter().all(|(_, c)| c.is_empty())
    }

    /// Returns the number of containers in the bitmap.
    pub const fn num_containers(&self) -> usize {
        self.containers.len()
    }

    /// Splits a 64-bit value into high 48 bits and low 16 bits.
    #[inline]
    const fn split(value: u64) -> (u64, u16) {
        (value >> 16, value as u16)
    }

    /// Combines high 48 bits and low 16 bits into a 64-bit value.
    #[inline]
    const fn combine(high: u64, low: u16) -> u64 {
        (high << 16) | (low as u64)
    }

    /// Finds the container for the given high bits, returning its index.
    fn find_container(&self, high: u64) -> Result<usize, usize> {
        self.containers.binary_search_by_key(&high, |(h, _)| *h)
    }

    /// Checks if the given value is present in the bitmap.
    pub fn contains(&self, value: u64) -> bool {
        let (high, low) = Self::split(value);
        self.find_container(high)
            .is_ok_and(|idx| self.containers[idx].1.contains(low))
    }

    /// Inserts a value into the bitmap. Returns true if the value was newly inserted.
    pub fn insert(&mut self, value: u64) -> bool {
        let (high, low) = Self::split(value);
        match self.find_container(high) {
            Ok(idx) => {
                let inserted = self.containers[idx].1.insert(low);
                if inserted {
                    self.containers[idx].1.maybe_convert_to_bitmap();
                }
                inserted
            }
            Err(idx) => {
                let mut container = Container::new_array();
                container.insert(low);
                self.containers.insert(idx, (high, container));
                true
            }
        }
    }

    /// Removes a value from the bitmap. Returns true if the value was present.
    pub fn remove(&mut self, value: u64) -> bool {
        let (high, low) = Self::split(value);
        match self.find_container(high) {
            Ok(idx) => {
                let removed = self.containers[idx].1.remove(low);
                if removed {
                    if self.containers[idx].1.is_empty() {
                        self.containers.remove(idx);
                    } else {
                        self.containers[idx].1.maybe_convert_to_array();
                    }
                }
                removed
            }
            Err(_) => false,
        }
    }

    /// Clears all values from the bitmap.
    pub fn clear(&mut self) {
        self.containers.clear();
    }

    /// Returns the minimum value in the bitmap, or None if empty.
    pub fn min(&self) -> Option<u64> {
        self.containers.first().and_then(|(high, container)| {
            container.iter().next().map(|low| Self::combine(*high, low))
        })
    }

    /// Returns the maximum value in the bitmap, or None if empty.
    pub fn max(&self) -> Option<u64> {
        self.containers.last().and_then(|(high, container)| {
            let low: Option<u16> = match container {
                Container::Array(arr) => arr.last().copied(),
                Container::Bitmap(bits) => {
                    // Find the last set bit
                    bits.iter()
                        .enumerate()
                        .rev()
                        .find(|(_, &word)| word != 0)
                        .map(|(word_idx, &word)| {
                            let bit_idx = 63 - word.leading_zeros();
                            (word_idx * 64 + bit_idx as usize) as u16
                        })
                }
            };
            low.map(|low| Self::combine(*high, low))
        })
    }

    /// Returns an iterator over all values in the bitmap in ascending order.
    pub fn iter(&self) -> Iter<'_> {
        Iter {
            containers: &self.containers,
            container_idx: 0,
            container_iter: None,
        }
    }

    /// Performs a bitwise AND with another bitmap, modifying self in place.
    pub fn and(&mut self, other: &Self) {
        let mut result = Vec::new();
        let mut self_idx = 0;
        let mut other_idx = 0;

        while self_idx < self.containers.len() && other_idx < other.containers.len() {
            let (self_high, _) = &self.containers[self_idx];
            let (other_high, _) = &other.containers[other_idx];

            match self_high.cmp(other_high) {
                core::cmp::Ordering::Less => {
                    // Container only in self, skip it
                    self_idx += 1;
                }
                core::cmp::Ordering::Greater => {
                    // Container only in other, skip it
                    other_idx += 1;
                }
                core::cmp::Ordering::Equal => {
                    // Container in both, AND them
                    let high = *self_high;
                    let new_container = and_containers(
                        &self.containers[self_idx].1,
                        &other.containers[other_idx].1,
                    );
                    if !new_container.is_empty() {
                        result.push((high, new_container));
                    }
                    self_idx += 1;
                    other_idx += 1;
                }
            }
        }

        self.containers = result;
    }

    /// Performs a bitwise OR with another bitmap, modifying self in place.
    pub fn or(&mut self, other: &Self) {
        let mut result = Vec::new();
        let mut self_idx = 0;
        let mut other_idx = 0;

        while self_idx < self.containers.len() || other_idx < other.containers.len() {
            let self_item = self.containers.get(self_idx);
            let other_item = other.containers.get(other_idx);

            match (self_item, other_item) {
                (Some((self_high, _)), Some((other_high, _))) => match self_high.cmp(other_high) {
                    core::cmp::Ordering::Less => {
                        result.push(self.containers[self_idx].clone());
                        self_idx += 1;
                    }
                    core::cmp::Ordering::Greater => {
                        result.push(other.containers[other_idx].clone());
                        other_idx += 1;
                    }
                    core::cmp::Ordering::Equal => {
                        let high = *self_high;
                        let new_container = or_containers(
                            &self.containers[self_idx].1,
                            &other.containers[other_idx].1,
                        );
                        result.push((high, new_container));
                        self_idx += 1;
                        other_idx += 1;
                    }
                },
                (Some(_), None) => {
                    result.push(self.containers[self_idx].clone());
                    self_idx += 1;
                }
                (None, Some(_)) => {
                    result.push(other.containers[other_idx].clone());
                    other_idx += 1;
                }
                (None, None) => break,
            }
        }

        self.containers = result;
    }

    /// Performs a bitwise XOR with another bitmap, modifying self in place.
    pub fn xor(&mut self, other: &Self) {
        let mut result = Vec::new();
        let mut self_idx = 0;
        let mut other_idx = 0;

        while self_idx < self.containers.len() || other_idx < other.containers.len() {
            let self_item = self.containers.get(self_idx);
            let other_item = other.containers.get(other_idx);

            match (self_item, other_item) {
                (Some((self_high, _)), Some((other_high, _))) => match self_high.cmp(other_high) {
                    core::cmp::Ordering::Less => {
                        result.push(self.containers[self_idx].clone());
                        self_idx += 1;
                    }
                    core::cmp::Ordering::Greater => {
                        result.push(other.containers[other_idx].clone());
                        other_idx += 1;
                    }
                    core::cmp::Ordering::Equal => {
                        let high = *self_high;
                        let new_container = xor_containers(
                            &self.containers[self_idx].1,
                            &other.containers[other_idx].1,
                        );
                        if !new_container.is_empty() {
                            result.push((high, new_container));
                        }
                        self_idx += 1;
                        other_idx += 1;
                    }
                },
                (Some(_), None) => {
                    result.push(self.containers[self_idx].clone());
                    self_idx += 1;
                }
                (None, Some(_)) => {
                    result.push(other.containers[other_idx].clone());
                    other_idx += 1;
                }
                (None, None) => break,
            }
        }

        self.containers = result;
    }

    /// Returns the intersection of two bitmaps as a new bitmap.
    pub fn intersection(&self, other: &Self) -> Self {
        let mut result = self.clone();
        result.and(other);
        result
    }

    /// Returns the union of two bitmaps as a new bitmap.
    pub fn union(&self, other: &Self) -> Self {
        let mut result = self.clone();
        result.or(other);
        result
    }

    /// Returns the symmetric difference of two bitmaps as a new bitmap.
    pub fn symmetric_difference(&self, other: &Self) -> Self {
        let mut result = self.clone();
        result.xor(other);
        result
    }
}

/// AND two containers together.
fn and_containers(a: &Container, b: &Container) -> Container {
    match (a, b) {
        (Container::Array(arr_a), Container::Array(arr_b)) => {
            // Intersection of two sorted arrays
            let mut result = Vec::new();
            let mut i = 0;
            let mut j = 0;
            while i < arr_a.len() && j < arr_b.len() {
                match arr_a[i].cmp(&arr_b[j]) {
                    core::cmp::Ordering::Less => i += 1,
                    core::cmp::Ordering::Greater => j += 1,
                    core::cmp::Ordering::Equal => {
                        result.push(arr_a[i]);
                        i += 1;
                        j += 1;
                    }
                }
            }
            Container::Array(result)
        }
        (Container::Bitmap(bits_a), Container::Bitmap(bits_b)) => {
            let bits: Vec<u64> = bits_a
                .iter()
                .zip(bits_b.iter())
                .map(|(&a, &b)| a & b)
                .collect();
            let mut container = Container::Bitmap(bits);
            container.maybe_convert_to_array();
            container
        }
        (Container::Array(arr), Container::Bitmap(bits))
        | (Container::Bitmap(bits), Container::Array(arr)) => {
            let result: Vec<u16> = arr
                .iter()
                .copied()
                .filter(|&v| {
                    let word_idx = v as usize / 64;
                    let bit_idx = v as usize % 64;
                    (bits[word_idx] & (1u64 << bit_idx)) != 0
                })
                .collect();
            Container::Array(result)
        }
    }
}

/// OR two containers together.
fn or_containers(a: &Container, b: &Container) -> Container {
    match (a, b) {
        (Container::Array(arr_a), Container::Array(arr_b)) => {
            // Union of two sorted arrays
            let mut result = Vec::with_capacity(arr_a.len() + arr_b.len());
            let mut i = 0;
            let mut j = 0;
            while i < arr_a.len() && j < arr_b.len() {
                match arr_a[i].cmp(&arr_b[j]) {
                    core::cmp::Ordering::Less => {
                        result.push(arr_a[i]);
                        i += 1;
                    }
                    core::cmp::Ordering::Greater => {
                        result.push(arr_b[j]);
                        j += 1;
                    }
                    core::cmp::Ordering::Equal => {
                        result.push(arr_a[i]);
                        i += 1;
                        j += 1;
                    }
                }
            }
            result.extend_from_slice(&arr_a[i..]);
            result.extend_from_slice(&arr_b[j..]);

            let mut container = Container::Array(result);
            container.maybe_convert_to_bitmap();
            container
        }
        (Container::Bitmap(bits_a), Container::Bitmap(bits_b)) => {
            let bits: Vec<u64> = bits_a
                .iter()
                .zip(bits_b.iter())
                .map(|(&a, &b)| a | b)
                .collect();
            Container::Bitmap(bits)
        }
        (Container::Array(arr), Container::Bitmap(bits))
        | (Container::Bitmap(bits), Container::Array(arr)) => {
            let mut new_bits = bits.clone();
            for &v in arr {
                let word_idx = v as usize / 64;
                let bit_idx = v as usize % 64;
                new_bits[word_idx] |= 1u64 << bit_idx;
            }
            Container::Bitmap(new_bits)
        }
    }
}

/// XOR two containers together.
fn xor_containers(a: &Container, b: &Container) -> Container {
    match (a, b) {
        (Container::Array(arr_a), Container::Array(arr_b)) => {
            // Symmetric difference of two sorted arrays
            let mut result = Vec::with_capacity(arr_a.len() + arr_b.len());
            let mut i = 0;
            let mut j = 0;
            while i < arr_a.len() && j < arr_b.len() {
                match arr_a[i].cmp(&arr_b[j]) {
                    core::cmp::Ordering::Less => {
                        result.push(arr_a[i]);
                        i += 1;
                    }
                    core::cmp::Ordering::Greater => {
                        result.push(arr_b[j]);
                        j += 1;
                    }
                    core::cmp::Ordering::Equal => {
                        // Skip elements that are in both
                        i += 1;
                        j += 1;
                    }
                }
            }
            result.extend_from_slice(&arr_a[i..]);
            result.extend_from_slice(&arr_b[j..]);

            let mut container = Container::Array(result);
            container.maybe_convert_to_bitmap();
            container
        }
        (Container::Bitmap(bits_a), Container::Bitmap(bits_b)) => {
            let bits: Vec<u64> = bits_a
                .iter()
                .zip(bits_b.iter())
                .map(|(&a, &b)| a ^ b)
                .collect();
            let mut container = Container::Bitmap(bits);
            container.maybe_convert_to_array();
            container
        }
        (Container::Array(arr), Container::Bitmap(bits))
        | (Container::Bitmap(bits), Container::Array(arr)) => {
            let mut new_bits = bits.clone();
            for &v in arr {
                let word_idx = v as usize / 64;
                let bit_idx = v as usize % 64;
                new_bits[word_idx] ^= 1u64 << bit_idx;
            }
            let mut container = Container::Bitmap(new_bits);
            container.maybe_convert_to_array();
            container
        }
    }
}

impl Default for RoaringBitmap {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for RoaringBitmap {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "RoaringBitmap {{ len: {}, containers: {} }}",
            self.len(),
            self.num_containers()
        )
    }
}

/// Iterator over values in a RoaringBitmap.
pub struct Iter<'a> {
    containers: &'a [(u64, Container)],
    container_idx: usize,
    container_iter: Option<(u64, ContainerIter<'a>)>,
}

impl Iterator for Iter<'_> {
    type Item = u64;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            // Try to get next value from current container
            if let Some((high, ref mut iter)) = self.container_iter {
                if let Some(low) = iter.next() {
                    return Some(RoaringBitmap::combine(high, low));
                }
            }

            // Move to next container
            if self.container_idx >= self.containers.len() {
                return None;
            }

            let (high, container) = &self.containers[self.container_idx];
            self.container_iter = Some((*high, container.iter()));
            self.container_idx += 1;
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        // Calculate remaining elements
        let remaining: usize = self.containers[self.container_idx..]
            .iter()
            .map(|(_, c)| c.len())
            .sum();
        (remaining, Some(remaining))
    }
}

impl<'a> IntoIterator for &'a RoaringBitmap {
    type Item = u64;
    type IntoIter = Iter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl FromIterator<u64> for RoaringBitmap {
    fn from_iter<I: IntoIterator<Item = u64>>(iter: I) -> Self {
        let mut bitmap = Self::new();
        for value in iter {
            bitmap.insert(value);
        }
        bitmap
    }
}

impl Extend<u64> for RoaringBitmap {
    fn extend<I: IntoIterator<Item = u64>>(&mut self, iter: I) {
        for value in iter {
            self.insert(value);
        }
    }
}

// Container type tag for serialization
const CONTAINER_TYPE_ARRAY: u8 = 0;
const CONTAINER_TYPE_BITMAP: u8 = 1;

impl Write for Container {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::Array(arr) => {
                CONTAINER_TYPE_ARRAY.write(buf);
                (arr.len() as u16).write(buf);
                for &value in arr {
                    value.write(buf);
                }
            }
            Self::Bitmap(bits) => {
                CONTAINER_TYPE_BITMAP.write(buf);
                for &word in bits {
                    word.write(buf);
                }
            }
        }
    }
}

impl Read for Container {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _cfg: &Self::Cfg) -> Result<Self, CodecError> {
        let container_type = u8::read(buf)?;
        match container_type {
            CONTAINER_TYPE_ARRAY => {
                let len = u16::read(buf)? as usize;
                at_least(buf, len * 2)?;
                let mut arr = Vec::with_capacity(len);
                for _ in 0..len {
                    arr.push(u16::read(buf)?);
                }
                Ok(Self::Array(arr))
            }
            CONTAINER_TYPE_BITMAP => {
                at_least(buf, BITMAP_CONTAINER_SIZE)?;
                let mut bits = Vec::with_capacity(BITMAP_CONTAINER_SIZE / 8);
                for _ in 0..BITMAP_CONTAINER_SIZE / 8 {
                    bits.push(u64::read(buf)?);
                }
                Ok(Self::Bitmap(bits))
            }
            _ => Err(CodecError::Invalid(
                "Container",
                "Invalid container type tag",
            )),
        }
    }
}

impl EncodeSize for Container {
    fn encode_size(&self) -> usize {
        match self {
            Self::Array(arr) => {
                1 // type tag
                + 2 // length
                + arr.len() * 2 // values
            }
            Self::Bitmap(_) => {
                1 // type tag
                + BITMAP_CONTAINER_SIZE // bitmap data
            }
        }
    }
}

impl Write for RoaringBitmap {
    fn write(&self, buf: &mut impl BufMut) {
        // Write number of containers
        (self.containers.len() as u64).write(buf);

        // Write each container with its high bits key
        for (high, container) in &self.containers {
            high.write(buf);
            container.write(buf);
        }
    }
}

impl Read for RoaringBitmap {
    type Cfg = u64; // Max number of containers

    fn read_cfg(buf: &mut impl Buf, max_containers: &Self::Cfg) -> Result<Self, CodecError> {
        let num_containers = u64::read(buf)?;
        if num_containers > *max_containers {
            return Err(CodecError::InvalidLength(num_containers as usize));
        }

        let mut containers = Vec::with_capacity(num_containers as usize);
        let mut last_high: Option<u64> = None;

        for _ in 0..num_containers {
            let high = u64::read(buf)?;

            // Verify containers are in sorted order and unique
            if let Some(last) = last_high {
                if high <= last {
                    return Err(CodecError::Invalid(
                        "RoaringBitmap",
                        "Containers must be in ascending order with unique keys",
                    ));
                }
            }
            last_high = Some(high);

            let container = Container::read(buf)?;
            if container.is_empty() {
                return Err(CodecError::Invalid(
                    "RoaringBitmap",
                    "Empty containers are not allowed",
                ));
            }
            containers.push((high, container));
        }

        Ok(Self { containers })
    }
}

impl EncodeSize for RoaringBitmap {
    fn encode_size(&self) -> usize {
        8 // number of containers (u64)
        + self.containers.iter().map(|(_, c)| 8 + c.encode_size()).sum::<usize>()
    }
}

#[cfg(feature = "arbitrary")]
impl arbitrary::Arbitrary<'_> for RoaringBitmap {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let size = u.int_in_range(0..=1024)?;
        let mut bitmap = Self::new();
        for _ in 0..size {
            bitmap.insert(u.arbitrary::<u64>()?);
        }
        Ok(bitmap)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::{Decode, Encode};

    #[test]
    fn test_new() {
        let bitmap = RoaringBitmap::new();
        assert!(bitmap.is_empty());
        assert_eq!(bitmap.len(), 0);
        assert_eq!(bitmap.num_containers(), 0);
    }

    #[test]
    fn test_insert_and_contains() {
        let mut bitmap = RoaringBitmap::new();

        // Insert some values
        assert!(bitmap.insert(10));
        assert!(bitmap.insert(100));
        assert!(bitmap.insert(1000));
        assert!(bitmap.insert(100_000));

        // Verify they are present
        assert!(bitmap.contains(10));
        assert!(bitmap.contains(100));
        assert!(bitmap.contains(1000));
        assert!(bitmap.contains(100_000));

        // Verify non-existent values
        assert!(!bitmap.contains(11));
        assert!(!bitmap.contains(99));
        assert!(!bitmap.contains(50_000));

        // Insert duplicate returns false
        assert!(!bitmap.insert(10));
        assert_eq!(bitmap.len(), 4);
    }

    #[test]
    fn test_large_u64_values() {
        let mut bitmap = RoaringBitmap::new();

        // Test with large u64 values
        let large_values = [
            1_000_000_000_000u64,
            u64::MAX - 100,
            u64::MAX,
            1u64 << 48,
            (1u64 << 48) + 1,
        ];

        for &value in &large_values {
            assert!(bitmap.insert(value));
        }

        for &value in &large_values {
            assert!(bitmap.contains(value), "Missing value: {}", value);
        }

        assert_eq!(bitmap.len(), large_values.len() as u64);
    }

    #[test]
    fn test_remove() {
        let mut bitmap = RoaringBitmap::new();
        bitmap.insert(10);
        bitmap.insert(20);
        bitmap.insert(30);

        assert_eq!(bitmap.len(), 3);

        // Remove existing value
        assert!(bitmap.remove(20));
        assert!(!bitmap.contains(20));
        assert_eq!(bitmap.len(), 2);

        // Remove non-existent value
        assert!(!bitmap.remove(20));
        assert!(!bitmap.remove(40));
        assert_eq!(bitmap.len(), 2);

        // Remove remaining values
        assert!(bitmap.remove(10));
        assert!(bitmap.remove(30));
        assert!(bitmap.is_empty());
    }

    #[test]
    fn test_min_max() {
        let mut bitmap = RoaringBitmap::new();

        assert_eq!(bitmap.min(), None);
        assert_eq!(bitmap.max(), None);

        bitmap.insert(100);
        assert_eq!(bitmap.min(), Some(100));
        assert_eq!(bitmap.max(), Some(100));

        bitmap.insert(10);
        assert_eq!(bitmap.min(), Some(10));
        assert_eq!(bitmap.max(), Some(100));

        bitmap.insert(1000);
        assert_eq!(bitmap.min(), Some(10));
        assert_eq!(bitmap.max(), Some(1000));

        // Add values in different containers
        bitmap.insert(100_000);
        assert_eq!(bitmap.min(), Some(10));
        assert_eq!(bitmap.max(), Some(100_000));

        // Test with large u64 values
        bitmap.insert(u64::MAX);
        assert_eq!(bitmap.min(), Some(10));
        assert_eq!(bitmap.max(), Some(u64::MAX));
    }

    #[test]
    fn test_iterator() {
        let mut bitmap = RoaringBitmap::new();
        bitmap.insert(5);
        bitmap.insert(10);
        bitmap.insert(70_000);
        bitmap.insert(15);

        let values: Vec<u64> = bitmap.iter().collect();
        assert_eq!(values, vec![5, 10, 15, 70_000]);
    }

    #[test]
    fn test_from_iterator() {
        let values = vec![100u64, 50, 200, 50, 75];
        let bitmap: RoaringBitmap = values.into_iter().collect();

        assert_eq!(bitmap.len(), 4); // 50 is duplicate
        assert!(bitmap.contains(50));
        assert!(bitmap.contains(75));
        assert!(bitmap.contains(100));
        assert!(bitmap.contains(200));
    }

    #[test]
    fn test_extend() {
        let mut bitmap = RoaringBitmap::new();
        bitmap.insert(1);
        bitmap.extend([2u64, 3, 4]);
        assert_eq!(bitmap.len(), 4);
    }

    #[test]
    fn test_array_to_bitmap_conversion() {
        let mut bitmap = RoaringBitmap::new();

        // Insert enough values to trigger conversion
        for i in 0..ARRAY_TO_BITMAP_THRESHOLD as u64 {
            bitmap.insert(i);
        }

        assert_eq!(bitmap.len(), ARRAY_TO_BITMAP_THRESHOLD as u64);

        // Verify all values are still present
        for i in 0..ARRAY_TO_BITMAP_THRESHOLD as u64 {
            assert!(bitmap.contains(i), "Missing value: {}", i);
        }
    }

    #[test]
    fn test_multiple_containers() {
        let mut bitmap = RoaringBitmap::new();

        // Insert values in different containers (different high 48 bits)
        bitmap.insert(0);
        bitmap.insert(65_536); // Container 1
        bitmap.insert(131_072); // Container 2
        bitmap.insert(196_608); // Container 3

        assert_eq!(bitmap.num_containers(), 4);
        assert_eq!(bitmap.len(), 4);

        assert!(bitmap.contains(0));
        assert!(bitmap.contains(65_536));
        assert!(bitmap.contains(131_072));
        assert!(bitmap.contains(196_608));
    }

    #[test]
    fn test_and() {
        let mut a = RoaringBitmap::new();
        a.insert(1);
        a.insert(2);
        a.insert(3);
        a.insert(100_000);

        let mut b = RoaringBitmap::new();
        b.insert(2);
        b.insert(3);
        b.insert(4);
        b.insert(100_000);

        a.and(&b);

        assert_eq!(a.len(), 3);
        assert!(!a.contains(1));
        assert!(a.contains(2));
        assert!(a.contains(3));
        assert!(!a.contains(4));
        assert!(a.contains(100_000));
    }

    #[test]
    fn test_or() {
        let mut a = RoaringBitmap::new();
        a.insert(1);
        a.insert(2);

        let mut b = RoaringBitmap::new();
        b.insert(2);
        b.insert(3);

        a.or(&b);

        assert_eq!(a.len(), 3);
        assert!(a.contains(1));
        assert!(a.contains(2));
        assert!(a.contains(3));
    }

    #[test]
    fn test_xor() {
        let mut a = RoaringBitmap::new();
        a.insert(1);
        a.insert(2);
        a.insert(3);

        let mut b = RoaringBitmap::new();
        b.insert(2);
        b.insert(3);
        b.insert(4);

        a.xor(&b);

        assert_eq!(a.len(), 2);
        assert!(a.contains(1));
        assert!(!a.contains(2));
        assert!(!a.contains(3));
        assert!(a.contains(4));
    }

    #[test]
    fn test_intersection() {
        let mut a = RoaringBitmap::new();
        a.extend([1u64, 2, 3, 4]);

        let mut b = RoaringBitmap::new();
        b.extend([3u64, 4, 5, 6]);

        let c = a.intersection(&b);
        assert_eq!(c.len(), 2);
        assert!(c.contains(3));
        assert!(c.contains(4));

        // Original unchanged
        assert_eq!(a.len(), 4);
    }

    #[test]
    fn test_union() {
        let mut a = RoaringBitmap::new();
        a.extend([1u64, 2]);

        let mut b = RoaringBitmap::new();
        b.extend([2u64, 3]);

        let c = a.union(&b);
        assert_eq!(c.len(), 3);
    }

    #[test]
    fn test_symmetric_difference() {
        let mut a = RoaringBitmap::new();
        a.extend([1u64, 2, 3]);

        let mut b = RoaringBitmap::new();
        b.extend([2u64, 3, 4]);

        let c = a.symmetric_difference(&b);
        assert_eq!(c.len(), 2);
        assert!(c.contains(1));
        assert!(c.contains(4));
    }

    #[test]
    fn test_clear() {
        let mut bitmap = RoaringBitmap::new();
        bitmap.extend([1u64, 2, 3, 100_000]);

        bitmap.clear();
        assert!(bitmap.is_empty());
        assert_eq!(bitmap.num_containers(), 0);
    }

    #[test]
    fn test_codec_empty() {
        let bitmap = RoaringBitmap::new();
        let encoded = bitmap.encode();
        let decoded = RoaringBitmap::decode_cfg(encoded, &1000).unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn test_codec_array_container() {
        let mut bitmap = RoaringBitmap::new();
        bitmap.extend([1u64, 5, 10, 100, 1000]);

        let encoded = bitmap.encode();
        let decoded = RoaringBitmap::decode_cfg(encoded, &1000).unwrap();

        assert_eq!(decoded.len(), bitmap.len());
        for value in bitmap.iter() {
            assert!(decoded.contains(value));
        }
    }

    #[test]
    fn test_codec_bitmap_container() {
        let mut bitmap = RoaringBitmap::new();
        // Insert enough to create a bitmap container
        for i in 0..ARRAY_TO_BITMAP_THRESHOLD as u64 {
            bitmap.insert(i);
        }

        let encoded = bitmap.encode();
        let decoded = RoaringBitmap::decode_cfg(encoded, &1000).unwrap();

        assert_eq!(decoded.len(), bitmap.len());
        for i in 0..ARRAY_TO_BITMAP_THRESHOLD as u64 {
            assert!(decoded.contains(i));
        }
    }

    #[test]
    fn test_codec_multiple_containers() {
        let mut bitmap = RoaringBitmap::new();
        bitmap.insert(10);
        bitmap.insert(65_536 + 20);
        bitmap.insert(2 * 65_536 + 30);

        let encoded = bitmap.encode();
        let decoded = RoaringBitmap::decode_cfg(encoded, &1000).unwrap();

        assert_eq!(decoded.num_containers(), 3);
        assert!(decoded.contains(10));
        assert!(decoded.contains(65_536 + 20));
        assert!(decoded.contains(2 * 65_536 + 30));
    }

    #[test]
    fn test_codec_large_u64_values() {
        let mut bitmap = RoaringBitmap::new();
        bitmap.insert(1_000_000_000_000u64);
        bitmap.insert(u64::MAX);
        bitmap.insert(1u64 << 48);

        let encoded = bitmap.encode();
        let decoded = RoaringBitmap::decode_cfg(encoded, &1000).unwrap();

        assert_eq!(decoded.len(), 3);
        assert!(decoded.contains(1_000_000_000_000u64));
        assert!(decoded.contains(u64::MAX));
        assert!(decoded.contains(1u64 << 48));
    }

    #[test]
    fn test_codec_max_containers_exceeded() {
        let mut bitmap = RoaringBitmap::new();
        bitmap.insert(0);
        bitmap.insert(65_536);
        bitmap.insert(2 * 65_536);

        let encoded = bitmap.encode();
        let result = RoaringBitmap::decode_cfg(encoded, &2);
        assert!(result.is_err());
    }

    #[test]
    fn test_encode_size() {
        let mut bitmap = RoaringBitmap::new();
        bitmap.extend([1u64, 2, 3]);

        let encoded = bitmap.encode();
        assert_eq!(encoded.len(), bitmap.encode_size());
    }

    #[test]
    fn test_debug() {
        let mut bitmap = RoaringBitmap::new();
        bitmap.extend([1u64, 2, 3]);
        let debug_str = format!("{:?}", bitmap);
        assert!(debug_str.contains("RoaringBitmap"));
        assert!(debug_str.contains("len: 3"));
    }

    #[test]
    fn test_default() {
        let bitmap: RoaringBitmap = Default::default();
        assert!(bitmap.is_empty());
    }

    #[test]
    fn test_clone_and_eq() {
        let mut bitmap = RoaringBitmap::new();
        bitmap.extend([1u64, 2, 3, 100_000]);

        let cloned = bitmap.clone();
        assert_eq!(bitmap, cloned);

        // Modify original
        bitmap.insert(4);
        assert_ne!(bitmap, cloned);
    }

    #[test]
    fn test_boundary_values() {
        let mut bitmap = RoaringBitmap::new();

        // Test boundary values
        bitmap.insert(0);
        bitmap.insert(u64::MAX);
        bitmap.insert(65_535); // Last value in container 0
        bitmap.insert(65_536); // First value in container 1

        assert!(bitmap.contains(0));
        assert!(bitmap.contains(u64::MAX));
        assert!(bitmap.contains(65_535));
        assert!(bitmap.contains(65_536));

        assert_eq!(bitmap.min(), Some(0));
        assert_eq!(bitmap.max(), Some(u64::MAX));
    }

    #[test]
    fn test_sparse_values() {
        let mut bitmap = RoaringBitmap::new();

        // Insert values spread across many containers
        for i in 0..100u64 {
            bitmap.insert(i * 65_536);
        }

        assert_eq!(bitmap.num_containers(), 100);
        assert_eq!(bitmap.len(), 100);

        for i in 0..100u64 {
            assert!(bitmap.contains(i * 65_536));
        }
    }

    #[test]
    fn test_high_bit_containers() {
        let mut bitmap = RoaringBitmap::new();

        // Test values that differ only in high bits
        let base = 1u64 << 48;
        bitmap.insert(base);
        bitmap.insert(base + 1);
        bitmap.insert(base + 65_536);

        assert_eq!(bitmap.num_containers(), 2); // Two different high-48-bit groups
        assert!(bitmap.contains(base));
        assert!(bitmap.contains(base + 1));
        assert!(bitmap.contains(base + 65_536));
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use commonware_codec::conformance::CodecConformance;

        commonware_conformance::conformance_tests! {
            CodecConformance<super::RoaringBitmap>,
        }
    }
}
