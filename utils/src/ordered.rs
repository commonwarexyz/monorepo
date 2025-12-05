//! Ordered collections that guarantee sorted, deduplicated items.

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, RangeCfg, Read, Write};
use core::{
    fmt,
    hash::Hash,
    ops::{Deref, Index, Range},
};
#[cfg(not(feature = "std"))]
use hashbrown::HashSet;
#[cfg(feature = "std")]
use std::collections::HashSet;
use thiserror::Error;

#[cfg(not(feature = "std"))]
type VecIntoIter<T> = alloc::vec::IntoIter<T>;
#[cfg(feature = "std")]
type VecIntoIter<T> = std::vec::IntoIter<T>;

/// Errors that can occur when interacting with ordered collections.
#[derive(Error, Debug, PartialEq, Eq)]
pub enum Error {
    /// A key was duplicated.
    #[error("duplicate key")]
    DuplicateKey,

    /// A value was duplicated.
    #[error("duplicate value")]
    DuplicateValue,
}

use crate::TryFromIterator;

/// An ordered, deduplicated collection of items.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Set<T>(Vec<T>);

impl<T: fmt::Debug> fmt::Debug for Set<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Set").field(&self.0).finish()
    }
}

impl<T: Ord> Set<T> {
    /// Creates a new [`Set`] from an iterator, removing duplicates.
    ///
    /// Unlike [`FromIterator`] and [`From`], this method tolerates duplicate
    /// items by silently discarding them.
    pub fn from_iter_dedup<I: IntoIterator<Item = T>>(iter: I) -> Self {
        let mut items: Vec<T> = iter.into_iter().collect();
        items.sort();
        items.dedup();
        Self(items)
    }
}

impl<T> Set<T> {
    /// Returns the size of the ordered collection.
    pub const fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns `true` if the collection is empty.
    pub const fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns an item by index, if it exists.
    pub fn get(&self, index: usize) -> Option<&T> {
        self.0.get(index)
    }

    /// Returns the position of a given item in the collection, if it exists.
    pub fn position(&self, item: &T) -> Option<usize>
    where
        T: Ord,
    {
        self.0.binary_search(item).ok()
    }

    /// Returns an iterator over the items in the collection.
    pub fn iter(&self) -> core::slice::Iter<'_, T> {
        self.into_iter()
    }
}

impl<T: Write> Write for Set<T> {
    fn write(&self, buf: &mut impl BufMut) {
        self.0.write(buf);
    }
}

impl<T: EncodeSize> EncodeSize for Set<T> {
    fn encode_size(&self) -> usize {
        self.0.encode_size()
    }
}

impl<T: Read + Ord> Read for Set<T> {
    type Cfg = (RangeCfg<usize>, T::Cfg);

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
        let items = Vec::<T>::read_cfg(buf, cfg)?;
        for i in 1..items.len() {
            if items[i - 1] >= items[i] {
                return Err(commonware_codec::Error::Invalid(
                    "Set",
                    "items must be sorted and unique",
                ));
            }
        }
        Ok(Self(items))
    }
}

impl<T: Ord> TryFromIterator<T> for Set<T> {
    type Error = Error;

    /// Attempts to create a [`Set`] from an iterator.
    ///
    /// Returns an error if there are duplicate items.
    fn try_from_iter<I: IntoIterator<Item = T>>(iter: I) -> Result<Self, Self::Error> {
        let mut items: Vec<T> = iter.into_iter().collect();
        items.sort();
        let len = items.len();
        items.dedup();
        if items.len() != len {
            return Err(Error::DuplicateKey);
        }
        Ok(Self(items))
    }
}

impl<T: Ord> TryFrom<Vec<T>> for Set<T> {
    type Error = Error;

    fn try_from(items: Vec<T>) -> Result<Self, Self::Error> {
        Self::try_from_iter(items)
    }
}

impl<T: Ord + Clone> TryFrom<&[T]> for Set<T> {
    type Error = Error;

    fn try_from(items: &[T]) -> Result<Self, Self::Error> {
        Self::try_from_iter(items.iter().cloned())
    }
}

impl<T: Ord, const N: usize> TryFrom<[T; N]> for Set<T> {
    type Error = Error;

    fn try_from(items: [T; N]) -> Result<Self, Self::Error> {
        Self::try_from_iter(items)
    }
}

impl<T: Ord + Clone, const N: usize> TryFrom<&[T; N]> for Set<T> {
    type Error = Error;

    fn try_from(items: &[T; N]) -> Result<Self, Self::Error> {
        Self::try_from(items.as_slice())
    }
}

impl<T> IntoIterator for Set<T> {
    type Item = T;
    type IntoIter = VecIntoIter<T>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'a, T> IntoIterator for &'a Set<T> {
    type Item = &'a T;
    type IntoIter = core::slice::Iter<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl<T> Index<usize> for Set<T> {
    type Output = T;

    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index]
    }
}

impl<T> Index<Range<usize>> for Set<T> {
    type Output = [T];

    fn index(&self, index: Range<usize>) -> &Self::Output {
        &self.0[index]
    }
}

impl<T> AsRef<[T]> for Set<T> {
    fn as_ref(&self) -> &[T] {
        &self.0
    }
}

impl<T: fmt::Display> fmt::Display for Set<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "[")?;
        for (i, item) in self.0.iter().enumerate() {
            if i > 0 {
                write!(f, ", ")?;
            }
            write!(f, "{item}")?;
        }
        write!(f, "]")
    }
}

impl<T> From<Set<T>> for Vec<T> {
    fn from(set: Set<T>) -> Self {
        set.0
    }
}

/// Extension trait for [`Set`] participant sets providing quorum and index utilities.
pub trait Quorum {
    /// The type of items in this set.
    type Item: Ord;

    /// Returns the quorum value (2f+1) for this participant set.
    ///
    /// ## Panics
    ///
    /// Panics if the number of participants exceeds `u32::MAX`.
    fn quorum(&self) -> u32;

    /// Returns the maximum number of faults (f) tolerated by this participant set.
    ///
    /// ## Panics
    ///
    /// Panics if the number of participants exceeds `u32::MAX`.
    fn max_faults(&self) -> u32;

    /// Returns the participant key at the given index.
    fn key(&self, index: u32) -> Option<&Self::Item>;

    /// Returns the index for the given participant key, if present.
    ///
    /// ## Panics
    ///
    /// Panics if the participant index exceeds `u32::MAX`.
    fn index(&self, key: &Self::Item) -> Option<u32>;
}

impl<T: Ord> Quorum for Set<T> {
    type Item = T;

    fn quorum(&self) -> u32 {
        crate::quorum(u32::try_from(self.len()).expect("too many participants"))
    }

    fn max_faults(&self) -> u32 {
        crate::max_faults(u32::try_from(self.len()).expect("too many participants"))
    }

    fn key(&self, index: u32) -> Option<&Self::Item> {
        self.get(index as usize)
    }

    fn index(&self, key: &Self::Item) -> Option<u32> {
        self.position(key)
            .map(|position| u32::try_from(position).expect("too many participants"))
    }
}

/// An ordered, deduplicated collection of key-value pairs.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Map<K, V> {
    keys: Set<K>,
    values: Vec<V>,
}

impl<K: Ord, V> Map<K, V> {
    /// Creates a new [`Map`] from an iterator, removing duplicate keys.
    ///
    /// Unlike [`FromIterator`] and [`From`], this method tolerates duplicate
    /// keys by silently discarding them (keeping the first occurrence).
    pub fn from_iter_dedup<I: IntoIterator<Item = (K, V)>>(iter: I) -> Self {
        let mut items: Vec<(K, V)> = iter.into_iter().collect();
        items.sort_by(|(lk, _), (rk, _)| lk.cmp(rk));
        items.dedup_by(|l, r| l.0 == r.0);

        let mut keys = Vec::with_capacity(items.len());
        let mut values = Vec::with_capacity(items.len());
        for (key, value) in items {
            keys.push(key);
            values.push(value);
        }

        Self {
            keys: Set(keys),
            values,
        }
    }
}

impl<K, V> Map<K, V> {
    /// Returns the number of entries in the map.
    pub const fn len(&self) -> usize {
        self.keys.len()
    }

    /// Returns `true` if the map is empty.
    pub const fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// Returns a key by index, if it exists.
    pub fn get(&self, index: usize) -> Option<&K> {
        self.keys.get(index)
    }

    /// Returns the position of the provided key, if it exists.
    pub fn position(&self, key: &K) -> Option<usize>
    where
        K: Ord,
    {
        self.keys.position(key)
    }

    /// Returns the ordered keys as a [`Set`] reference.
    pub const fn keys(&self) -> &Set<K> {
        &self.keys
    }

    /// Consumes the map and returns the ordered keys.
    pub fn into_keys(self) -> Set<K> {
        self.keys
    }

    /// Returns the associated value at `index`, if it exists.
    pub fn value(&self, index: usize) -> Option<&V> {
        self.values.get(index)
    }

    /// Returns the associated value for `key`, if it exists.
    pub fn get_value(&self, key: &K) -> Option<&V>
    where
        K: Ord,
    {
        self.position(key).and_then(|index| self.values.get(index))
    }

    /// Returns a mutable reference to the associated value for `key`, if it exists.
    pub fn get_value_mut(&mut self, key: &K) -> Option<&mut V>
    where
        K: Ord,
    {
        self.position(key)
            .and_then(|index| self.values.get_mut(index))
    }

    /// Returns the associated values.
    pub fn values(&self) -> &[V] {
        &self.values
    }

    /// Returns a mutable reference to the associated values
    pub fn values_mut(&mut self) -> &mut [V] {
        &mut self.values
    }

    /// Returns a zipped iterator over keys and values.
    pub fn iter_pairs(&self) -> impl Iterator<Item = (&K, &V)> {
        self.keys.iter().zip(self.values.iter())
    }

    /// Returns an iterator over the ordered keys.
    pub fn iter(&self) -> core::slice::Iter<'_, K> {
        self.keys.iter()
    }
}

impl<K: fmt::Debug, V: fmt::Debug> fmt::Debug for Map<K, V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Map")
            .field(&self.iter_pairs().collect::<Vec<_>>())
            .finish()
    }
}

impl<K: fmt::Display, V: fmt::Display> fmt::Display for Map<K, V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "[")?;
        for (i, (key, value)) in self.iter_pairs().enumerate() {
            if i > 0 {
                write!(f, ", ")?;
            }
            write!(f, "({key}, {value})")?;
        }
        write!(f, "]")
    }
}

impl<K, V> AsRef<[K]> for Map<K, V> {
    fn as_ref(&self) -> &[K] {
        self.keys.as_ref()
    }
}

impl<K, V> AsRef<Set<K>> for Map<K, V> {
    fn as_ref(&self) -> &Set<K> {
        &self.keys
    }
}

impl<K, V> Deref for Map<K, V> {
    type Target = Set<K>;

    fn deref(&self) -> &Self::Target {
        &self.keys
    }
}

impl<K: Ord, V> TryFromIterator<(K, V)> for Map<K, V> {
    type Error = Error;

    /// Attempts to create a [`Map`] from an iterator.
    ///
    /// Returns an error if there are duplicate keys.
    fn try_from_iter<I: IntoIterator<Item = (K, V)>>(iter: I) -> Result<Self, Self::Error> {
        let mut items: Vec<(K, V)> = iter.into_iter().collect();
        items.sort_by(|(lk, _), (rk, _)| lk.cmp(rk));
        let len = items.len();
        items.dedup_by(|l, r| l.0 == r.0);
        if items.len() != len {
            return Err(Error::DuplicateKey);
        }

        let mut keys = Vec::with_capacity(items.len());
        let mut values = Vec::with_capacity(items.len());
        for (key, value) in items {
            keys.push(key);
            values.push(value);
        }

        Ok(Self {
            keys: Set(keys),
            values,
        })
    }
}

impl<K: Ord, V> TryFrom<Vec<(K, V)>> for Map<K, V> {
    type Error = Error;

    fn try_from(items: Vec<(K, V)>) -> Result<Self, Self::Error> {
        Self::try_from_iter(items)
    }
}

impl<K: Ord + Clone, V: Clone> TryFrom<&[(K, V)]> for Map<K, V> {
    type Error = Error;

    fn try_from(items: &[(K, V)]) -> Result<Self, Self::Error> {
        Self::try_from_iter(items.iter().cloned())
    }
}

impl<K: Ord, V, const N: usize> TryFrom<[(K, V); N]> for Map<K, V> {
    type Error = Error;

    fn try_from(items: [(K, V); N]) -> Result<Self, Self::Error> {
        Self::try_from_iter(items)
    }
}

impl<K: Ord + Clone, V: Clone, const N: usize> TryFrom<&[(K, V); N]> for Map<K, V> {
    type Error = Error;

    fn try_from(items: &[(K, V); N]) -> Result<Self, Self::Error> {
        Self::try_from(items.as_slice())
    }
}

impl<K, V> From<Map<K, V>> for Vec<(K, V)> {
    fn from(wrapped: Map<K, V>) -> Self {
        wrapped.into_iter().collect()
    }
}

impl<K: Write, V: Write> Write for Map<K, V> {
    fn write(&self, buf: &mut impl BufMut) {
        self.keys.write(buf);
        self.values.write(buf);
    }
}

impl<K: EncodeSize, V: EncodeSize> EncodeSize for Map<K, V> {
    fn encode_size(&self) -> usize {
        self.keys.encode_size() + self.values.encode_size()
    }
}

impl<K: Read + Ord, V: Read> Read for Map<K, V> {
    type Cfg = (RangeCfg<usize>, K::Cfg, V::Cfg);

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
        let (range_cfg, key_cfg, value_cfg) = cfg;
        let keys = Set::<K>::read_cfg(buf, &(*range_cfg, key_cfg.clone()))?;
        let values = Vec::<V>::read_cfg(buf, &(RangeCfg::exact(keys.len()), value_cfg.clone()))?;
        Ok(Self { keys, values })
    }
}

impl<K, V> IntoIterator for Map<K, V> {
    type Item = (K, V);
    type IntoIter = MapIntoIter<K, V>;

    fn into_iter(self) -> Self::IntoIter {
        MapIntoIter {
            keys: self.keys.into_iter(),
            values: self.values.into_iter(),
        }
    }
}

impl<'a, K, V> IntoIterator for &'a Map<K, V> {
    type Item = (&'a K, &'a V);
    type IntoIter = core::iter::Zip<core::slice::Iter<'a, K>, core::slice::Iter<'a, V>>;

    fn into_iter(self) -> Self::IntoIter {
        self.keys.iter().zip(self.values.iter())
    }
}

/// An iterator over owned key-value pairs.
pub struct MapIntoIter<K, V> {
    keys: VecIntoIter<K>,
    values: VecIntoIter<V>,
}

impl<K, V> Iterator for MapIntoIter<K, V> {
    type Item = (K, V);

    fn next(&mut self) -> Option<Self::Item> {
        let key = self.keys.next()?;
        let value = self.values.next()?;
        Some((key, value))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.keys.size_hint()
    }
}

impl<K, V> ExactSizeIterator for MapIntoIter<K, V> {}

impl<K, V> DoubleEndedIterator for MapIntoIter<K, V> {
    fn next_back(&mut self) -> Option<Self::Item> {
        let key = self.keys.next_back()?;
        let value = self.values.next_back()?;
        Some((key, value))
    }
}

/// An ordered, deduplicated collection of key-value pairs with unique values.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct BiMap<K, V> {
    inner: Map<K, V>,
}

impl<K, V> BiMap<K, V> {
    /// Returns the number of entries in the map.
    pub const fn len(&self) -> usize {
        self.inner.len()
    }

    /// Returns `true` if the map is empty.
    pub const fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Returns a key by index, if it exists.
    pub fn get(&self, index: usize) -> Option<&K> {
        self.inner.get(index)
    }

    /// Returns the position of the provided key, if it exists.
    pub fn position(&self, key: &K) -> Option<usize>
    where
        K: Ord,
    {
        self.inner.position(key)
    }

    /// Returns the ordered keys as a [`Set`] reference.
    pub const fn keys(&self) -> &Set<K> {
        self.inner.keys()
    }

    /// Consumes the map and returns the ordered keys.
    pub fn into_keys(self) -> Set<K> {
        self.inner.into_keys()
    }

    /// Returns the associated value at `index`, if it exists.
    pub fn value(&self, index: usize) -> Option<&V> {
        self.inner.value(index)
    }

    /// Returns the associated value for `key`, if it exists.
    pub fn get_value(&self, key: &K) -> Option<&V>
    where
        K: Ord,
    {
        self.inner.get_value(key)
    }

    /// Returns the associated key for `value`, if it exists.
    pub fn get_key(&self, value: &V) -> Option<&K>
    where
        V: PartialEq,
    {
        self.inner
            .values()
            .iter()
            .position(|v| v == value)
            .map(|idx| &self.inner.keys()[idx])
    }

    /// Returns the associated values.
    pub fn values(&self) -> &[V] {
        self.inner.values()
    }

    /// Returns a zipped iterator over keys and values.
    pub fn iter_pairs(&self) -> impl Iterator<Item = (&K, &V)> {
        self.inner.iter_pairs()
    }

    /// Returns an iterator over the ordered keys.
    pub fn iter(&self) -> core::slice::Iter<'_, K> {
        self.inner.iter()
    }
}

impl<K: Ord, V: Eq + Hash> TryFromIterator<(K, V)> for BiMap<K, V> {
    type Error = Error;

    /// Attempts to create a [`BiMap`] from an iterator of key-value pairs.
    ///
    /// Returns an error if any key or value is duplicated.
    fn try_from_iter<I: IntoIterator<Item = (K, V)>>(iter: I) -> Result<Self, Self::Error> {
        let map = <Map<K, V> as TryFromIterator<(K, V)>>::try_from_iter(iter)?;
        Self::try_from(map)
    }
}

impl<K, V: Eq + Hash> TryFrom<Map<K, V>> for BiMap<K, V> {
    type Error = Error;

    fn try_from(map: Map<K, V>) -> Result<Self, Self::Error> {
        {
            let mut seen = HashSet::with_capacity(map.values.len());
            for value in map.values.iter() {
                if !seen.insert(value) {
                    return Err(Error::DuplicateValue);
                }
            }
        }
        Ok(Self { inner: map })
    }
}

impl<K: fmt::Debug, V: fmt::Debug> fmt::Debug for BiMap<K, V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("BiMap")
            .field(&self.inner.iter_pairs().collect::<Vec<_>>())
            .finish()
    }
}

impl<K: fmt::Display, V: fmt::Display> fmt::Display for BiMap<K, V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "[")?;
        for (i, (key, value)) in self.iter_pairs().enumerate() {
            if i > 0 {
                write!(f, ", ")?;
            }
            write!(f, "({key}, {value})")?;
        }
        write!(f, "]")
    }
}

impl<K, V> AsRef<[K]> for BiMap<K, V> {
    fn as_ref(&self) -> &[K] {
        self.inner.as_ref()
    }
}

impl<K, V> AsRef<Set<K>> for BiMap<K, V> {
    fn as_ref(&self) -> &Set<K> {
        self.inner.as_ref()
    }
}

impl<K, V> Deref for BiMap<K, V> {
    type Target = Set<K>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<K: Ord + Clone, V: Clone + Eq + Hash> TryFrom<&[(K, V)]> for BiMap<K, V> {
    type Error = Error;

    fn try_from(items: &[(K, V)]) -> Result<Self, Self::Error> {
        Self::try_from_iter(items.iter().cloned())
    }
}

impl<K: Ord, V: Eq + Hash> TryFrom<Vec<(K, V)>> for BiMap<K, V> {
    type Error = Error;

    fn try_from(items: Vec<(K, V)>) -> Result<Self, Self::Error> {
        Self::try_from_iter(items)
    }
}

impl<K: Ord, V: Eq + Hash, const N: usize> TryFrom<[(K, V); N]> for BiMap<K, V> {
    type Error = Error;

    fn try_from(items: [(K, V); N]) -> Result<Self, Self::Error> {
        Self::try_from_iter(items)
    }
}

impl<K: Ord + Clone, V: Clone + Eq + Hash, const N: usize> TryFrom<&[(K, V); N]> for BiMap<K, V> {
    type Error = Error;

    fn try_from(items: &[(K, V); N]) -> Result<Self, Self::Error> {
        Self::try_from(items.as_slice())
    }
}

impl<K, V> From<BiMap<K, V>> for Vec<(K, V)> {
    fn from(wrapped: BiMap<K, V>) -> Self {
        wrapped.inner.into()
    }
}

impl<K: Write, V: Write> Write for BiMap<K, V> {
    fn write(&self, buf: &mut impl BufMut) {
        self.inner.write(buf);
    }
}

impl<K: EncodeSize, V: EncodeSize> EncodeSize for BiMap<K, V> {
    fn encode_size(&self) -> usize {
        self.inner.encode_size()
    }
}

impl<K: Read + Ord, V: Eq + Hash + Read> Read for BiMap<K, V> {
    type Cfg = (RangeCfg<usize>, K::Cfg, V::Cfg);

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
        let inner = Map::<K, V>::read_cfg(buf, cfg)?;
        Self::try_from(inner).map_err(|_| {
            commonware_codec::Error::Invalid(
                "BiMap",
                "duplicate value detected during deserialization",
            )
        })
    }
}

impl<K, V> IntoIterator for BiMap<K, V> {
    type Item = (K, V);
    type IntoIter = MapIntoIter<K, V>;

    fn into_iter(self) -> Self::IntoIter {
        self.inner.into_iter()
    }
}

impl<'a, K, V> IntoIterator for &'a BiMap<K, V> {
    type Item = (&'a K, &'a V);
    type IntoIter = core::iter::Zip<core::slice::Iter<'a, K>, core::slice::Iter<'a, V>>;

    fn into_iter(self) -> Self::IntoIter {
        self.inner.iter().zip(self.inner.values().iter())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_sorted_unique_construct_unseal() {
        const CASE: [u8; 12] = [1, 3, 2, 5, 4, 3, 1, 7, 9, 6, 8, 4];
        const EXPECTED: [u8; 9] = [1, 2, 3, 4, 5, 6, 7, 8, 9];

        let sorted = Set::from_iter_dedup(CASE);
        assert_eq!(sorted.iter().copied().collect::<Vec<_>>(), EXPECTED);

        let unsealed: Vec<_> = sorted.into();
        assert_eq!(unsealed, EXPECTED);
    }

    #[test]
    fn test_sorted_unique_codec_roundtrip() {
        const CASE: [u8; 9] = [1, 2, 3, 4, 5, 6, 7, 8, 9];
        let sorted: Set<_> = CASE.try_into().unwrap();

        let mut buf = Vec::with_capacity(sorted.encode_size());
        sorted.write(&mut buf);
        let decoded =
            Set::<u8>::read_cfg(&mut buf.as_slice(), &(RangeCfg::from(0..=9), ())).unwrap();

        assert_eq!(sorted, decoded);
    }

    #[test]
    fn test_sorted_unique_display() {
        const CASE: [u8; 9] = [1, 2, 3, 4, 5, 6, 7, 8, 9];

        #[derive(Ord, PartialOrd, Eq, PartialEq)]
        struct Example(u8);
        impl fmt::Display for Example {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "ex({})", self.0)
            }
        }
        let sorted: Set<_> = Set::try_from_iter(CASE.into_iter().map(Example)).unwrap();
        assert_eq!(
            sorted.to_string(),
            "[ex(1), ex(2), ex(3), ex(4), ex(5), ex(6), ex(7), ex(8), ex(9)]"
        );
    }

    #[test]
    fn test_set_from_iter_dedup() {
        let items = [3u8, 1u8, 2u8, 2u8];
        let set = Set::from_iter_dedup(items);
        assert_eq!(set.iter().copied().collect::<Vec<_>>(), vec![1, 2, 3]);
    }

    #[test]
    fn test_set_try_from_duplicate() {
        let result: Result<Set<u8>, _> = vec![3u8, 1u8, 2u8, 2u8].try_into();
        assert_eq!(result, Err(Error::DuplicateKey));
    }

    #[test]
    fn test_set_try_from_iter_duplicate() {
        let items = vec![3u8, 1u8, 2u8, 2u8];
        let result = Set::try_from_iter(items);
        assert_eq!(result, Err(Error::DuplicateKey));
    }

    #[test]
    fn test_map_from_iter_dedup() {
        let items = vec![(3u8, "c"), (1u8, "a"), (2u8, "b"), (1u8, "duplicate")];
        let map = Map::from_iter_dedup(items);

        assert_eq!(map.len(), 3);
        assert_eq!(map.iter().copied().collect::<Vec<_>>(), vec![1, 2, 3]);
        assert_eq!(map.get_value(&1), Some(&"a"));
        assert_eq!(map.get_value(&4), None);
        assert_eq!(map.value(1), Some(&"b"));
    }

    #[test]
    fn test_map_try_from() {
        let pairs = vec![(3u8, "c"), (1u8, "a"), (2u8, "b")];
        let wrapped: Map<_, _> = pairs.try_into().unwrap();

        assert_eq!(wrapped.iter().copied().collect::<Vec<_>>(), vec![1, 2, 3]);
        assert_eq!(wrapped.get_value(&2), Some(&"b"));
    }

    #[test]
    fn test_map_try_from_duplicate() {
        let result: Result<Map<u8, &str>, _> =
            vec![(3u8, "c"), (1u8, "a"), (2u8, "b"), (1u8, "duplicate")].try_into();
        assert_eq!(result, Err(Error::DuplicateKey));
    }

    #[test]
    fn test_map_try_from_iter_duplicate() {
        let pairs = vec![(3u8, "c"), (1u8, "a"), (2u8, "b"), (1u8, "duplicate")];
        let result = Map::try_from_iter(pairs);
        assert_eq!(result, Err(Error::DuplicateKey));
    }

    #[test]
    fn test_map_deref_to_set() {
        fn sum(set: &Set<u8>) -> u32 {
            set.iter().map(|v| *v as u32).sum()
        }

        let map: Map<_, _> = vec![(2u8, "b"), (1u8, "a")].try_into().unwrap();
        assert_eq!(sum(&map), 3);
    }

    #[test]
    fn test_map_from_set() {
        let set: Set<_> = vec![(3u8, 'a'), (1u8, 'b'), (2u8, 'c')].try_into().unwrap();
        let wrapped: Map<_, _> = Map::try_from_iter(set.clone()).unwrap();

        assert_eq!(
            set.iter().map(|(k, _)| *k).collect::<Vec<_>>(),
            wrapped.keys().iter().copied().collect::<Vec<_>>(),
        );
    }

    #[test]
    fn test_map_into_keys() {
        let map: Map<_, _> = vec![(3u8, "c"), (1u8, "a"), (2u8, "b")].try_into().unwrap();
        let keys = map.into_keys();
        assert_eq!(keys.iter().copied().collect::<Vec<_>>(), vec![1, 2, 3]);
    }

    #[test]
    fn test_values_mut() {
        let mut map: Map<u8, u8> = vec![(1u8, 10u8), (2, 20)].try_into().unwrap();
        for value in map.values_mut() {
            *value += 1;
        }
        assert_eq!(map.values(), &[11, 21]);
    }

    #[test]
    fn test_map_allows_duplicate_values() {
        let items = vec![(1u8, "a"), (2u8, "b"), (3u8, "a")];
        let map: Map<_, _> = items.try_into().unwrap();
        assert_eq!(map.len(), 3);
        assert_eq!(map.get_value(&1), Some(&"a"));
        assert_eq!(map.get_value(&3), Some(&"a"));
    }

    #[test]
    fn test_bimap_duplicate_value_error() {
        let items = vec![(1u8, "a"), (2u8, "b"), (3u8, "a")];
        let result = BiMap::try_from_iter(items);
        assert_eq!(result, Err(Error::DuplicateValue));
    }

    #[test]
    fn test_bimap_no_duplicate_values() {
        let items = vec![(1u8, "a"), (2u8, "b"), (3u8, "c")];
        let result = BiMap::try_from_iter(items);
        assert!(result.is_ok());
        let map = result.unwrap();
        assert_eq!(map.len(), 3);
        assert_eq!(map.get_value(&1), Some(&"a"));
        assert_eq!(map.get_value(&2), Some(&"b"));
        assert_eq!(map.get_value(&3), Some(&"c"));
    }

    #[test]
    fn test_bimap_try_from_map() {
        let items = vec![(1u8, "a"), (2u8, "b"), (3u8, "c")];
        let map: Map<_, _> = items.try_into().unwrap();
        let bimap = BiMap::try_from(map).unwrap();
        assert_eq!(bimap.len(), 3);
        assert_eq!(bimap.get_value(&1), Some(&"a"));
    }

    #[test]
    fn test_bimap_get_key() {
        let items = vec![(1u8, "a"), (2u8, "b"), (3u8, "c")];
        let bimap: BiMap<_, _> = items.try_into().unwrap();
        assert_eq!(bimap.get_key(&"a"), Some(&1));
        assert_eq!(bimap.get_key(&"b"), Some(&2));
        assert_eq!(bimap.get_key(&"c"), Some(&3));
        assert_eq!(bimap.get_key(&"d"), None);
    }

    #[test]
    fn test_bimap_try_from_map_duplicate() {
        let items = vec![(1u8, "a"), (2u8, "b"), (3u8, "a")];
        let map: Map<_, _> = items.try_into().unwrap();
        let result = BiMap::try_from(map);
        assert_eq!(result, Err(Error::DuplicateValue));
    }

    #[test]
    fn test_bimap_decode_rejects_duplicate_values() {
        let items = vec![(1u8, 10u8), (2, 20), (3, 10)];
        let map: Map<_, _> = items.try_into().unwrap();

        let mut buf = Vec::with_capacity(map.encode_size());
        map.write(&mut buf);

        let cfg = (RangeCfg::from(0..=10), (), ());
        let result = BiMap::<u8, u8>::read_cfg(&mut buf.as_slice(), &cfg);
        assert!(result.is_err());
    }

    #[test]
    fn test_set_decode_rejects_duplicates() {
        let items: Vec<u8> = vec![1, 2, 2, 3];
        let mut buf = Vec::new();
        items.write(&mut buf);

        let cfg = (RangeCfg::from(0..=10), ());
        let result = Set::<u8>::read_cfg(&mut buf.as_slice(), &cfg);
        assert!(result.is_err());
    }

    #[test]
    fn test_set_decode_rejects_unsorted() {
        let items: Vec<u8> = vec![1, 3, 2, 4];
        let mut buf = Vec::new();
        items.write(&mut buf);

        let cfg = (RangeCfg::from(0..=10), ());
        let result = Set::<u8>::read_cfg(&mut buf.as_slice(), &cfg);
        assert!(result.is_err());
    }

    #[test]
    fn test_set_decode_accepts_valid() {
        let items: Vec<u8> = vec![1, 2, 3, 4];
        let mut buf = Vec::new();
        items.write(&mut buf);

        let cfg = (RangeCfg::from(0..=10), ());
        let result = Set::<u8>::read_cfg(&mut buf.as_slice(), &cfg);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().iter().copied().collect::<Vec<_>>(), items);
    }

    #[test]
    fn test_map_decode_rejects_duplicate_keys() {
        let keys: Vec<u8> = vec![1, 2, 2, 3];
        let values: Vec<u8> = vec![10, 20, 30, 40];
        let mut buf = Vec::new();
        keys.write(&mut buf);
        values.write(&mut buf);

        let cfg = (RangeCfg::from(0..=10), (), ());
        let result = Map::<u8, u8>::read_cfg(&mut buf.as_slice(), &cfg);
        assert!(result.is_err());
    }

    #[test]
    fn test_map_decode_rejects_unsorted_keys() {
        let keys: Vec<u8> = vec![1, 3, 2, 4];
        let values: Vec<u8> = vec![10, 20, 30, 40];
        let mut buf = Vec::new();
        keys.write(&mut buf);
        values.write(&mut buf);

        let cfg = (RangeCfg::from(0..=10), (), ());
        let result = Map::<u8, u8>::read_cfg(&mut buf.as_slice(), &cfg);
        assert!(result.is_err());
    }

    #[test]
    fn test_map_decode_accepts_valid() {
        let keys: Vec<u8> = vec![1, 2, 3, 4];
        let values: Vec<u8> = vec![10, 20, 30, 40];
        let mut buf = Vec::new();
        keys.write(&mut buf);
        values.write(&mut buf);

        let cfg = (RangeCfg::from(0..=10), (), ());
        let result = Map::<u8, u8>::read_cfg(&mut buf.as_slice(), &cfg);
        assert!(result.is_ok());
        let map = result.unwrap();
        assert_eq!(map.keys().iter().copied().collect::<Vec<_>>(), keys);
        assert_eq!(map.values(), values.as_slice());
    }
}
