//! Ordered collections that guarantee sorted, deduplicated keys.

#[cfg(not(feature = "std"))]
use alloc::{collections::BTreeSet, vec::Vec};
use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, RangeCfg, Read, Write};
use core::{
    fmt,
    ops::{Deref, Index, Range},
};
#[cfg(feature = "std")]
use std::collections::BTreeSet;
use thiserror::Error;

#[cfg(not(feature = "std"))]
type VecIntoIter<T> = alloc::vec::IntoIter<T>;
#[cfg(feature = "std")]
type VecIntoIter<T> = std::vec::IntoIter<T>;

/// Errors that can occur when constructing [`OrderedAssociatedUnique`].
#[derive(Error, Debug, PartialEq, Eq)]
pub enum Error {
    /// A value was duplicated across different keys.
    #[error("duplicate value across keys")]
    DuplicateValue,
}

/// An ordered, deduplicated slice of items.
///
/// After construction, the contained [`Vec<T>`] is sealed and cannot be modified. To unseal the
/// inner [`Vec<T>`], use the [`Into<Vec<T>>`] impl.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Ordered<T>(Vec<T>);

impl<T> Ordered<T> {
    /// Returns the size of the ordered collection.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns `true` if the collection is empty.
    pub fn is_empty(&self) -> bool {
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

impl<T: Write> Write for Ordered<T> {
    fn write(&self, buf: &mut impl BufMut) {
        self.0.write(buf);
    }
}

impl<T: EncodeSize> EncodeSize for Ordered<T> {
    fn encode_size(&self) -> usize {
        self.0.encode_size()
    }
}

impl<T: Read> Read for Ordered<T> {
    type Cfg = (RangeCfg<usize>, T::Cfg);

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
        Ok(Self(Vec::<T>::read_cfg(buf, cfg)?))
    }
}

impl<T: Ord> FromIterator<T> for Ordered<T> {
    fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> Self {
        let items: Vec<_> = iter.into_iter().collect();
        items.into()
    }
}

impl<T: Ord> From<Vec<T>> for Ordered<T> {
    fn from(mut items: Vec<T>) -> Self {
        items.sort();
        items.dedup();
        Self(items)
    }
}

impl<T: Ord + Clone> From<&[T]> for Ordered<T> {
    fn from(items: &[T]) -> Self {
        items.iter().cloned().collect()
    }
}

impl<T: Ord, const N: usize> From<[T; N]> for Ordered<T> {
    fn from(items: [T; N]) -> Self {
        items.into_iter().collect()
    }
}

impl<T: Ord + Clone, const N: usize> From<&[T; N]> for Ordered<T> {
    fn from(items: &[T; N]) -> Self {
        items.as_slice().into()
    }
}

impl<T> IntoIterator for Ordered<T> {
    type Item = T;
    type IntoIter = VecIntoIter<T>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'a, T> IntoIterator for &'a Ordered<T> {
    type Item = &'a T;
    type IntoIter = core::slice::Iter<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl<T> Index<usize> for Ordered<T> {
    type Output = T;

    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index]
    }
}

impl<T> Index<Range<usize>> for Ordered<T> {
    type Output = [T];

    fn index(&self, index: Range<usize>) -> &Self::Output {
        &self.0[index]
    }
}

impl<T> AsRef<[T]> for Ordered<T> {
    fn as_ref(&self) -> &[T] {
        &self.0
    }
}

impl<T: fmt::Display> fmt::Display for Ordered<T> {
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

impl<T: Ord> From<Ordered<T>> for Vec<T> {
    fn from(set: Ordered<T>) -> Self {
        set.0
    }
}

/// An ordered, deduplicated slice of items each paired with some associated value.
///
/// Like [`Ordered`], the contained [`Vec<(K, V)>`] is sealed after construction and cannot be modified. To unseal the
/// inner [`Vec<(K, V)>`], use the [`Into<Vec<(K, V)>>`] impl.
///
/// Consumers that only need the ordered keys can treat an [`OrderedAssociated`] as an
/// [`Ordered`] through deref coercions.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct OrderedAssociated<K, V> {
    keys: Ordered<K>,
    values: Vec<V>,
}

impl<K, V> OrderedAssociated<K, V> {
    /// Returns the number of entries in the map.
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Returns `true` if the map is empty.
    pub fn is_empty(&self) -> bool {
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

    /// Returns the ordered keys as an [`Ordered`] reference.
    pub fn keys(&self) -> &Ordered<K> {
        &self.keys
    }

    /// Consumes the map and returns the ordered keys.
    pub fn into_keys(self) -> Ordered<K> {
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

    /// Returns the associated values.
    pub fn values(&self) -> &[V] {
        &self.values
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

impl<K: fmt::Debug, V: fmt::Debug> fmt::Debug for OrderedAssociated<K, V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("OrderedAssociated")
            .field(&self.iter_pairs().collect::<Vec<_>>())
            .finish()
    }
}

impl<K, V> AsRef<[K]> for OrderedAssociated<K, V> {
    fn as_ref(&self) -> &[K] {
        self.keys.as_ref()
    }
}

impl<K, V> AsRef<Ordered<K>> for OrderedAssociated<K, V> {
    fn as_ref(&self) -> &Ordered<K> {
        &self.keys
    }
}

impl<K, V> Deref for OrderedAssociated<K, V> {
    type Target = Ordered<K>;

    fn deref(&self) -> &Self::Target {
        &self.keys
    }
}

impl<K: Ord, V> FromIterator<(K, V)> for OrderedAssociated<K, V> {
    fn from_iter<I: IntoIterator<Item = (K, V)>>(iter: I) -> Self {
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
            keys: Ordered(keys),
            values,
        }
    }
}

impl<K: Ord + Clone, V: Clone> From<&[(K, V)]> for OrderedAssociated<K, V> {
    fn from(items: &[(K, V)]) -> Self {
        items.iter().cloned().collect()
    }
}

impl<K: Ord, V> From<Vec<(K, V)>> for OrderedAssociated<K, V> {
    fn from(items: Vec<(K, V)>) -> Self {
        items.into_iter().collect()
    }
}

impl<K: Ord, V, const N: usize> From<[(K, V); N]> for OrderedAssociated<K, V> {
    fn from(items: [(K, V); N]) -> Self {
        items.into_iter().collect()
    }
}

impl<K: Ord + Clone, V: Clone, const N: usize> From<&[(K, V); N]> for OrderedAssociated<K, V> {
    fn from(items: &[(K, V); N]) -> Self {
        items.as_slice().into()
    }
}

impl<K: Ord, V> From<OrderedAssociated<K, V>> for Vec<(K, V)> {
    fn from(wrapped: OrderedAssociated<K, V>) -> Self {
        wrapped.into_iter().collect()
    }
}

impl<K: Write, V: Write> Write for OrderedAssociated<K, V> {
    fn write(&self, buf: &mut impl BufMut) {
        self.keys.write(buf);
        self.values.write(buf);
    }
}

impl<K: EncodeSize, V: EncodeSize> EncodeSize for OrderedAssociated<K, V> {
    fn encode_size(&self) -> usize {
        self.keys.encode_size() + self.values.encode_size()
    }
}

impl<K: Read, V: Read> Read for OrderedAssociated<K, V> {
    type Cfg = (RangeCfg<usize>, K::Cfg, V::Cfg);

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
        let (range_cfg, key_cfg, value_cfg) = cfg;
        let keys = Ordered::<K>::read_cfg(buf, &(*range_cfg, key_cfg.clone()))?;
        let values = Vec::<V>::read_cfg(buf, &(RangeCfg::exact(keys.len()), value_cfg.clone()))?;
        Ok(Self { keys, values })
    }
}

impl<K, V> IntoIterator for OrderedAssociated<K, V> {
    type Item = (K, V);
    type IntoIter = OrderedAssociatedIntoIter<K, V>;

    fn into_iter(self) -> Self::IntoIter {
        OrderedAssociatedIntoIter {
            keys: self.keys.into_iter(),
            values: self.values.into_iter(),
        }
    }
}

impl<'a, K, V> IntoIterator for &'a OrderedAssociated<K, V> {
    type Item = (&'a K, &'a V);
    type IntoIter = core::iter::Zip<core::slice::Iter<'a, K>, core::slice::Iter<'a, V>>;

    fn into_iter(self) -> Self::IntoIter {
        self.keys.iter().zip(self.values.iter())
    }
}

/// Owned iterator over [`OrderedAssociated`].
pub struct OrderedAssociatedIntoIter<K, V> {
    keys: VecIntoIter<K>,
    values: VecIntoIter<V>,
}

impl<K, V> Iterator for OrderedAssociatedIntoIter<K, V> {
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

impl<K, V> ExactSizeIterator for OrderedAssociatedIntoIter<K, V> {}

impl<K, V> DoubleEndedIterator for OrderedAssociatedIntoIter<K, V> {
    fn next_back(&mut self) -> Option<Self::Item> {
        let key = self.keys.next_back()?;
        let value = self.values.next_back()?;
        Some((key, value))
    }
}

/// An ordered, deduplicated slice of items each paired with some associated value, where values must be unique.
///
/// Like [`OrderedAssociated`], but enforces that values are unique across all keys. The contained
/// [`Vec<(K, V)>`] is sealed after construction and cannot be modified. To unseal the inner
/// [`Vec<(K, V)>`], use the [`Into<Vec<(K, V)>>`] impl.
///
/// Consumers that only need the ordered keys can treat an [`OrderedAssociatedUnique`] as an
/// [`Ordered`] through deref coercions.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct OrderedAssociatedUnique<K, V> {
    inner: OrderedAssociated<K, V>,
}

impl<K, V> OrderedAssociatedUnique<K, V> {
    /// Returns the number of entries in the map.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Returns `true` if the map is empty.
    pub fn is_empty(&self) -> bool {
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

    /// Returns the ordered keys as an [`Ordered`] reference.
    pub fn keys(&self) -> &Ordered<K> {
        self.inner.keys()
    }

    /// Consumes the map and returns the ordered keys.
    pub fn into_keys(self) -> Ordered<K> {
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

    /// Attempts to create an [`OrderedAssociatedUnique`] from an [`OrderedAssociated`].
    ///
    /// Returns an error if any value is duplicated across different keys.
    pub fn try_from_associated(map: OrderedAssociated<K, V>) -> Result<Self, Error>
    where
        V: Ord,
    {
        let mut seen = BTreeSet::new();
        for value in &map.values {
            if !seen.insert(value) {
                return Err(Error::DuplicateValue);
            }
        }
        Ok(Self { inner: map })
    }

    /// Attempts to create an [`OrderedAssociatedUnique`] from an iterator of key-value pairs.
    ///
    /// Returns an error if any value is duplicated across different keys.
    pub fn try_from_iter<I: IntoIterator<Item = (K, V)>>(iter: I) -> Result<Self, Error>
    where
        K: Ord,
        V: Ord,
    {
        let map: OrderedAssociated<K, V> = iter.into_iter().collect();
        Self::try_from_associated(map)
    }
}

impl<K: fmt::Debug, V: fmt::Debug> fmt::Debug for OrderedAssociatedUnique<K, V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("OrderedAssociatedUnique")
            .field(&self.inner.iter_pairs().collect::<Vec<_>>())
            .finish()
    }
}

impl<K, V> AsRef<[K]> for OrderedAssociatedUnique<K, V> {
    fn as_ref(&self) -> &[K] {
        self.inner.as_ref()
    }
}

impl<K, V> AsRef<Ordered<K>> for OrderedAssociatedUnique<K, V> {
    fn as_ref(&self) -> &Ordered<K> {
        self.inner.as_ref()
    }
}

impl<K, V> Deref for OrderedAssociatedUnique<K, V> {
    type Target = Ordered<K>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<K: Ord, V: Ord> FromIterator<(K, V)> for OrderedAssociatedUnique<K, V> {
    fn from_iter<I: IntoIterator<Item = (K, V)>>(iter: I) -> Self {
        Self::try_from_iter(iter)
            .expect("duplicate value detected during OrderedAssociatedUnique construction")
    }
}

impl<K: Ord + Clone, V: Clone + Ord> From<&[(K, V)]> for OrderedAssociatedUnique<K, V> {
    fn from(items: &[(K, V)]) -> Self {
        items.iter().cloned().collect()
    }
}

impl<K: Ord, V: Ord> From<Vec<(K, V)>> for OrderedAssociatedUnique<K, V> {
    fn from(items: Vec<(K, V)>) -> Self {
        items.into_iter().collect()
    }
}

impl<K: Ord, V: Ord, const N: usize> From<[(K, V); N]> for OrderedAssociatedUnique<K, V> {
    fn from(items: [(K, V); N]) -> Self {
        items.into_iter().collect()
    }
}

impl<K: Ord + Clone, V: Clone + Ord, const N: usize> From<&[(K, V); N]>
    for OrderedAssociatedUnique<K, V>
{
    fn from(items: &[(K, V); N]) -> Self {
        items.as_slice().into()
    }
}

impl<K: Ord, V> From<OrderedAssociatedUnique<K, V>> for Vec<(K, V)> {
    fn from(wrapped: OrderedAssociatedUnique<K, V>) -> Self {
        wrapped.inner.into()
    }
}

impl<K: Write, V: Write> Write for OrderedAssociatedUnique<K, V> {
    fn write(&self, buf: &mut impl BufMut) {
        self.inner.write(buf);
    }
}

impl<K: EncodeSize, V: EncodeSize> EncodeSize for OrderedAssociatedUnique<K, V> {
    fn encode_size(&self) -> usize {
        self.inner.encode_size()
    }
}

impl<K: Read, V: Read> Read for OrderedAssociatedUnique<K, V> {
    type Cfg = (RangeCfg<usize>, K::Cfg, V::Cfg);

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
        let inner = OrderedAssociated::<K, V>::read_cfg(buf, cfg)?;
        Ok(Self { inner })
    }
}

impl<K, V> IntoIterator for OrderedAssociatedUnique<K, V> {
    type Item = (K, V);
    type IntoIter = OrderedAssociatedIntoIter<K, V>;

    fn into_iter(self) -> Self::IntoIter {
        self.inner.into_iter()
    }
}

impl<'a, K, V> IntoIterator for &'a OrderedAssociatedUnique<K, V> {
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

        let sorted: Ordered<_> = CASE.into_iter().collect();
        assert_eq!(sorted.iter().copied().collect::<Vec<_>>(), EXPECTED);

        let unsealed: Vec<_> = sorted.into();
        assert_eq!(unsealed, EXPECTED);
    }

    #[test]
    fn test_sorted_unique_codec_roundtrip() {
        const CASE: [u8; 9] = [1, 2, 3, 4, 5, 6, 7, 8, 9];
        let sorted: Ordered<_> = CASE.into_iter().collect();

        let mut buf = Vec::with_capacity(sorted.encode_size());
        sorted.write(&mut buf);
        let decoded =
            Ordered::<u8>::read_cfg(&mut buf.as_slice(), &(RangeCfg::from(0..=9), ())).unwrap();

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
        let examples = CASE.into_iter().map(Example).collect::<Vec<_>>();

        let sorted: Ordered<_> = examples.into_iter().collect();
        assert_eq!(
            sorted.to_string(),
            "[ex(1), ex(2), ex(3), ex(4), ex(5), ex(6), ex(7), ex(8), ex(9)]"
        );
    }

    #[test]
    fn test_ordered_from_slice() {
        let items = [3u8, 1u8, 2u8, 2u8];
        let ordered = Ordered::from(&items[..]);
        assert_eq!(ordered.iter().copied().collect::<Vec<_>>(), vec![1, 2, 3]);
    }

    #[test]
    fn test_ordered_from_iterator() {
        let items = [3u8, 1u8, 2u8, 2u8];
        let ordered = items.iter().copied().collect::<Ordered<_>>();
        assert_eq!(ordered.iter().copied().collect::<Vec<_>>(), vec![1, 2, 3]);
    }

    #[test]
    fn test_ordered_map_dedup_and_access() {
        let items = vec![(3u8, "c"), (1u8, "a"), (2u8, "b"), (1u8, "duplicate")];

        let map: OrderedAssociated<_, _> = items.into_iter().collect();

        assert_eq!(map.len(), 3);
        assert_eq!(map.iter().copied().collect::<Vec<_>>(), vec![1, 2, 3]);
        assert_eq!(map.get_value(&1), Some(&"a"));
        assert_eq!(map.get_value(&4), None);
        assert_eq!(map.value(1), Some(&"b"));
    }

    #[test]
    fn test_ordered_wrapped_from_slice() {
        let pairs = [(3u8, "c"), (1u8, "a"), (2u8, "b")];
        let wrapped = OrderedAssociated::from(&pairs[..]);

        assert_eq!(wrapped.iter().copied().collect::<Vec<_>>(), vec![1, 2, 3]);
        assert_eq!(wrapped.get_value(&2), Some(&"b"));
    }

    #[test]
    fn test_ordered_wrapped_from_iterator() {
        let pairs = [(3u8, "c"), (1u8, "a"), (2u8, "b")];
        let wrapped = pairs
            .iter()
            .map(|(k, v)| (*k, *v))
            .collect::<OrderedAssociated<_, _>>();

        assert_eq!(wrapped.iter().copied().collect::<Vec<_>>(), vec![1, 2, 3]);
        assert_eq!(wrapped.get_value(&1), Some(&"a"));
    }

    #[test]
    fn test_ordered_map_deref_to_ordered() {
        fn sum(set: &Ordered<u8>) -> u32 {
            set.iter().map(|v| *v as u32).sum()
        }

        let map: OrderedAssociated<_, _> = vec![(2u8, "b"), (1u8, "a")].into_iter().collect();
        assert_eq!(sum(&map), 3);
    }

    #[test]
    fn test_ordered_map_from_ordered() {
        let ordered: Ordered<_> = vec![(3u8, 'a'), (1u8, 'b'), (2u8, 'c')]
            .into_iter()
            .collect();
        let wrapped: OrderedAssociated<_, _> = ordered.clone().into_iter().collect();

        assert_eq!(
            ordered.iter().map(|(k, _)| *k).collect::<Vec<_>>(),
            wrapped.keys().iter().copied().collect::<Vec<_>>(),
        );
    }

    #[test]
    fn test_ordered_map_into_keys() {
        let map: OrderedAssociated<_, _> = vec![(3u8, "c"), (1u8, "a"), (2u8, "b")]
            .into_iter()
            .collect();
        let keys = map.into_keys();
        assert_eq!(keys.iter().copied().collect::<Vec<_>>(), vec![1, 2, 3]);
    }

    #[test]
    fn test_ordered_map_allows_duplicate_values() {
        let items = vec![(1u8, "a"), (2u8, "b"), (3u8, "a")];
        let map: OrderedAssociated<_, _> = items.into_iter().collect();
        assert_eq!(map.len(), 3);
        assert_eq!(map.get_value(&1), Some(&"a"));
        assert_eq!(map.get_value(&3), Some(&"a"));
    }

    #[test]
    #[should_panic(expected = "duplicate value detected")]
    fn test_ordered_unique_duplicate_value_panic() {
        let items = vec![(1u8, "a"), (2u8, "b"), (3u8, "a")];
        let _map: OrderedAssociatedUnique<_, _> = items.into_iter().collect();
    }

    #[test]
    fn test_ordered_unique_duplicate_value_error() {
        let items = vec![(1u8, "a"), (2u8, "b"), (3u8, "a")];
        let result = OrderedAssociatedUnique::try_from_iter(items);
        assert_eq!(result, Err(Error::DuplicateValue));
    }

    #[test]
    fn test_ordered_unique_no_duplicate_values() {
        let items = vec![(1u8, "a"), (2u8, "b"), (3u8, "c")];
        let result = OrderedAssociatedUnique::try_from_iter(items);
        assert!(result.is_ok());
        let map = result.unwrap();
        assert_eq!(map.len(), 3);
        assert_eq!(map.get_value(&1), Some(&"a"));
        assert_eq!(map.get_value(&2), Some(&"b"));
        assert_eq!(map.get_value(&3), Some(&"c"));
    }

    #[test]
    fn test_ordered_unique_from_associated() {
        let items = vec![(1u8, "a"), (2u8, "b"), (3u8, "c")];
        let associated: OrderedAssociated<_, _> = items.into_iter().collect();
        let unique = OrderedAssociatedUnique::try_from_associated(associated).unwrap();
        assert_eq!(unique.len(), 3);
        assert_eq!(unique.get_value(&1), Some(&"a"));
    }

    #[test]
    fn test_ordered_unique_from_associated_duplicate() {
        let items = vec![(1u8, "a"), (2u8, "b"), (3u8, "a")];
        let associated: OrderedAssociated<_, _> = items.into_iter().collect();
        let result = OrderedAssociatedUnique::try_from_associated(associated);
        assert_eq!(result, Err(Error::DuplicateValue));
    }
}
