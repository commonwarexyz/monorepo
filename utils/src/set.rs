//! [`Vec<T>`] wrapper that guarantees the contained items are sorted and deduplicated upon construction.

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, RangeCfg, Read, Write};
use core::{
    fmt,
    iter::FusedIterator,
    ops::{Index, Range},
};

/// A wrapper around a [`Vec<T>`] that guarantees the contained items are sorted and deduplicated
/// upon construction.
///
/// After construction, the contained [Vec] is sealed and cannot be modified. To unseal the
/// inner [Vec], use the [`Into<Vec<T>>`] impl.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Ordered<T>(Vec<T>);

impl<T> Ordered<T> {
    /// Constructs a new [Ordered] array from an iterator, sorting and deduplicating the items
    /// using the mapped key.
    pub fn new_by_key<K: Ord>(items: impl IntoIterator<Item = T>, f: impl Fn(&T) -> &K) -> Self {
        let mut items: Vec<_> = items.into_iter().collect();
        items.sort_by(|l, r| f(l).cmp(f(r)));
        items.dedup_by(|l, r| f(l) == f(r));
        Self(items)
    }

    /// Returns the size of the [Ordered].
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns true if the [Ordered] is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns an item by index, if it exists.
    pub fn get(&self, index: usize) -> Option<&T> {
        self.0.get(index)
    }

    /// Returns the position of a given item in the [Ordered], if it exists.
    pub fn position(&self, item: &T) -> Option<usize>
    where
        T: Ord,
    {
        self.0.binary_search(item).ok()
    }

    /// Returns an iterator over the items in the set.
    pub fn iter(&self) -> core::slice::Iter<'_, T> {
        self.into_iter()
    }
}

impl<K: Ord, V> Ordered<(K, V)> {
    /// Constructs a new [Ordered] set from `(key, value)` tuples, sorting and deduplicating entries
    /// by the `key` component.
    pub fn new_by_first(items: impl IntoIterator<Item = (K, V)>) -> Self {
        Self::new_by_key(items, |(key, _)| key)
    }
}

/// Abstraction over ordered key sets, allowing multiple backing stores (e.g. tuples) to expose the
/// same interface without copying keys.
pub trait OrderedKeySet<K: Ord> {
    /// Iterator type that yields references to ordered keys.
    type Iter<'a>: Iterator<Item = &'a K> + DoubleEndedIterator + ExactSizeIterator + FusedIterator
    where
        Self: 'a,
        K: 'a;

    /// Returns the size of the set.
    fn len(&self) -> usize;

    /// Returns true if the set is empty.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns the key at the provided index, if it exists.
    fn get(&self, index: usize) -> Option<&K>;

    /// Returns the position of `key`, if present.
    fn position(&self, key: &K) -> Option<usize>;

    /// Returns an iterator over the ordered keys.
    fn iter(&self) -> Self::Iter<'_>;

    /// Returns the first key, if present.
    fn first(&self) -> Option<&K> {
        self.get(0)
    }

    /// Returns the last key, if present.
    fn last(&self) -> Option<&K> {
        if self.is_empty() {
            None
        } else {
            self.get(self.len() - 1)
        }
    }
}

impl<K: Ord> OrderedKeySet<K> for Ordered<K> {
    type Iter<'a>
        = core::slice::Iter<'a, K>
    where
        K: 'a;

    fn len(&self) -> usize {
        Ordered::<K>::len(self)
    }

    fn get(&self, index: usize) -> Option<&K> {
        Ordered::<K>::get(self, index)
    }

    fn position(&self, key: &K) -> Option<usize> {
        Ordered::<K>::position(self, key)
    }

    fn iter(&self) -> Self::Iter<'_> {
        Ordered::<K>::iter(self)
    }
}

impl<K: Ord, V> OrderedKeySet<K> for Ordered<(K, V)> {
    type Iter<'a>
        = TupleKeyIter<'a, K, V>
    where
        K: 'a,
        V: 'a;

    fn len(&self) -> usize {
        Ordered::<(K, V)>::len(self)
    }

    fn get(&self, index: usize) -> Option<&K> {
        Ordered::<(K, V)>::get(self, index).map(|(key, _)| key)
    }

    fn position(&self, key: &K) -> Option<usize> {
        self.0
            .binary_search_by(|(candidate, _)| candidate.cmp(key))
            .ok()
    }

    fn iter(&self) -> Self::Iter<'_> {
        TupleKeyIter {
            inner: self.0.iter(),
        }
    }
}

/// Iterator over the first element of `(key, value)` tuples.
#[derive(Clone)]
pub struct TupleKeyIter<'a, K, V> {
    inner: core::slice::Iter<'a, (K, V)>,
}

impl<'a, K, V> Iterator for TupleKeyIter<'a, K, V> {
    type Item = &'a K;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().map(|(key, _)| key)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}

impl<'a, K, V> DoubleEndedIterator for TupleKeyIter<'a, K, V> {
    fn next_back(&mut self) -> Option<Self::Item> {
        self.inner.next_back().map(|(key, _)| key)
    }
}

impl<'a, K, V> ExactSizeIterator for TupleKeyIter<'a, K, V> {
    fn len(&self) -> usize {
        self.inner.len()
    }
}

impl<'a, K, V> FusedIterator for TupleKeyIter<'a, K, V> {}

impl<'a, T, K> OrderedKeySet<K> for &'a T
where
    K: Ord,
    T: OrderedKeySet<K> + ?Sized,
{
    type Iter<'b>
        = T::Iter<'b>
    where
        Self: 'b,
        T: 'b,
        K: 'b;

    fn len(&self) -> usize {
        (**self).len()
    }

    fn get(&self, index: usize) -> Option<&K> {
        (**self).get(index)
    }

    fn position(&self, key: &K) -> Option<usize> {
        (**self).position(key)
    }

    fn iter(&self) -> Self::Iter<'_> {
        (**self).iter()
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

impl<T> IntoIterator for Ordered<T> {
    type Item = T;
    #[cfg(not(feature = "std"))]
    type IntoIter = alloc::vec::IntoIter<T>;
    #[cfg(feature = "std")]
    type IntoIter = std::vec::IntoIter<T>;

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
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> Result<(), fmt::Error> {
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

        struct Example(u8);
        let examples = CASE.into_iter().map(Example).collect::<Vec<_>>();
        let sorted_examples = Ordered::new_by_key(examples, |e| &e.0);
        assert_eq!(
            sorted_examples.iter().map(|e| e.0).collect::<Vec<_>>(),
            EXPECTED
        );
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
    fn test_tuple_key_set() {
        let ordered =
            Ordered::new_by_first([(2u8, "two"), (1, "one"), (3, "three"), (2, "duplicate two")]);

        assert_eq!(ordered.len(), 3);
        assert_eq!(OrderedKeySet::<u8>::position(&ordered, &1), Some(0));
        assert_eq!(OrderedKeySet::<u8>::position(&ordered, &3), Some(2));
        assert_eq!(OrderedKeySet::<u8>::get(&ordered, 0), Some(&1));
        assert_eq!(OrderedKeySet::<u8>::last(&ordered), Some(&3));

        let keys: Vec<u8> = OrderedKeySet::<u8>::iter(&ordered).copied().collect();
        assert_eq!(keys, vec![1, 2, 3]);
    }
}
