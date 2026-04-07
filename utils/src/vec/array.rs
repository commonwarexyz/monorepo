//! A fixed-capacity, inline vector.
//!
//! [`ArrayVec`] stores up to `N` elements inline (no heap allocation for the
//! backing storage). Capacity is capped at `u16::MAX` to prevent accidentally
//! large inline buffers. Lengths and indices are [`usize`] to match slices
//! and [`Vec`].
//!
//! Internally uses unsafe partial-initialization (only `0..len` is
//! initialized) to avoid requiring `T: Default`. The public API is fully safe.
//!
//! # Examples
//!
//! ```
//! use commonware_utils::{array_vec, vec::ArrayVec};
//!
//! let mut buffer = ArrayVec::<u8, 4>::new();
//! buffer.push(1);
//! buffer.push(2);
//! assert_eq!(buffer.as_slice(), &[1, 2]);
//!
//! let exact = array_vec![3, 4, 5];
//! assert_eq!(exact.len(), 3);
//! assert_eq!(exact.capacity(), 3);
//!
//! let repeated = array_vec![7u8; 4];
//! assert_eq!(repeated.as_slice(), &[7, 7, 7, 7]);
//! ```
//!
//! ```compile_fail
//! use commonware_utils::array_vec;
//!
//! let n: usize = 4;
//! let _ = array_vec![0u8; n];
//! ```
//!
//! ```compile_fail
//! use commonware_utils::vec::ArrayVec;
//!
//! let _ = ArrayVec::<u8, 70_000>::new();
//! ```

use crate::TryFromIterator;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use bytes::{Buf, BufMut};
use commonware_codec::{BufsMut, EncodeSize, RangeCfg, Read, Write};
use core::{
    cmp::Ordering,
    fmt,
    hash::{Hash, Hasher},
    iter::FusedIterator,
    mem::{ManuallyDrop, MaybeUninit},
    ops::{Deref, DerefMut},
    ptr, slice,
};
use thiserror::Error;

/// Errors returned when constructing an [`ArrayVec`].
#[derive(Error, Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The source contained more elements than the inline capacity allows.
    #[error("array length exceeds ArrayVec capacity")]
    CapacityExceeded,
}

/// A fixed-capacity vector that stores up to `N` elements inline.
///
/// Capacity is capped at `u16::MAX` to prevent oversized inline buffers.
pub struct ArrayVec<T, const N: usize> {
    len: usize,
    items: [MaybeUninit<T>; N],
}

impl<T, const N: usize> ArrayVec<T, N> {
    /// The maximum supported inline capacity.
    pub const MAX_CAPACITY: usize = u16::MAX as usize;

    const ASSERT_CAPACITY: () = assert!(
        N <= Self::MAX_CAPACITY,
        "ArrayVec capacity must be <= u16::MAX"
    );

    /// Creates an empty [`ArrayVec`].
    pub const fn new() -> Self {
        let () = Self::ASSERT_CAPACITY;
        Self {
            len: 0,
            items: [const { MaybeUninit::uninit() }; N],
        }
    }

    /// Creates a full [`ArrayVec`] from a `[T; N]` array.
    pub fn from_array(items: [T; N]) -> Self {
        let () = Self::ASSERT_CAPACITY;
        Self {
            len: N,
            items: items.map(MaybeUninit::new),
        }
    }

    #[inline]
    unsafe fn push_unchecked(&mut self, value: T) {
        // SAFETY: The caller guarantees `len < N`, so the slot at `len` exists
        // and is currently uninitialized.
        unsafe {
            self.items.get_unchecked_mut(self.len).write(value);
        }

        self.len += 1;
    }

    /// Returns the number of elements.
    #[inline]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Returns `true` if the vector contains no elements.
    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Returns the inline capacity.
    #[inline]
    pub const fn capacity(&self) -> usize {
        N
    }

    /// Returns the elements as a slice.
    #[inline]
    pub const fn as_slice(&self) -> &[T] {
        // SAFETY: The `ArrayVec` invariant guarantees that exactly the prefix
        // `0..len` is initialized.
        unsafe { slice::from_raw_parts(self.items.as_ptr().cast(), self.len) }
    }

    /// Returns the elements as a mutable slice.
    #[inline]
    pub const fn as_mut_slice(&mut self) -> &mut [T] {
        // SAFETY: The `ArrayVec` invariant guarantees that exactly the prefix
        // `0..len` is initialized and uniquely borrowed here.
        unsafe { slice::from_raw_parts_mut(self.items.as_mut_ptr().cast(), self.len) }
    }

    /// Returns the first element, if any.
    #[inline]
    pub fn first(&self) -> Option<&T> {
        self.get(0)
    }

    /// Returns a mutable reference to the first element, if any.
    #[inline]
    pub fn first_mut(&mut self) -> Option<&mut T> {
        self.get_mut(0)
    }

    /// Returns the last element, if any.
    #[inline]
    pub fn last(&self) -> Option<&T> {
        self.len.checked_sub(1).and_then(|index| self.get(index))
    }

    /// Returns a mutable reference to the last element, if any.
    #[inline]
    pub fn last_mut(&mut self) -> Option<&mut T> {
        self.len
            .checked_sub(1)
            .and_then(|index| self.get_mut(index))
    }

    /// Returns a reference to the element at `index`, if in bounds.
    #[inline]
    pub fn get(&self, index: usize) -> Option<&T> {
        if index >= self.len {
            return None;
        }

        // SAFETY: Only the prefix `0..len` is initialized, and the bounds
        // check above guarantees `index < len`.
        unsafe { Some(self.items.get_unchecked(index).assume_init_ref()) }
    }

    /// Returns a mutable reference to the element at `index`, if in bounds.
    #[inline]
    pub fn get_mut(&mut self, index: usize) -> Option<&mut T> {
        if index >= self.len {
            return None;
        }

        // SAFETY: Only the prefix `0..len` is initialized, the bounds check
        // above guarantees `index < len`, and `&mut self` ensures uniqueness.
        unsafe { Some(self.items.get_unchecked_mut(index).assume_init_mut()) }
    }

    /// Pushes an element, returning `Err(value)` if the vector is full.
    #[inline]
    pub fn try_push(&mut self, value: T) -> Result<(), T> {
        if self.len == N {
            return Err(value);
        }

        // SAFETY: The vector is not full, so there is an uninitialized slot at
        // the current logical end.
        unsafe {
            self.push_unchecked(value);
        }
        Ok(())
    }

    /// Pushes an element to the back.
    ///
    /// # Panics
    ///
    /// Panics if the vector is full.
    #[inline]
    pub fn push(&mut self, value: T) {
        self.try_push(value)
            .unwrap_or_else(|_| panic!("ArrayVec::push: capacity exceeded"));
    }

    /// Inserts an element at `index`, shifting `index..len` right.
    ///
    /// Returns `Err(value)` if the vector is full.
    ///
    /// # Panics
    ///
    /// Panics if `index > len()`.
    pub fn try_insert(&mut self, index: usize, value: T) -> Result<(), T> {
        assert!(index <= self.len, "index out of bounds");

        if self.len == N {
            return Err(value);
        }

        // SAFETY: `index <= len < N`. The initialized suffix `index..len` is
        // shifted right by one slot. `ptr::copy` is correct for overlapping
        // ranges, and the destination range lies within the backing array.
        unsafe {
            let ptr = self.items.as_mut_ptr().cast::<T>();
            ptr::copy(ptr.add(index), ptr.add(index + 1), self.len - index);
            ptr::write(ptr.add(index), value);
        }

        self.len += 1;
        Ok(())
    }

    /// Inserts an element at `index`, shifting `index..len` right.
    ///
    /// # Panics
    ///
    /// Panics if `index > len()` or the vector is full.
    pub fn insert(&mut self, index: usize, value: T) {
        self.try_insert(index, value)
            .unwrap_or_else(|_| panic!("ArrayVec::insert: capacity exceeded"));
    }

    /// Extends from an iterator, returning the first rejected item on
    /// overflow. Items pushed before the overflow remain in the vector.
    pub fn try_extend<I: IntoIterator<Item = T>>(&mut self, iter: I) -> Result<(), T> {
        for item in iter {
            self.try_push(item)?;
        }
        Ok(())
    }

    /// Extends from an iterator.
    ///
    /// # Panics
    ///
    /// Panics if the iterator yields more items than the remaining capacity.
    pub fn extend<I: IntoIterator<Item = T>>(&mut self, iter: I) {
        self.try_extend(iter)
            .unwrap_or_else(|_| panic!("ArrayVec::extend: capacity exceeded"));
    }

    /// Resizes the vector to `new_len`, cloning `value` when growing.
    ///
    /// # Panics
    ///
    /// Panics if `new_len > capacity()`.
    pub fn resize(&mut self, new_len: usize, value: T)
    where
        T: Clone,
    {
        assert!(
            new_len <= N,
            "ArrayVec::resize: new length exceeds capacity"
        );

        if new_len <= self.len {
            self.truncate(new_len);
            return;
        }

        while self.len + 1 < new_len {
            // SAFETY: The assertion above guarantees `new_len <= capacity()`,
            // and the loop only runs while `len + 1 < new_len`.
            unsafe {
                self.push_unchecked(value.clone());
            }
        }

        // SAFETY: The loop above stops with exactly one slot remaining.
        unsafe {
            self.push_unchecked(value);
        }
    }

    /// Resizes the vector to `new_len`, calling `f` to create new elements.
    ///
    /// # Panics
    ///
    /// Panics if `new_len > capacity()`.
    pub fn resize_with<F>(&mut self, new_len: usize, mut f: F)
    where
        F: FnMut() -> T,
    {
        assert!(
            new_len <= N,
            "ArrayVec::resize_with: new length exceeds capacity"
        );

        if new_len <= self.len {
            self.truncate(new_len);
            return;
        }

        while self.len < new_len {
            // SAFETY: The assertion above guarantees `new_len <= capacity()`,
            // and the loop only runs while `len < new_len`.
            unsafe {
                self.push_unchecked(f());
            }
        }
    }

    /// Removes the last element and returns it, if any.
    #[inline]
    pub fn pop(&mut self) -> Option<T> {
        if self.len == 0 {
            return None;
        }

        self.len -= 1;

        // SAFETY: The slot at `self.len` was initialized before the length was
        // decreased, and it is now outside the logical prefix.
        unsafe { Some(self.items.get_unchecked(self.len).assume_init_read()) }
    }

    /// Removes the element at `index`, shifting `(index+1)..len` left.
    ///
    /// # Panics
    ///
    /// Panics if `index >= len()`.
    #[inline]
    pub fn remove(&mut self, index: usize) -> T {
        assert!(index < self.len, "index out of bounds");

        // SAFETY: `index < len`, so the element exists. The suffix
        // `(index + 1)..len` is moved one slot to the left, which is valid for
        // overlapping ranges.
        unsafe {
            let ptr = self.items.as_mut_ptr().cast::<T>();
            let value = ptr.add(index).read();
            ptr::copy(ptr.add(index + 1), ptr.add(index), self.len - index - 1);
            self.len -= 1;
            value
        }
    }

    /// Removes the element at `index` by swapping it with the last element.
    ///
    /// `O(1)` but does not preserve order.
    ///
    /// # Panics
    ///
    /// Panics if `index >= len()`.
    #[inline]
    pub fn swap_remove(&mut self, index: usize) -> T {
        assert!(index < self.len, "index out of bounds");
        let last = self.len - 1;

        // SAFETY: `index < len`, so the target element exists. When `index !=
        // last`, the last initialized element is moved into the removed slot.
        unsafe {
            let ptr = self.items.as_mut_ptr().cast::<T>();
            let value = ptr.add(index).read();
            if index != last {
                ptr.add(index).write(ptr.add(last).read());
            }
            self.len = last;
            value
        }
    }

    /// Shortens the vector to `len` elements, dropping the rest.
    #[inline]
    pub fn truncate(&mut self, len: usize) {
        let current = self.len;
        if len >= current {
            return;
        }

        // Set length first so a panicking destructor doesn't cause
        // double-drops when `ArrayVec::drop` runs during unwinding.
        self.len = len;

        // SAFETY: The range `len..current` was initialized before the length
        // was decreased.
        unsafe {
            ptr::drop_in_place(ptr::slice_from_raw_parts_mut(
                self.items.as_mut_ptr().add(len).cast::<T>(),
                current - len,
            ));
        }
    }

    /// Removes all elements.
    #[inline]
    pub fn clear(&mut self) {
        self.truncate(0);
    }

    /// Converts into a heap-allocated [`Vec`].
    pub fn into_vec(self) -> Vec<T> {
        let this = ManuallyDrop::new(self);
        let mut vec = Vec::with_capacity(this.len);

        // SAFETY: Source (`this.items`) and destination (`vec`) don't overlap.
        // Exactly `this.len` elements are initialized, and `this` is wrapped
        // in `ManuallyDrop` so the source won't be double-freed.
        unsafe {
            ptr::copy_nonoverlapping(this.items.as_ptr().cast::<T>(), vec.as_mut_ptr(), this.len);
            vec.set_len(this.len);
        }

        vec
    }
}

impl<T, const N: usize> Default for ArrayVec<T, N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T, const N: usize> Drop for ArrayVec<T, N> {
    fn drop(&mut self) {
        self.clear();
    }
}

impl<T: Clone, const N: usize> Clone for ArrayVec<T, N> {
    fn clone(&self) -> Self {
        let mut clone = Self::new();
        for item in self.iter() {
            // SAFETY: `clone` is built from `self.iter()`, so it cannot exceed
            // the original initialized length and therefore fits in `N`.
            unsafe {
                clone.push_unchecked(item.clone());
            }
        }
        clone
    }
}

impl<T: fmt::Debug, const N: usize> fmt::Debug for ArrayVec<T, N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.iter()).finish()
    }
}

impl<T: PartialEq, const N: usize, const M: usize> PartialEq<ArrayVec<T, M>> for ArrayVec<T, N> {
    fn eq(&self, other: &ArrayVec<T, M>) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl<T: Eq, const N: usize> Eq for ArrayVec<T, N> {}

impl<T: PartialOrd, const N: usize, const M: usize> PartialOrd<ArrayVec<T, M>> for ArrayVec<T, N> {
    fn partial_cmp(&self, other: &ArrayVec<T, M>) -> Option<Ordering> {
        self.as_slice().partial_cmp(other.as_slice())
    }
}

impl<T: Ord, const N: usize> Ord for ArrayVec<T, N> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.as_slice().cmp(other.as_slice())
    }
}

impl<T: Hash, const N: usize> Hash for ArrayVec<T, N> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.as_slice().hash(state);
    }
}

impl<T, const N: usize> Deref for ArrayVec<T, N> {
    type Target = [T];

    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

impl<T, const N: usize> DerefMut for ArrayVec<T, N> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.as_mut_slice()
    }
}

impl<T, const N: usize> AsRef<[T]> for ArrayVec<T, N> {
    fn as_ref(&self) -> &[T] {
        self.as_slice()
    }
}

impl<T, const N: usize> AsMut<[T]> for ArrayVec<T, N> {
    fn as_mut(&mut self) -> &mut [T] {
        self.as_mut_slice()
    }
}

impl<T, const N: usize> From<[T; N]> for ArrayVec<T, N> {
    fn from(items: [T; N]) -> Self {
        Self::from_array(items)
    }
}

impl<T, const N: usize> From<ArrayVec<T, N>> for Vec<T> {
    fn from(array: ArrayVec<T, N>) -> Self {
        array.into_vec()
    }
}

impl<T, const N: usize> TryFrom<Vec<T>> for ArrayVec<T, N> {
    type Error = Error;

    fn try_from(vec: Vec<T>) -> Result<Self, Self::Error> {
        if vec.len() > N {
            return Err(Error::CapacityExceeded);
        }

        let mut array = Self::new();
        for item in vec {
            // SAFETY: The length check above guarantees the iterator fits.
            unsafe {
                array.push_unchecked(item);
            }
        }
        Ok(array)
    }
}

impl<T: Clone, const N: usize> TryFrom<&[T]> for ArrayVec<T, N> {
    type Error = Error;

    fn try_from(slice: &[T]) -> Result<Self, Self::Error> {
        if slice.len() > N {
            return Err(Error::CapacityExceeded);
        }

        let mut array = Self::new();
        for item in slice {
            // SAFETY: The length check above guarantees the cloned slice fits.
            unsafe {
                array.push_unchecked(item.clone());
            }
        }
        Ok(array)
    }
}

impl<T: Clone, const N: usize, const M: usize> TryFrom<&[T; M]> for ArrayVec<T, N> {
    type Error = Error;

    fn try_from(array: &[T; M]) -> Result<Self, Self::Error> {
        Self::try_from(array.as_slice())
    }
}

impl<T, const N: usize> TryFromIterator<T> for ArrayVec<T, N> {
    type Error = Error;

    fn try_from_iter<I: IntoIterator<Item = T>>(iter: I) -> Result<Self, Self::Error> {
        let mut array = Self::new();
        for item in iter {
            if array.try_push(item).is_err() {
                return Err(Error::CapacityExceeded);
            }
        }
        Ok(array)
    }
}

/// Owning iterator for [`ArrayVec`].
pub struct IntoIter<T, const N: usize> {
    index: usize,
    len: usize,
    items: [MaybeUninit<T>; N],
}

impl<T, const N: usize> Iterator for IntoIter<T, N> {
    type Item = T;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index == self.len {
            return None;
        }

        let index = self.index;
        self.index += 1;

        // SAFETY: `index < len`, so this slot is initialized and has not yet
        // been yielded.
        unsafe { Some(self.items.get_unchecked(index).assume_init_read()) }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.len - self.index;
        (remaining, Some(remaining))
    }
}

impl<T, const N: usize> DoubleEndedIterator for IntoIter<T, N> {
    fn next_back(&mut self) -> Option<Self::Item> {
        if self.index == self.len {
            return None;
        }

        self.len -= 1;

        // SAFETY: After decrementing `len`, the previous tail slot is still
        // initialized and has not been yielded from the back.
        unsafe { Some(self.items.get_unchecked(self.len).assume_init_read()) }
    }
}

impl<T, const N: usize> ExactSizeIterator for IntoIter<T, N> {}
impl<T, const N: usize> FusedIterator for IntoIter<T, N> {}

impl<T, const N: usize> Drop for IntoIter<T, N> {
    fn drop(&mut self) {
        if self.index == self.len {
            return;
        }

        // SAFETY: The remaining range `index..len` is initialized and has not
        // yet been yielded.
        unsafe {
            ptr::drop_in_place(ptr::slice_from_raw_parts_mut(
                self.items.as_mut_ptr().add(self.index).cast::<T>(),
                self.len - self.index,
            ));
        }
    }
}

impl<T, const N: usize> IntoIterator for ArrayVec<T, N> {
    type Item = T;
    type IntoIter = IntoIter<T, N>;

    fn into_iter(self) -> Self::IntoIter {
        let this = ManuallyDrop::new(self);

        // SAFETY: `this` will not be dropped, so moving out the backing array is
        // sound. The iterator becomes responsible for dropping the remaining
        // initialized prefix.
        unsafe {
            IntoIter {
                index: 0,
                len: this.len,
                items: ptr::read(&this.items),
            }
        }
    }
}

impl<'a, T, const N: usize> IntoIterator for &'a ArrayVec<T, N> {
    type Item = &'a T;
    type IntoIter = core::slice::Iter<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<'a, T, const N: usize> IntoIterator for &'a mut ArrayVec<T, N> {
    type Item = &'a mut T;
    type IntoIter = core::slice::IterMut<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter_mut()
    }
}

impl<T: Write, const N: usize> Write for ArrayVec<T, N> {
    fn write(&self, buf: &mut impl BufMut) {
        self.as_slice().write(buf);
    }

    fn write_bufs(&self, buf: &mut impl BufsMut) {
        self.as_slice().write_bufs(buf);
    }
}

impl<T: EncodeSize, const N: usize> EncodeSize for ArrayVec<T, N> {
    fn encode_size(&self) -> usize {
        self.as_slice().encode_size()
    }

    fn encode_inline_size(&self) -> usize {
        self.as_slice().encode_inline_size()
    }
}

impl<T: Read, const N: usize> Read for ArrayVec<T, N> {
    type Cfg = (RangeCfg<usize>, T::Cfg);

    fn read_cfg(
        buf: &mut impl Buf,
        (range, cfg): &Self::Cfg,
    ) -> Result<Self, commonware_codec::Error> {
        let len = usize::read_cfg(buf, range)?;
        if len > N {
            return Err(commonware_codec::Error::InvalidLength(len));
        }

        let mut array = Self::new();
        for _ in 0..len {
            let item = T::read_cfg(buf, cfg)?;

            // SAFETY: The decoded length was checked against the inline
            // capacity before any elements were read.
            unsafe {
                array.push_unchecked(item);
            }
        }
        Ok(array)
    }
}

#[cfg(feature = "arbitrary")]
impl<'a, T: arbitrary::Arbitrary<'a>, const N: usize> arbitrary::Arbitrary<'a> for ArrayVec<T, N> {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let len: usize = u.int_in_range(0usize..=N)?;
        let mut array = Self::new();
        for _ in 0..len {
            // SAFETY: `len` is sampled from `0..=N`, so the generated number of
            // items always fits in the vector.
            unsafe {
                array.push_unchecked(u.arbitrary()?);
            }
        }
        Ok(array)
    }
}

/// Creates an [`ArrayVec`] whose inline capacity matches the input.
///
/// # Forms
///
/// | Syntax | Result |
/// |--------|--------|
/// | `array_vec![]` | `ArrayVec<_, 0>` |
/// | `array_vec![a, b, c]` | `ArrayVec<_, 3>` |
/// | `array_vec![elem; N]` | `ArrayVec<_, N>` filled with clones of `elem` |
///
/// The repeat form requires `N` to be a const expression because the capacity
/// is part of the resulting type.
///
/// # Examples
///
/// ```
/// use commonware_utils::{array_vec, vec::ArrayVec};
///
/// let empty: ArrayVec<u8, 0> = array_vec![];
/// assert!(empty.is_empty());
///
/// let values = array_vec![1, 2, 3];
/// assert_eq!(values.capacity(), 3);
///
/// let repeated = array_vec![9u8; 4];
/// assert_eq!(repeated.as_slice(), &[9, 9, 9, 9]);
/// ```
#[macro_export]
macro_rules! array_vec {
    () => {
        $crate::vec::ArrayVec::<_, 0>::new()
    };
    ($elem:expr; $n:expr) => {{
        const N: usize = $n;
        const _: () = assert!(
            N <= ::core::primitive::u16::MAX as usize,
            "ArrayVec capacity must be <= u16::MAX"
        );
        let mut array = $crate::vec::ArrayVec::<_, N>::new();
        array.resize(N, $elem);
        array
    }};
    ($first:expr $(, $rest:expr)* $(,)?) => {
        $crate::vec::ArrayVec::from_array([$first $(, $rest)*])
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TryCollect;
    use bytes::{buf::UninitSlice, BufMut, Bytes, BytesMut};
    use commonware_codec::{
        BufsMut, Encode, EncodeSize, Error as CodecError, RangeCfg, Read, Write,
    };
    use std::{cell::Cell, cmp::Ordering, rc::Rc};

    #[derive(Default)]
    struct TestBufs {
        inline: BytesMut,
        pushed: Vec<Bytes>,
    }

    // SAFETY: `TestBufs` forwards all `BufMut` operations to the inner
    // `BytesMut`, preserving its invariants.
    unsafe impl BufMut for TestBufs {
        fn remaining_mut(&self) -> usize {
            self.inline.remaining_mut()
        }

        fn chunk_mut(&mut self) -> &mut UninitSlice {
            self.inline.chunk_mut()
        }

        unsafe fn advance_mut(&mut self, cnt: usize) {
            // SAFETY: Forwards to the inner `BytesMut` with the same `cnt`.
            unsafe {
                self.inline.advance_mut(cnt);
            }
        }
    }

    impl BufsMut for TestBufs {
        fn push(&mut self, bytes: impl Into<Bytes>) {
            self.pushed.push(bytes.into());
        }
    }

    #[derive(Debug)]
    struct DropTracker(Rc<Cell<usize>>);

    impl Drop for DropTracker {
        fn drop(&mut self) {
            self.0.set(self.0.get() + 1);
        }
    }

    #[test]
    fn test_new() {
        const EMPTY: ArrayVec<u8, 4> = ArrayVec::new();

        assert_eq!(EMPTY.len(), 0);
        assert_eq!(EMPTY.capacity(), 4);
        assert!(EMPTY.is_empty());
        assert_eq!(EMPTY.capacity() - EMPTY.len(), 4);
    }

    #[test]
    fn test_default_and_rejected_element() {
        let mut values = ArrayVec::<u8, 3>::default();
        assert_eq!(values.capacity() - values.len(), 3);

        assert_eq!(values.try_push(1), Ok(()));
        assert_eq!(values.try_push(2), Ok(()));
        assert_eq!(values.try_push(3), Ok(()));
        assert_eq!(values.capacity() - values.len(), 0);
        assert_eq!(values.len(), values.capacity());

        let error = values.try_push(9).unwrap_err();
        assert_eq!(error, 9);

        values.truncate(2);
        assert_eq!(values.capacity() - values.len(), 1);

        values.clear();
        assert_eq!(values.capacity() - values.len(), 3);

        let values = ArrayVec::from_array([1u8, 2, 3]);
        assert_eq!(&*values, &[1, 2, 3]);
        assert_eq!(format!("{values:?}"), "[1, 2, 3]");
    }

    #[test]
    fn test_from_array() {
        let values = ArrayVec::from_array([1, 2, 3]);
        assert_eq!(values.len(), 3);
        assert_eq!(values.capacity(), 3);
        assert_eq!(values.as_slice(), &[1, 2, 3]);
        assert_eq!(values.capacity() - values.len(), 0);
    }

    #[test]
    fn test_macro() {
        let values = array_vec![1, 2, 3];
        assert_eq!(values.len(), 3);
        assert_eq!(values.capacity(), 3);
        assert_eq!(values.as_slice(), &[1, 2, 3]);

        let trailing = array_vec![1, 2, 3,];
        assert_eq!(trailing.as_slice(), &[1, 2, 3]);

        let repeated = array_vec![7u8; 4];
        assert_eq!(repeated.len(), 4);
        assert_eq!(repeated.capacity(), 4);
        assert_eq!(repeated.as_slice(), &[7, 7, 7, 7]);
    }

    #[test]
    fn test_try_from_vec() {
        let values: ArrayVec<i32, 4> = vec![1, 2, 3].try_into().unwrap();
        assert_eq!(values.as_slice(), &[1, 2, 3]);

        let exact: ArrayVec<i32, 2> = vec![1, 2].try_into().unwrap();
        assert_eq!(exact.as_slice(), &[1, 2]);

        let error: Result<ArrayVec<i32, 2>, _> = vec![1, 2, 3].try_into();
        assert_eq!(error, Err(Error::CapacityExceeded));

        let error: Result<ArrayVec<i32, 4>, _> = vec![1, 2, 3, 4, 5].try_into();
        assert_eq!(error, Err(Error::CapacityExceeded));
    }

    #[test]
    fn test_try_from_slice() {
        let values: ArrayVec<i32, 4> = [1, 2, 3].as_slice().try_into().unwrap();
        assert_eq!(values.as_slice(), &[1, 2, 3]);

        let exact: ArrayVec<i32, 2> = [1, 2].as_slice().try_into().unwrap();
        assert_eq!(exact.as_slice(), &[1, 2]);

        let error: Result<ArrayVec<i32, 2>, _> = [1, 2, 3].as_slice().try_into();
        assert_eq!(error, Err(Error::CapacityExceeded));

        let error: Result<ArrayVec<i32, 3>, _> = [1, 2, 3, 4].as_slice().try_into();
        assert_eq!(error, Err(Error::CapacityExceeded));

        let error: Result<ArrayVec<i32, 4>, _> = [1, 2, 3, 4, 5].as_slice().try_into();
        assert_eq!(error, Err(Error::CapacityExceeded));

        let error: Result<ArrayVec<u8, 8>, _> = [0u8; 9].as_slice().try_into();
        assert_eq!(error, Err(Error::CapacityExceeded));

        let bytes = vec![Bytes::from_static(b"x"); 9];
        let error: Result<ArrayVec<Bytes, 8>, _> = bytes.as_slice().try_into();
        assert_eq!(error, Err(Error::CapacityExceeded));
    }

    #[test]
    fn test_try_from_array_ref() {
        let values: ArrayVec<i32, 4> = (&[1, 2, 3]).try_into().unwrap();
        assert_eq!(values.as_slice(), &[1, 2, 3]);
    }

    #[test]
    fn test_try_from_iterator() {
        let values: ArrayVec<i32, 4> = (1..=3).try_collect().unwrap();
        assert_eq!(values.as_slice(), &[1, 2, 3]);

        let exact: ArrayVec<i32, 2> = (1..=2).try_collect().unwrap();
        assert_eq!(exact.as_slice(), &[1, 2]);

        let error: Result<ArrayVec<i32, 2>, _> = (1..=3).try_collect();
        assert_eq!(error, Err(Error::CapacityExceeded));

        let error: Result<ArrayVec<i32, 4>, _> = (1..=5).try_collect();
        assert_eq!(error, Err(Error::CapacityExceeded));
    }

    #[test]
    fn test_first_last_get() {
        let mut values = array_vec![1, 2, 3];

        assert_eq!(values.first(), Some(&1));
        assert_eq!(values.last(), Some(&3));
        assert_eq!(values.get(1), Some(&2));
        assert_eq!(values.get(99), None);

        *values.first_mut().unwrap() = 10;
        *values.last_mut().unwrap() = 30;
        *values.get_mut(1).unwrap() = 20;
        assert_eq!(values.as_slice(), &[10, 20, 30]);
    }

    #[test]
    fn test_push_and_try_push() {
        let mut values = ArrayVec::<i32, 2>::new();
        assert_eq!(values.try_push(1), Ok(()));
        assert_eq!(values.try_push(2), Ok(()));
        assert_eq!(values.try_push(3), Err(3));
        assert_eq!(values.as_slice(), &[1, 2]);
        values.truncate(2);
        assert_eq!(values.as_slice(), &[1, 2]);
    }

    #[test]
    #[should_panic(expected = "ArrayVec::push: capacity exceeded")]
    fn test_push_panics_when_full() {
        let mut values = ArrayVec::<i32, 1>::new();
        values.push(1);
        values.push(2);
    }

    #[test]
    fn test_insert_and_try_insert() {
        let mut values = ArrayVec::<i32, 4>::new();
        assert_eq!(values.try_push(1), Ok(()));
        assert_eq!(values.try_push(3), Ok(()));
        assert_eq!(values.try_insert(1, 2), Ok(()));
        assert_eq!(values.as_slice(), &[1, 2, 3]);

        assert_eq!(values.try_push(4), Ok(()));
        assert_eq!(values.try_insert(2, 9), Err(9));
        assert_eq!(values.as_slice(), &[1, 2, 3, 4]);

        let mut single = ArrayVec::<u8, 1>::new();
        assert_eq!(single.try_insert(0, 7), Ok(()));
        single.truncate(1);
        assert_eq!(single.as_slice(), &[7]);
    }

    #[test]
    #[should_panic(expected = "ArrayVec::insert: capacity exceeded")]
    fn test_insert_panics_when_full() {
        let mut values: ArrayVec<u8, 1> = [1].into();
        values.insert(1, 2);
    }

    #[test]
    fn test_extend_and_try_extend() {
        let mut values = ArrayVec::<i32, 4>::new();
        assert_eq!(values.try_extend([1, 2, 3]), Ok(()));
        assert_eq!(values.as_slice(), &[1, 2, 3]);

        let mut exact = ArrayVec::<i32, 4>::new();
        assert_eq!(exact.try_extend([1, 2]), Ok(()));
        assert_eq!(exact.as_slice(), &[1, 2]);

        let mut single = ArrayVec::<i32, 1>::new();
        assert_eq!(single.try_extend([1]), Ok(()));
        assert_eq!(single.as_slice(), &[1]);

        let error = values.try_extend([4, 5]);
        assert_eq!(error, Err(5));
        assert_eq!(values.as_slice(), &[1, 2, 3, 4]);
    }

    #[test]
    #[should_panic(expected = "ArrayVec::extend: capacity exceeded")]
    fn test_extend_panics_when_full() {
        let mut values = ArrayVec::<i32, 1>::new();
        values.extend([1, 2]);
    }

    #[test]
    fn test_resize() {
        let mut values = ArrayVec::<i32, 5>::new();
        values.resize(3, 7);
        assert_eq!(values.as_slice(), &[7, 7, 7]);

        values.resize(1, 9);
        assert_eq!(values.as_slice(), &[7]);
        values.truncate(1);
        assert_eq!(values.as_slice(), &[7]);

        let mut single = ArrayVec::<i32, 1>::new();
        single.resize(1, 9);
        assert_eq!(single.as_slice(), &[9]);

        let mut repeated = array_vec![7u8; 4];
        repeated.resize(2, 9);
        assert_eq!(repeated.as_slice(), &[7, 7]);
    }

    #[test]
    fn test_resize_with() {
        let mut next = 0;
        let mut values = ArrayVec::<i32, 4>::new();
        let mut fill = || {
            next += 1;
            next * 10
        };
        values.resize_with(3, &mut fill);
        assert_eq!(values.as_slice(), &[10, 20, 30]);

        values.resize_with(1, &mut fill);
        assert_eq!(values.as_slice(), &[10]);
    }

    #[test]
    #[should_panic(expected = "ArrayVec::resize: new length exceeds capacity")]
    fn test_resize_panics_when_too_large() {
        let mut values = ArrayVec::<i32, 1>::new();
        values.resize(2, 1);
    }

    #[test]
    fn test_pop() {
        let mut values = array_vec![1, 2, 3];
        assert_eq!(values.pop(), Some(3));
        assert_eq!(values.pop(), Some(2));
        assert_eq!(values.pop(), Some(1));
        assert_eq!(values.pop(), None);
    }

    #[test]
    fn test_remove() {
        let mut values = array_vec![1, 2, 3, 4];
        assert_eq!(values.remove(1), 2);
        assert_eq!(values.as_slice(), &[1, 3, 4]);
        assert_eq!(values.remove(2), 4);
        assert_eq!(values.as_slice(), &[1, 3]);
    }

    #[test]
    fn test_swap_remove() {
        let mut values = array_vec![1, 2, 3, 4];
        assert_eq!(values.swap_remove(1), 2);
        assert_eq!(values.as_slice(), &[1, 4, 3]);

        assert_eq!(values.swap_remove(2), 3);
        assert_eq!(values.as_slice(), &[1, 4]);
    }

    #[test]
    fn test_truncate_and_clear() {
        let mut values = array_vec![1, 2, 3, 4];
        values.truncate(2);
        assert_eq!(values.as_slice(), &[1, 2]);

        values.clear();
        assert!(values.is_empty());
    }

    #[test]
    fn test_deref_and_deref_mut() {
        let mut values = array_vec![3, 1, 2];
        values.sort();
        assert_eq!(&*values, &[1, 2, 3]);

        values.reverse();
        assert_eq!(values[0], 3);
        assert_eq!(values.as_slice(), &[3, 2, 1]);
    }

    #[test]
    fn test_clone_debug_eq_hash() {
        use std::collections::hash_map::DefaultHasher;

        let values = array_vec![1, 2, 3];
        let cloned = values.clone();
        assert_eq!(values, cloned);
        assert_eq!(format!("{values:?}"), "[1, 2, 3]");

        let mut left = DefaultHasher::new();
        values.hash(&mut left);
        let mut right = DefaultHasher::new();
        cloned.hash(&mut right);
        assert_eq!(left.finish(), right.finish());
    }

    #[test]
    fn test_from_impl_and_ordering() {
        let left: ArrayVec<i32, 2> = [1, 2].into();
        let same: ArrayVec<i32, 2> = [1, 2].into();
        let greater: ArrayVec<i32, 2> = [1, 3].into();
        let wider: ArrayVec<i32, 3> = [1, 3].as_slice().try_into().unwrap();

        assert_eq!(left, same);
        assert_eq!(&*left, &[1, 2]);
        assert_eq!(format!("{left:?}"), "[1, 2]");
        assert_eq!(left.partial_cmp(&wider), Some(Ordering::Less));
        assert_eq!(left.cmp(&greater), Ordering::Less);
    }

    #[test]
    fn test_into_vec_and_from_impl() {
        let values = array_vec![1, 2, 3];
        let vec = values.into_vec();
        assert_eq!(vec, vec![1, 2, 3]);

        let values = array_vec![4, 5, 6];
        let vec: Vec<_> = values.into();
        assert_eq!(vec, vec![4, 5, 6]);
    }

    #[test]
    fn test_iterators() {
        let values = array_vec![1, 2, 3];
        let borrowed: Vec<_> = (&values).into_iter().copied().collect();
        assert_eq!(borrowed, vec![1, 2, 3]);

        let mut values = array_vec![1, 2, 3];
        for value in &mut values {
            *value *= 2;
        }
        assert_eq!(values.as_slice(), &[2, 4, 6]);

        let values = array_vec![1, 2, 3];
        let owned: Vec<_> = values.into_iter().collect();
        assert_eq!(owned, vec![1, 2, 3]);

        let values = array_vec![1, 2, 3];
        let reversed: Vec<_> = values.into_iter().rev().collect();
        assert_eq!(reversed, vec![3, 2, 1]);

        let mut partial = array_vec![1, 2, 3].into_iter();
        assert_eq!(partial.next(), Some(1));
        drop(partial);
    }

    #[test]
    fn test_into_iter_drop_drops_unyielded_items() {
        let drops = Rc::new(Cell::new(0));
        let values = ArrayVec::from_array([
            DropTracker(drops.clone()),
            DropTracker(drops.clone()),
            DropTracker(drops.clone()),
        ]);
        let mut iter = values.into_iter();

        assert_eq!(iter.size_hint(), (3, Some(3)));
        drop(iter.next());
        assert_eq!(drops.get(), 1);
        assert_eq!(iter.size_hint(), (2, Some(2)));

        drop(iter);
        assert_eq!(drops.get(), 3);

        let drops = Rc::new(Cell::new(0));
        let values = ArrayVec::from_array([
            DropTracker(drops.clone()),
            DropTracker(drops.clone()),
            DropTracker(drops.clone()),
        ]);
        let mut iter = values.into_iter();
        drop(iter.next());
        drop(iter.next());
        drop(iter.next());
        assert!(iter.next().is_none());
        drop(iter);
        assert_eq!(drops.get(), 3);
    }

    #[test]
    fn test_drop_tracker_truncate_clear_and_drop() {
        let drops = Rc::new(Cell::new(0));

        {
            let mut values = ArrayVec::from_array([
                DropTracker(drops.clone()),
                DropTracker(drops.clone()),
                DropTracker(drops.clone()),
            ]);

            values.truncate(1);
            assert_eq!(drops.get(), 2);

            values.clear();
            assert_eq!(drops.get(), 3);
        }

        assert_eq!(drops.get(), 3);
    }

    #[test]
    fn test_codec_roundtrip() {
        let mut values: ArrayVec<u8, 8> = [1, 2, 3].as_slice().try_into().unwrap();
        values.truncate(3);

        let mut buf = Vec::with_capacity(values.encode_size());
        values.write(&mut buf);

        let decoded =
            ArrayVec::<u8, 8>::read_cfg(&mut buf.as_slice(), &(RangeCfg::from(..=8), ())).unwrap();
        assert_eq!(values, decoded);

        let encoded = vec![4u8, 5, 6].encode();
        let decoded =
            ArrayVec::<u8, 3>::read_cfg(&mut encoded.as_ref(), &(RangeCfg::from(..=3), ()))
                .unwrap();
        assert_eq!(decoded.as_slice(), &[4, 5, 6]);
    }

    #[test]
    fn test_codec_helpers() {
        let values: ArrayVec<u8, 8> = [1, 2, 3].as_slice().try_into().unwrap();
        assert_eq!(values.encode_inline_size(), values.encode_size());
        assert_eq!(&*values, &[1, 2, 3]);
        assert_eq!(format!("{values:?}"), "[1, 2, 3]");

        let bytes_values: ArrayVec<Bytes, 8> =
            [Bytes::from_static(b"ab"), Bytes::from_static(b"c")]
                .as_slice()
                .try_into()
                .unwrap();
        let mut bytes_values = bytes_values;
        bytes_values.truncate(2);
        let mut buf = TestBufs::default();

        bytes_values.write_bufs(&mut buf);

        assert_eq!(buf.inline.len(), bytes_values.encode_inline_size());
        assert_eq!(
            buf.inline.len() + buf.pushed.iter().map(Bytes::len).sum::<usize>(),
            bytes_values.encode_size()
        );
        assert_eq!(
            buf.pushed,
            vec![Bytes::from_static(b"ab"), Bytes::from_static(b"c")]
        );
    }

    #[test]
    fn test_codec_rejects_length_above_capacity() {
        let encoded = vec![1u8, 2, 3, 4].encode();
        let result = ArrayVec::<u8, 3>::read_cfg(&mut encoded.as_ref(), &(RangeCfg::from(..), ()));
        assert_eq!(
            result.unwrap_err().to_string(),
            CodecError::InvalidLength(4).to_string()
        );

        let encoded = vec![0u8; 9].encode();
        let result = ArrayVec::<u8, 8>::read_cfg(&mut encoded.as_ref(), &(RangeCfg::from(..), ()));
        assert_eq!(
            result.unwrap_err().to_string(),
            CodecError::InvalidLength(9).to_string()
        );
    }

    #[test]
    fn test_codec_rejects_truncated_length_prefix() {
        let result = ArrayVec::<u8, 3>::read_cfg(&mut [].as_slice(), &(RangeCfg::from(..), ()));
        assert_eq!(
            result.unwrap_err().to_string(),
            CodecError::EndOfBuffer.to_string()
        );
    }

    #[test]
    fn test_codec_rejects_truncated_item() {
        let encoded = 1usize.encode();
        let result = ArrayVec::<u8, 3>::read_cfg(&mut encoded.as_ref(), &(RangeCfg::from(..), ()));
        assert_eq!(
            result.unwrap_err().to_string(),
            CodecError::EndOfBuffer.to_string()
        );
    }

    #[test]
    fn test_as_ref_as_mut() {
        let mut values = array_vec![1, 2, 3];

        let slice: &[i32] = values.as_ref();
        assert_eq!(slice, &[1, 2, 3]);

        let slice_mut: &mut [i32] = values.as_mut();
        slice_mut[0] = 9;
        assert_eq!(values.as_slice(), &[9, 2, 3]);
    }
}
