//! Codec implementations for common types

use crate::{Error, Read};
use ::bytes::Buf;
use core::cmp::Ordering;

pub mod btree_map;
pub mod btree_set;
pub mod bytes;
#[cfg(feature = "std")]
pub mod hash_map;
#[cfg(feature = "std")]
pub mod hash_set;
pub mod lazy;
#[cfg(feature = "std")]
pub mod net;
pub mod primitives;
pub mod range;
pub mod tuple;
pub mod vec;

/// Read keyed items from [Buf] in ascending order.
pub(crate) fn read_ordered_map<K, V, F>(
    buf: &mut impl Buf,
    len: usize,
    k_cfg: &K::Cfg,
    v_cfg: &V::Cfg,
    mut insert: F,
    map_type: &'static str,
) -> Result<(), Error>
where
    K: Read + Ord,
    V: Read,
    F: FnMut(K, V) -> Option<V>,
{
    let mut last: Option<(K, V)> = None;
    for _ in 0..len {
        // Read key
        let key = K::read_cfg(buf, k_cfg)?;

        // Check if keys are in ascending order relative to the previous key
        if let Some((ref last_key, _)) = last {
            match key.cmp(last_key) {
                Ordering::Equal => return Err(Error::Invalid(map_type, "Duplicate key")),
                Ordering::Less => return Err(Error::Invalid(map_type, "Keys must ascend")),
                _ => {}
            }
        }

        // Read value
        let value = V::read_cfg(buf, v_cfg)?;

        // Add previous item, if exists
        if let Some((last_key, last_value)) = last.take() {
            insert(last_key, last_value);
        }
        last = Some((key, value));
    }

    // Add last item, if exists
    if let Some((last_key, last_value)) = last {
        insert(last_key, last_value);
    }

    Ok(())
}

/// Read items from [Buf] in ascending order.
pub(crate) fn read_ordered_set<K, F>(
    buf: &mut impl Buf,
    len: usize,
    cfg: &K::Cfg,
    mut insert: F,
    set_type: &'static str,
) -> Result<(), Error>
where
    K: Read + Ord,
    F: FnMut(K) -> bool,
{
    let mut last: Option<K> = None;
    for _ in 0..len {
        // Read item
        let item = K::read_cfg(buf, cfg)?;

        // Check if items are in ascending order
        if let Some(ref last) = last {
            match item.cmp(last) {
                Ordering::Equal => return Err(Error::Invalid(set_type, "Duplicate item")),
                Ordering::Less => return Err(Error::Invalid(set_type, "Items must ascend")),
                _ => {}
            }
        }

        // Add previous item, if exists
        if let Some(last) = last.take() {
            insert(last);
        }
        last = Some(item);
    }

    // Add last item, if exists
    if let Some(last) = last {
        insert(last);
    }

    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use crate::{BufsMut, Error, Read, Write};
    use bytes::{buf::UninitSlice, Buf, BufMut, Bytes, BytesMut};

    /// One-byte test type that uses the default aggregate hooks.
    ///
    /// This lets tests distinguish the generic per-element path from the
    /// specialized `u8` path while keeping the same encoded representation.
    #[derive(Debug, PartialEq, Eq)]
    pub struct Byte(pub u8);

    impl Write for Byte {
        fn write(&self, buf: &mut impl BufMut) {
            buf.put_u8(self.0);
        }
    }

    impl Read for Byte {
        type Cfg = ();

        fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, Error> {
            Ok(Self(<u8 as Read>::read_cfg(buf, &())?))
        }
    }

    /// Test [`BufMut`] implementation that records how values are written.
    ///
    /// Specialization-selection tests use this to assert whether a container
    /// wrote its payload with one aggregate [`BufMut::put_slice`] call or with
    /// per-element [`BufMut::put_u8`] calls.
    pub struct TrackingWriteBuf {
        inner: BytesMut,
        /// Number of aggregate slice writes.
        pub put_slice_calls: usize,
        /// Number of single-byte writes.
        pub put_u8_calls: usize,
        /// Number of externally pushed chunks.
        pub push_calls: usize,
    }

    impl TrackingWriteBuf {
        pub fn new() -> Self {
            Self {
                inner: BytesMut::new(),
                put_slice_calls: 0,
                put_u8_calls: 0,
                push_calls: 0,
            }
        }

        pub fn freeze(self) -> Bytes {
            self.inner.freeze()
        }
    }

    // SAFETY: `TrackingWriteBuf` delegates storage and cursor management to
    // `BytesMut`, which upholds the `BufMut` invariants. The overridden write
    // methods only count calls before forwarding.
    unsafe impl BufMut for TrackingWriteBuf {
        fn remaining_mut(&self) -> usize {
            self.inner.remaining_mut()
        }

        fn chunk_mut(&mut self) -> &mut UninitSlice {
            self.inner.chunk_mut()
        }

        unsafe fn advance_mut(&mut self, cnt: usize) {
            // SAFETY: The caller guarantees that `cnt` bytes in the current
            // chunk were initialized. `BytesMut` owns the cursor state and
            // enforces the remaining invariants.
            unsafe { self.inner.advance_mut(cnt) }
        }

        fn put_slice(&mut self, src: &[u8]) {
            self.put_slice_calls += 1;
            self.inner.put_slice(src);
        }

        fn put_u8(&mut self, n: u8) {
            self.put_u8_calls += 1;
            self.inner.put_u8(n);
        }
    }

    impl BufsMut for TrackingWriteBuf {
        fn push(&mut self, bytes: impl Into<Bytes>) {
            let bytes = bytes.into();
            self.push_calls += 1;
            self.inner.extend_from_slice(&bytes);
        }
    }

    /// Test [`Buf`] implementation that records how values are read.
    ///
    /// Specialization-selection tests use this to assert whether a container
    /// read its payload with one aggregate [`Buf::copy_to_slice`] call or with
    /// per-element [`Buf::get_u8`] calls.
    pub struct TrackingReadBuf {
        inner: Bytes,
        /// Number of aggregate slice reads.
        pub copy_to_slice_calls: usize,
        /// Number of single-byte reads.
        pub get_u8_calls: usize,
    }

    impl TrackingReadBuf {
        pub fn new(bytes: &'static [u8]) -> Self {
            Self {
                inner: Bytes::from_static(bytes),
                copy_to_slice_calls: 0,
                get_u8_calls: 0,
            }
        }
    }

    impl Buf for TrackingReadBuf {
        fn remaining(&self) -> usize {
            self.inner.remaining()
        }

        fn chunk(&self) -> &[u8] {
            self.inner.chunk()
        }

        fn advance(&mut self, cnt: usize) {
            self.inner.advance(cnt)
        }

        fn copy_to_slice(&mut self, dst: &mut [u8]) {
            self.copy_to_slice_calls += 1;
            self.inner.copy_to_slice(dst);
        }

        fn get_u8(&mut self) -> u8 {
            self.get_u8_calls += 1;
            self.inner.get_u8()
        }
    }
}
