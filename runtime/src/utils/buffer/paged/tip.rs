use crate::{BufferPool, IoBufMut, IoBufs};
use bytes::BufMut;
use commonware_codec::{FixedSize, Write};

/// Append-only buffering for the page-oriented writer.
///
/// Complete allocations are frozen into `prefix`. The uniquely owned `tail` begins at a page
/// boundary and is the only allocation that can be mutated. Prefix chunks and the writable part
/// of the tail are restricted to whole pages, so extension never copies initialized prefix bytes.
pub(super) struct Buffer {
    prefix: IoBufs,
    tail: IoBufMut,
    len: usize,
    pub(super) offset: u64,
    pub(super) capacity: usize,
    page_size: usize,
    pool: BufferPool,
}

impl Buffer {
    /// Creates a buffer seeded with less than one page of existing logical data.
    pub(super) fn from(
        offset: u64,
        data: &[u8],
        capacity: usize,
        page_size: usize,
        pool: BufferPool,
    ) -> Self {
        assert!(page_size > 0, "page size must be non-zero");
        assert!(
            capacity.is_multiple_of(page_size),
            "buffer capacity must be page-aligned"
        );
        assert!(
            data.len() < page_size,
            "seed data must be less than one page"
        );

        let mut tail = Self::allocate_page(&pool, page_size, data.len());
        tail.put_slice(data);
        Self {
            prefix: IoBufs::default(),
            tail,
            len: data.len(),
            offset,
            capacity,
            page_size,
            pool,
        }
    }

    /// Returns the current logical size of the blob including buffered data.
    pub(super) const fn size(&self) -> u64 {
        self.offset
            .checked_add(self.len as u64)
            .expect("buffer size overflow")
    }

    /// Returns the number of buffered logical bytes.
    pub(super) const fn len(&self) -> usize {
        self.len
    }

    /// Returns whether no logical bytes are buffered.
    pub(super) const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Returns the immutable prefix owners and initialized mutable tail bytes.
    pub(super) fn parts(&self) -> (&IoBufs, &[u8]) {
        (&self.prefix, self.tail.as_ref())
    }

    /// Appends borrowed bytes and reports whether the logical flush guide was exceeded.
    pub(super) fn append(&mut self, data: &[u8]) -> bool {
        let end = self
            .len
            .checked_add(data.len())
            .expect("buffer length overflow");
        let spare = self.tail_spare();
        if data.len() <= spare {
            let mut dst = (&mut self.tail).limit(data.len());
            dst.put_slice(data);
            self.len = end;
            return end > self.capacity;
        }

        let mut next = self.allocate_growth(data.len(), spare);
        {
            let mut dst = (&mut self.tail)
                .limit(spare)
                .chain_mut(&mut next)
                .limit(data.len());
            dst.put_slice(data);
        }
        self.retire_tail(next, end);
        end > self.capacity
    }

    /// Encodes one fixed-size value directly across the current and next allocations.
    pub(super) fn append_value<T: FixedSize + Write>(&mut self, value: &T) {
        let end = self
            .len
            .checked_add(T::SIZE)
            .expect("buffer length overflow");
        let spare = self.tail_spare();
        if T::SIZE <= spare {
            let mut dst = (&mut self.tail).limit(T::SIZE);
            value.write(&mut dst);
            assert_eq!(dst.remaining_mut(), 0, "encoded size must match FixedSize");
            self.len = end;
            return;
        }

        let mut next = self.allocate_growth(T::SIZE, spare);
        {
            let mut dst = (&mut self.tail)
                .limit(spare)
                .chain_mut(&mut next)
                .limit(T::SIZE);
            value.write(&mut dst);
            assert_eq!(dst.remaining_mut(), 0, "encoded size must match FixedSize");
        }
        self.retire_tail(next, end);
    }

    /// Transfers every full logical page and retains at most one detached partial page.
    pub(super) fn drain_full_pages(&mut self) -> IoBufs {
        let full_len = self.len / self.page_size * self.page_size;
        if full_len == 0 {
            return IoBufs::default();
        }

        let partial_len = self.tail.len() % self.page_size;
        let tail_full_len = self.tail.len() - partial_len;
        let mut retained = Self::allocate_page(&self.pool, self.page_size, partial_len);
        if partial_len > 0 {
            retained.put_slice(&self.tail.as_ref()[tail_full_len..]);
        }

        let mut drained = std::mem::take(&mut self.prefix);
        let mut old_tail = std::mem::replace(&mut self.tail, retained);
        old_tail.truncate(tail_full_len);
        drained.append(old_tail.freeze());

        debug_assert_eq!(drained.len(), full_len);
        debug_assert!(
            drained
                .iter()
                .all(|chunk| chunk.len().is_multiple_of(self.page_size))
        );
        self.len = partial_len;
        self.offset = self
            .offset
            .checked_add(full_len as u64)
            .expect("buffer offset overflow");
        drained
    }

    /// Replaces the buffered partial page and detaches all prior backing.
    pub(super) fn replace(&mut self, offset: u64, data: &[u8]) {
        assert!(
            data.len() < self.page_size,
            "replacement data must be less than one page"
        );
        let mut tail = Self::allocate_page(&self.pool, self.page_size, data.len());
        tail.put_slice(data);
        self.prefix = IoBufs::default();
        self.tail = tail;
        self.len = data.len();
        self.offset = offset;
    }

    /// Clears buffered bytes and detaches their backing while preserving the logical offset.
    pub(super) fn clear(&mut self) {
        self.prefix = IoBufs::default();
        self.tail = IoBufMut::default();
        self.len = 0;
    }

    /// Allocates a page without allowing sparse pool classes or aligned fallbacks to retain a
    /// larger owner. An exact eligible class is reused when available.
    fn allocate_page(pool: &BufferPool, page_size: usize, needed: usize) -> IoBufMut {
        if needed == 0 {
            return IoBufMut::default();
        }
        let config = pool.config();
        let has_exact_eligible_class = page_size >= config.pool_min_size()
            && config
                .class_for(page_size)
                .is_some_and(|class| class.size.get() == page_size);
        if has_exact_eligible_class {
            pool.try_alloc(page_size)
                .unwrap_or_else(|_| IoBufMut::with_capacity(page_size))
        } else {
            IoBufMut::with_capacity(page_size)
        }
    }

    /// Returns writable space in the whole-page portion of the current allocation.
    const fn tail_spare(&self) -> usize {
        let usable = self.tail.capacity() / self.page_size * self.page_size;
        usable
            .checked_sub(self.tail.len())
            .expect("tail length must fit its page-aligned capacity")
    }

    /// Allocates a geometrically sized, page-aligned logical extension.
    fn allocate_growth(&self, additional: usize, spare: usize) -> IoBufMut {
        debug_assert!(additional > spare);
        let filled = self.len.checked_add(spare).expect("buffer growth overflow");
        debug_assert!(filled.is_multiple_of(self.page_size));
        let needed = additional - spare;
        let remaining_guide = self.capacity.saturating_sub(filled);
        let base = self.page_size.max(filled.min(remaining_guide));
        let target = needed.max(base);
        let remainder = target % self.page_size;
        let request = if remainder == 0 {
            target
        } else {
            target
                .checked_add(self.page_size - remainder)
                .expect("buffer growth overflow")
        };
        if request == self.page_size {
            Self::allocate_page(&self.pool, self.page_size, request)
        } else {
            self.pool.alloc(request)
        }
    }

    /// Freezes a completed page-aligned tail and installs the new unique tail.
    fn retire_tail(&mut self, next: IoBufMut, len: usize) {
        let old = std::mem::replace(&mut self.tail, next).freeze();
        debug_assert!(old.len().is_multiple_of(self.page_size));
        self.prefix.append(old);
        self.len = len;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BufferPoolConfig, telemetry::metrics::Registry};
    use commonware_utils::{NZU32, NZUsize};

    fn test_pool() -> BufferPool {
        BufferPool::new(
            BufferPoolConfig::for_storage().with_thread_cache_disabled(),
            &mut Registry::default(),
        )
    }

    fn growth_pool() -> BufferPool {
        BufferPool::new(
            BufferPoolConfig::for_storage()
                .with_size_classes([
                    (NZUsize!(8), NZU32!(4)),
                    (NZUsize!(16), NZU32!(4)),
                    (NZUsize!(32), NZU32!(4)),
                    (NZUsize!(64), NZU32!(4)),
                    (NZUsize!(128), NZU32!(4)),
                ])
                .with_pool_min_size(0)
                .with_thread_cache_disabled(),
            &mut Registry::default(),
        )
    }

    fn native_growth_pool() -> BufferPool {
        BufferPool::new(
            BufferPoolConfig::for_storage()
                .with_size_classes([(NZUsize!(8), NZU32!(4))])
                .with_pool_min_size(0)
                .with_alignment(NZUsize!(1))
                .with_thread_cache_disabled(),
            &mut Registry::default(),
        )
    }

    fn contents(buffer: &Buffer) -> Vec<u8> {
        let (prefix, tail) = buffer.parts();
        prefix
            .iter()
            .flat_map(|chunk| chunk.as_ref().iter().copied())
            .chain(tail.iter().copied())
            .collect()
    }

    #[test]
    fn extension_preserves_prior_allocation_pointers() {
        for pool in [growth_pool(), native_growth_pool()] {
            let mut buffer = Buffer::from(0, &[], 512, 8, pool);
            let mut prior = Vec::new();
            for (len, byte) in [(8, 1), (8, 2), (16, 3), (32, 4), (64, 5)] {
                assert!(!buffer.append(&vec![byte; len]));
                let (prefix, tail) = buffer.parts();
                let current = prefix
                    .iter()
                    .map(|chunk| chunk.as_ref().as_ptr() as usize)
                    .chain(std::iter::once(tail.as_ptr() as usize))
                    .collect::<Vec<_>>();
                assert_eq!(&current[..prior.len()], prior.as_slice());
                prior = current;
            }
            assert_eq!(
                buffer
                    .parts()
                    .0
                    .iter()
                    .map(|chunk| chunk.len())
                    .collect::<Vec<_>>(),
                [8, 8, 16, 32]
            );
            assert_eq!(
                contents(&buffer),
                [
                    vec![1; 8],
                    vec![2; 8],
                    vec![3; 16],
                    vec![4; 32],
                    vec![5; 64]
                ]
                .concat()
            );
            assert_eq!(buffer.len(), 128);
        }
    }

    struct Pattern<const N: usize>(u8);

    impl<const N: usize> FixedSize for Pattern<N> {
        const SIZE: usize = N;
    }

    impl<const N: usize> Write for Pattern<N> {
        fn write(&self, buf: &mut impl BufMut) {
            buf.put_bytes(self.0, N);
        }
    }

    #[test]
    fn typed_append_crosses_allocations_and_pages() {
        let mut buffer = Buffer::from(10, &[], 64, 8, test_pool());
        assert!(!buffer.append(&[1; 7]));
        let tail_ptr = buffer.parts().1.as_ptr();
        buffer.append_value(&Pattern::<18>(2));
        assert_eq!(buffer.parts().0.chunk_at(0).unwrap().as_ptr(), tail_ptr);
        assert_eq!(contents(&buffer), [vec![1; 7], vec![2; 18]].concat());
        assert_eq!(buffer.size(), 35);

        let drained = buffer.drain_full_pages();
        assert_eq!(drained.len(), 24);
        assert_eq!(
            drained.iter().map(|chunk| chunk.len()).collect::<Vec<_>>(),
            [8, 16]
        );
        assert_eq!(buffer.parts().1, &[2]);
        assert_eq!(buffer.offset, 34);
    }

    #[test]
    fn zero_size_typed_append_stays_detached() {
        let mut buffer = Buffer::from(7, &[], 16, 8, test_pool());
        buffer.append_value(&Pattern::<0>(9));
        assert!(buffer.is_empty());
        assert_eq!(buffer.size(), 7);
        assert_eq!(buffer.tail.capacity(), 0);
        assert!(buffer.prefix.is_empty());
    }

    struct IncorrectSize(usize);

    impl FixedSize for IncorrectSize {
        const SIZE: usize = 8;
    }

    impl Write for IncorrectSize {
        fn write(&self, buf: &mut impl BufMut) {
            buf.put_bytes(0, self.0);
        }
    }

    #[test]
    #[should_panic(expected = "encoded size must match FixedSize")]
    fn typed_append_rejects_short_encoding() {
        let mut buffer = Buffer::from(0, &[], 32, 8, test_pool());
        buffer.append_value(&IncorrectSize(7));
    }

    #[test]
    #[should_panic]
    fn typed_append_rejects_long_encoding() {
        let mut buffer = Buffer::from(0, &[], 32, 8, test_pool());
        buffer.append_value(&IncorrectSize(9));
    }

    #[test]
    fn drain_keeps_chunks_and_detaches_mutable_suffix() {
        let pool = BufferPool::new(
            BufferPoolConfig::for_storage()
                .with_size_classes([(NZUsize!(64), NZU32!(8)), (NZUsize!(128), NZU32!(8))])
                .with_pool_min_size(0)
                .with_thread_cache_disabled(),
            &mut Registry::default(),
        );
        let mut buffer = Buffer::from(0, &[], 512, 8, pool);
        for len in [8, 8, 56, 8] {
            buffer.append(&vec![len as u8; len]);
        }
        buffer.append(&[99]);
        let sparse_tail_ptr = buffer.tail.as_ref().as_ptr();

        let drained = buffer.drain_full_pages();
        assert_eq!(
            drained.iter().map(|chunk| chunk.len()).collect::<Vec<_>>(),
            [8, 8, 64]
        );
        assert_eq!(buffer.parts().1, &[99]);
        assert_eq!(buffer.tail.capacity(), 8);
        assert_ne!(buffer.tail.as_ref().as_ptr(), sparse_tail_ptr);

        let before = drained
            .iter()
            .flat_map(|chunk| chunk.as_ref().iter().copied())
            .collect::<Vec<_>>();
        buffer.append(&[100, 101]);
        assert_eq!(
            drained
                .iter()
                .flat_map(|chunk| chunk.as_ref().iter().copied())
                .collect::<Vec<_>>(),
            before
        );
        assert_eq!(buffer.parts().1, &[99, 100, 101]);
    }

    #[test]
    fn exhausted_page_class_falls_back_to_exact_backing() {
        let pool = BufferPool::new(
            BufferPoolConfig::for_storage()
                .with_size_classes([(NZUsize!(8), NZU32!(1))])
                .with_pool_min_size(0)
                .with_thread_cache_disabled(),
            &mut Registry::default(),
        );
        let lease = pool.try_alloc(8).unwrap();
        let mut buffer = Buffer::from(0, &[1], 16, 8, pool);
        assert_eq!(buffer.tail.capacity(), 8);
        assert!(!buffer.tail.is_pooled());
        drop(lease);

        buffer.append(&[2; 15]);
        let drained = buffer.drain_full_pages();
        assert_eq!(drained.len(), 16);
        assert!(buffer.is_empty());
        assert_eq!(buffer.tail.capacity(), 0);
    }

    #[test]
    fn replace_and_clear_detach_prior_owners() {
        let mut buffer = Buffer::from(4, &[1, 2], 18, 3, test_pool());
        buffer.append(&[3, 4, 5, 6]);
        let old = buffer.drain_full_pages();
        assert_eq!(old.len(), 6);

        buffer.replace(20, &[7, 8]);
        assert_eq!(contents(&buffer), [7, 8]);
        assert_eq!(buffer.size(), 22);
        assert_eq!(
            old.iter()
                .flat_map(|chunk| chunk.as_ref().iter().copied())
                .collect::<Vec<_>>(),
            [1, 2, 3, 4, 5, 6]
        );

        buffer.clear();
        assert!(buffer.is_empty());
        assert_eq!(buffer.offset, 20);
        assert_eq!(buffer.tail.capacity(), 0);
    }

    #[test]
    fn page_geometry_handles_one_and_non_power_of_two() {
        let mut single = Buffer::from(0, &[], 4, 1, test_pool());
        single.append(&[1, 2, 3]);
        assert_eq!(single.drain_full_pages().len(), 3);
        assert!(single.is_empty());

        let mut odd = Buffer::from(0, &[1, 2], 309, 103, test_pool());
        odd.append(&vec![3; 205]);
        assert_eq!(odd.drain_full_pages().len(), 206);
        assert_eq!(odd.parts().1, &[3]);

        let max_page = u16::MAX as usize;
        let mut max = Buffer::from(0, &[], max_page * 2, max_page, test_pool());
        max.append(&[4, 5, 6]);
        assert_eq!(max.parts().1, &[4, 5, 6]);
        assert_eq!(max.tail.capacity(), max_page);
    }

    #[test]
    #[should_panic(expected = "page size must be non-zero")]
    fn zero_page_size_is_rejected() {
        let _ = Buffer::from(0, &[], 0, 0, test_pool());
    }

    #[test]
    #[should_panic(expected = "buffer capacity must be page-aligned")]
    fn misaligned_capacity_is_rejected() {
        let _ = Buffer::from(0, &[], 17, 8, test_pool());
    }
}
