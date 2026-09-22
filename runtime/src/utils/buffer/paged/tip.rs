use crate::{BufferPool, IoBufMut, IoBufs};
use bytes::BufMut;
use commonware_codec::{FixedSize, Write};

/// Append-only buffering for the page-oriented writer.
///
/// The immutable `prefix` contains complete logical pages. The uniquely owned `tail` follows it
/// and can contain a final partial page. Writable capacity is restricted to whole pages, so a full
/// tail can join the prefix without copying bytes.
pub(super) struct Buffer {
    /// Frozen chunks, each containing a whole number of logical pages.
    prefix: IoBufs,
    /// The only mutable allocation, immediately following the prefix.
    tail: IoBufMut,
    /// Combined logical length of the prefix and tail, independent of backing capacity.
    len: usize,
    /// Logical blob offset of the first buffered byte.
    pub(super) offset: u64,
    /// Logical flush threshold. Backing is allocated as bytes arrive.
    pub(super) capacity: usize,
    /// Logical payload bytes per page, excluding on-disk checksums.
    page_size: usize,
    /// Shared allocator for reusable page and growth allocations.
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
    #[inline]
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

    /// Returns the sole partial page after complete pages have been drained.
    #[inline]
    pub(super) fn partial(&self) -> &[u8] {
        assert!(
            self.len < self.page_size,
            "buffer must contain less than one page"
        );
        self.tail.as_ref()
    }

    /// Appends borrowed bytes and reports whether the flush threshold was exceeded.
    pub(super) fn append(&mut self, data: &[u8]) -> bool {
        let end = self
            .len
            .checked_add(data.len())
            .expect("buffer length overflow");
        let spare = self.tail_spare();
        if data.len() <= spare {
            self.tail.put_slice(data);
        } else {
            // Fill the current tail to a page boundary and put the remainder in a new allocation.
            // Existing bytes stay in their original owners throughout the extension.
            let mut next = self.allocate_growth(data.len(), spare);
            let (first, rest) = data.split_at(spare);
            self.tail.put_slice(first);
            next.put_slice(rest);
            self.retire_tail(next);
        }
        self.len = end;
        end > self.capacity
    }

    /// Encodes one fixed-size value directly across the current and next allocations.
    pub(super) fn append_value<T: FixedSize + Write>(&mut self, value: &T) {
        // Limit the encoder to the declared size and reject short encodings before updating
        // the logical length. The same bound applies when the value spans allocations.
        let end = self
            .len
            .checked_add(T::SIZE)
            .expect("buffer length overflow");
        let spare = self.tail_spare();
        if T::SIZE <= spare {
            let mut dst = (&mut self.tail).limit(T::SIZE);
            value.write(&mut dst);
            assert_eq!(dst.remaining_mut(), 0, "encoded size must match FixedSize");
        } else {
            // Chaining writable regions lets the encoder cross an allocation boundary without
            // staging the value in a temporary buffer.
            let mut next = self.allocate_growth(T::SIZE, spare);
            {
                let mut dst = (&mut self.tail)
                    .limit(spare)
                    .chain_mut(&mut next)
                    .limit(T::SIZE);
                value.write(&mut dst);
                assert_eq!(dst.remaining_mut(), 0, "encoded size must match FixedSize");
            }
            self.retire_tail(next);
        }
        self.len = end;
    }

    /// Transfers every full logical page and retains at most one independent partial page.
    pub(super) fn drain_full_pages(&mut self) -> IoBufs {
        // With no full pages, the tail already fits in a page-sized allocation and can be reused.
        let full_len = self.len / self.page_size * self.page_size;
        if full_len == 0 {
            return IoBufs::default();
        }

        // Transfer prefix owners directly. A partial-only tail with at most one page of backing
        // can stay writable while those pages are in flight.
        let partial_len = self.tail.len() % self.page_size;
        let tail_full_len = self.tail.len() - partial_len;
        let mut drained = std::mem::take(&mut self.prefix);
        if tail_full_len > 0 || self.tail.capacity() > self.page_size {
            // Detach the partial page when the tail contributes full pages or owns a larger
            // allocation, allowing the old backing to return to the pool after I/O completes.
            let mut retained = Self::allocate_page(&self.pool, self.page_size, partial_len);
            if partial_len > 0 {
                retained.put_slice(&self.tail.as_ref()[tail_full_len..]);
            }
            let mut old_tail = std::mem::replace(&mut self.tail, retained);
            old_tail.truncate(tail_full_len);
            drained.append(old_tail.freeze());
        }

        // The drained chunks must cover exactly the full pages. Advancing by that length
        // keeps the retained partial page at its original logical position in the blob.
        assert_eq!(
            drained.len(),
            full_len,
            "drained pages must match the buffered length"
        );
        assert!(
            drained
                .iter()
                .all(|chunk| chunk.len().is_multiple_of(self.page_size)),
            "drained chunks must contain whole pages"
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

    /// Allocates at most one page of backing, staying detached when no bytes are needed.
    fn allocate_page(pool: &BufferPool, page_size: usize, needed: usize) -> IoBufMut {
        if needed == 0 {
            return IoBufMut::default();
        }

        // A larger pool class or aligned fallback could retain more than one page for a tiny
        // tail. Reuse only an exact eligible class, with exact native backing as the fallback.
        let config = pool.config();
        let has_page_class = page_size >= config.pool_min_size()
            && config
                .class_for(page_size)
                .is_some_and(|class| class.size.get() == page_size);
        if has_page_class {
            pool.try_alloc(page_size)
                .unwrap_or_else(|_| IoBufMut::with_capacity(page_size))
        } else {
            IoBufMut::with_capacity(page_size)
        }
    }

    /// Returns writable space in the whole-page portion of the current allocation.
    #[inline]
    const fn tail_spare(&self) -> usize {
        // Pool classes need not be multiples of the logical page size. Leave any fractional
        // page of capacity unused so a completed tail can join the prefix as whole pages.
        let usable = self.tail.capacity() / self.page_size * self.page_size;
        usable
            .checked_sub(self.tail.len())
            .expect("tail length must fit its page-aligned capacity")
    }

    /// Allocates a geometrically sized, page-aligned logical extension.
    fn allocate_growth(&self, additional: usize, spare: usize) -> IoBufMut {
        assert!(
            additional > spare,
            "growth must exceed the tail's spare capacity"
        );

        // After filling the current tail, use the buffered length as the next chunk's growth
        // target, capped by the remaining flush budget. A single append may exceed that budget.
        let filled = self.len.checked_add(spare).expect("buffer growth overflow");
        assert!(
            filled.is_multiple_of(self.page_size),
            "a filled tail must end on a page boundary"
        );
        let needed = additional - spare;
        let remaining = self.capacity.saturating_sub(filled);
        let base = self.page_size.max(filled.min(remaining));
        let target = needed.max(base);

        // Round up before consulting the pool so ignoring a fractional final page still leaves
        // room for the complete append.
        let request = target
            .checked_next_multiple_of(self.page_size)
            .expect("buffer growth overflow");
        if request == self.page_size {
            Self::allocate_page(&self.pool, self.page_size, request)
        } else {
            self.pool.alloc(request)
        }
    }

    /// Freezes a completed page-aligned tail and installs the new unique tail.
    fn retire_tail(&mut self, next: IoBufMut) {
        let old = std::mem::replace(&mut self.tail, next).freeze();
        assert!(
            old.len().is_multiple_of(self.page_size),
            "prefix chunks must contain whole pages"
        );
        self.prefix.append(old);
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

    /// Provides reusable backing for each geometric growth step.
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

    /// Pools the first page and forces larger chunks onto native backing.
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
        let mut bytes = prefix.clone().coalesce().as_ref().to_vec();
        bytes.extend_from_slice(tail);
        bytes
    }

    #[test]
    fn test_extension_preserves_prior_allocation_pointers() {
        // Each extension keeps earlier owners live, so their addresses must remain unchanged
        // whether subsequent allocations come from the pool or native backing.
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
    fn test_typed_append_crosses_allocations_and_pages() {
        // The value fills the original tail and crosses page boundaries in the new allocation.
        // The original tail must join the prefix without a copy.
        let mut buffer = Buffer::from(10, &[], 64, 8, test_pool());
        assert!(!buffer.append(&[1; 7]));
        let tail_ptr = buffer.parts().1.as_ptr();
        buffer.append_value(&Pattern::<18>(2));
        assert_eq!(buffer.parts().0.chunk_at(0).unwrap().as_ptr(), tail_ptr);
        assert_eq!(contents(&buffer), [vec![1; 7], vec![2; 18]].concat());
        assert_eq!(buffer.size(), 35);

        // Three complete pages transfer to the writer, leaving one byte at the new offset.
        let drained = buffer.drain_full_pages();
        assert_eq!(drained.len(), 24);
        assert_eq!(
            drained.iter().map(|chunk| chunk.len()).collect::<Vec<_>>(),
            [8, 16]
        );
        assert_eq!(buffer.partial(), &[2]);
        assert_eq!(buffer.offset, 34);
    }

    #[test]
    fn test_zero_size_typed_append_stays_detached() {
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

    #[rstest::rstest]
    #[case(&[])]
    #[case(&[0])]
    #[should_panic(expected = "encoded size must match FixedSize")]
    fn test_typed_append_rejects_short_encoding(#[case] seed: &[u8]) {
        // An empty seed takes the growth path. A seeded byte leaves room in the existing tail.
        let mut buffer = Buffer::from(0, seed, 32, 16, test_pool());
        buffer.append_value(&IncorrectSize(7));
    }

    #[rstest::rstest]
    #[case(&[])]
    #[case(&[0])]
    #[should_panic]
    fn test_typed_append_rejects_long_encoding(#[case] seed: &[u8]) {
        // Both destinations must bound the encoder even when their backing has spare capacity.
        let mut buffer = Buffer::from(0, seed, 32, 16, test_pool());
        buffer.append_value(&IncorrectSize(9));
    }

    #[test]
    fn test_drain_reuses_independent_partial_page() {
        let pool = BufferPool::new(
            BufferPoolConfig::for_storage()
                .with_size_classes([(NZUsize!(8), NZU32!(2))])
                .with_pool_min_size(0)
                .with_thread_cache_disabled(),
            &mut Registry::default(),
        );

        // Both pool slots remain occupied: one by the full-page prefix and one by the tail.
        // Draining the prefix can keep the already independent, page-sized tail in place.
        let mut buffer = Buffer::from(0, &[], 16, 8, pool);
        buffer.append(&[1; 8]);
        buffer.append(&[2]);
        let tail_ptr = buffer.tail.as_ref().as_ptr();
        assert_eq!(buffer.tail.capacity(), 8);
        let drained = buffer.drain_full_pages();
        assert_eq!(drained.clone().coalesce().as_ref(), &[1; 8]);
        assert_eq!(buffer.partial(), &[2]);
        assert_eq!(buffer.tail.capacity(), 8);
        assert_eq!(buffer.tail.as_ref().as_ptr(), tail_ptr);
        assert_eq!(buffer.offset, 8);

        // The transferred prefix stays immutable while the retained tail accepts new bytes.
        buffer.append(&[3]);
        assert_eq!(drained.coalesce().as_ref(), &[1; 8]);
        assert_eq!(buffer.parts().1, &[2, 3]);
    }

    #[test]
    fn test_drain_keeps_chunks_and_detaches_mutable_suffix() {
        // Sparse classes make the growing tail much larger than one page. Its final partial
        // page must detach from that backing when full pages are drained.
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

        // Keep the drained owners live while mutating the replacement tail to check that the
        // bytes handed to the writer remain unchanged.
        let before = drained.clone().coalesce();
        buffer.append(&[100, 101]);
        assert_eq!(drained.coalesce(), before);
        assert_eq!(buffer.parts().1, &[99, 100, 101]);
    }

    #[test]
    fn test_exhausted_page_class_falls_back_to_exact_backing() {
        let pool = BufferPool::new(
            BufferPoolConfig::for_storage()
                .with_size_classes([(NZUsize!(8), NZU32!(1))])
                .with_pool_min_size(0)
                .with_thread_cache_disabled(),
            &mut Registry::default(),
        );

        // Hold the only page-sized lease to force an exact-sized native allocation for the tail.
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
    fn test_replace_detaches_prior_owners() {
        let mut buffer = Buffer::from(4, &[1, 2], 18, 3, test_pool());
        buffer.append(&[3, 4, 5, 6]);
        let old = buffer.drain_full_pages();
        assert_eq!(old.len(), 6);

        buffer.replace(20, &[7, 8]);
        assert_eq!(contents(&buffer), [7, 8]);
        assert_eq!(buffer.size(), 22);
        assert_eq!(old.coalesce().as_ref(), &[1, 2, 3, 4, 5, 6]);

        buffer.replace(20, &[]);
        assert!(buffer.is_empty());
        assert_eq!(buffer.offset, 20);
        assert_eq!(buffer.tail.capacity(), 0);
    }

    #[test]
    fn test_page_geometry_handles_one_and_non_power_of_two() {
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
    fn test_zero_page_size_is_rejected() {
        let _ = Buffer::from(0, &[], 0, 0, test_pool());
    }

    #[test]
    #[should_panic(expected = "buffer capacity must be page-aligned")]
    fn test_misaligned_capacity_is_rejected() {
        let _ = Buffer::from(0, &[], 17, 8, test_pool());
    }

    #[test]
    #[should_panic(expected = "seed data must be less than one page")]
    fn test_full_page_seed_is_rejected() {
        let _ = Buffer::from(0, &[0; 8], 16, 8, test_pool());
    }

    #[test]
    #[should_panic(expected = "replacement data must be less than one page")]
    fn test_full_page_replacement_is_rejected() {
        let mut buffer = Buffer::from(0, &[], 16, 8, test_pool());
        buffer.replace(0, &[0; 8]);
    }
}
