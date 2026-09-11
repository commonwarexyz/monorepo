use super::{
    super::{CHECKSUM_SIZE, Checksum, cache::CacheRef},
    View,
};
use crate::{
    Blob, Error, Handle, IoBufs, IoBufsMut, ReadOptions, Runner, Storage as _, WriteOptions,
    buffer::paged::Writer, deterministic,
};
use commonware_cryptography::Crc32;
use commonware_utils::{NZU16, NZUsize, sync::Mutex};
use futures::{FutureExt, future::pending};
use rstest::rstest;
use std::{
    num::NonZeroU16,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};

const PAGE: usize = 101;
const PHYSICAL: usize = PAGE + CHECKSUM_SIZE as usize;

#[derive(Clone)]
struct ProbeBlob {
    bytes: Arc<Vec<u8>>,
    reads: Arc<Mutex<Vec<(u64, usize)>>>,
    block_first: bool,
    block_all: bool,
    first_started: Arc<AtomicBool>,
    fail_offset: Option<u64>,
    active: Arc<AtomicUsize>,
}

struct Active(Arc<AtomicUsize>);
impl Drop for Active {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

impl ProbeBlob {
    fn new(pages: usize) -> Self {
        let mut bytes = Vec::new();
        for page in 0..pages {
            let data = logical(page * PAGE, PAGE);
            let checksum = Checksum::new(PAGE as u16, Crc32::checksum(&data));
            bytes.extend_from_slice(&data);
            bytes.extend_from_slice(&checksum.to_bytes());
        }
        Self {
            bytes: Arc::new(bytes),
            reads: Default::default(),
            block_first: false,
            block_all: false,
            first_started: Default::default(),
            fail_offset: None,
            active: Default::default(),
        }
    }
}

impl Blob for ProbeBlob {
    async fn read_at(&self, offset: u64, len: usize, _: ReadOptions) -> Result<IoBufsMut, Error> {
        self.reads.lock().push((offset, len));
        self.active.fetch_add(1, Ordering::Relaxed);
        let _active = Active(self.active.clone());
        if self.block_all || (self.block_first && !self.first_started.swap(true, Ordering::Relaxed))
        {
            pending::<()>().await;
        }
        if self.fail_offset == Some(offset) {
            return Err(Error::ReadFailed);
        }
        let start = offset as usize;
        let bytes = self
            .bytes
            .get(start..start + len)
            .ok_or(Error::BlobInsufficientLength)?;
        Ok(bytes.to_vec().into())
    }
    async fn read_at_buf(
        &self,
        _: u64,
        _: usize,
        _: impl Into<IoBufsMut> + Send,
        _: ReadOptions,
    ) -> Result<IoBufsMut, Error> {
        unreachable!()
    }
    async fn write_at(
        &self,
        _: u64,
        _: impl Into<IoBufs> + Send,
        _: WriteOptions,
    ) -> Result<(), Error> {
        unreachable!()
    }
    async fn resize(&self, _: u64) -> Result<(), Error> {
        unreachable!()
    }
    async fn sync(&self) -> Result<(), Error> {
        Ok(())
    }
    async fn start_sync(&self) -> Handle<()> {
        Handle::ready(Ok(()))
    }
}

fn logical(offset: usize, len: usize) -> Vec<u8> {
    (offset..offset + len)
        .map(|i| (i.wrapping_mul(37) % 251) as u8)
        .collect()
}

#[rstest]
fn test_bulk_boundaries(
    #[values(63, 64, 65, 511, 512, 513)] pages: usize,
    #[values(1, 7, 64, 1025)] capacity: usize,
) {
    deterministic::Runner::default().start(|context| async move {
        let blob = ProbeBlob::new(pages);
        let cache = CacheRef::from_pooler(&context, NZU16!(PAGE as u16), NZUsize!(capacity));
        let tail = logical(pages * PAGE, 17);
        let view = View {
            blob: &blob,
            cache_ref: &cache,
            id: 0,
            size: (pages * PAGE + tail.len()) as u64,
            tail_offset: (pages * PAGE) as u64,
            tail: &tail,
        };
        let offsets: Vec<_> = (0..pages).map(|p| (p * PAGE + PAGE - 2) as u64).collect();
        let mut out = vec![0; pages * 4];
        view.read_many_into(&mut out, &offsets, NZUsize!(4))
            .await
            .unwrap();
        for (&offset, actual) in offsets.iter().zip(out.as_chunks::<4>().0) {
            assert_eq!(actual.as_slice(), logical(offset as usize, 4));
        }
        let reads = blob.reads.lock();
        assert!(reads.iter().all(|&(off, len)| off % PHYSICAL as u64 == 0
            && len % PHYSICAL == 0
            && len <= 64 * PHYSICAL));
        if capacity >= pages {
            assert_eq!(reads.len(), pages.div_ceil(64));
        }
    });
}

#[rstest]
fn test_sparse_waves(#[values(7, 8, 9, 17, 65)] requested: usize) {
    deterministic::Runner::default().start(|context| async move {
        let blob = ProbeBlob::new(requested * 2);
        let cache = CacheRef::from_pooler(&context, NZU16!(PAGE as u16), NZUsize!(requested));
        let offsets: Vec<_> = (0..requested).map(|p| (p * 2 * PAGE) as u64).collect();
        let view = View {
            blob: &blob,
            cache_ref: &cache,
            id: 0,
            size: (requested * 2 * PAGE) as u64,
            tail_offset: (requested * 2 * PAGE) as u64,
            tail: &[],
        };
        let mut out = vec![0; requested * 4];
        view.read_many_into(&mut out, &offsets, NZUsize!(4))
            .await
            .unwrap();
        for (&offset, actual) in offsets.iter().zip(out.as_chunks::<4>().0) {
            assert_eq!(actual.as_slice(), logical(offset as usize, 4));
        }
        assert_eq!(blob.reads.lock().len(), requested);
    });
}

#[test]
fn test_bulk_error_cancels_pending_sibling() {
    deterministic::Runner::default().start(|context| async move {
        let mut blob = ProbeBlob::new(3);
        blob.block_first = true;
        blob.fail_offset = Some((2 * PHYSICAL) as u64);
        let cache = CacheRef::from_pooler(&context, NZU16!(PAGE as u16), NZUsize!(3));
        let offsets = [0, (2 * PAGE) as u64];
        let mut out = [0; 8];
        let view = View {
            blob: &blob,
            cache_ref: &cache,
            id: 0,
            size: (3 * PAGE) as u64,
            tail_offset: (3 * PAGE) as u64,
            tail: &[],
        };
        let result = view
            .read_many_into(&mut out, &offsets, NZUsize!(4))
            .now_or_never();
        assert!(matches!(result, Some(Err(Error::ReadFailed))));
        assert_eq!(blob.active.load(Ordering::Relaxed), 0);
        blob.fail_offset = None;
        let view = View {
            blob: &blob,
            cache_ref: &cache,
            id: 0,
            size: (3 * PAGE) as u64,
            tail_offset: (3 * PAGE) as u64,
            tail: &[],
        };
        view.read_many_into(&mut out, &offsets, NZUsize!(4))
            .await
            .unwrap();
    });
}

#[test]
fn test_bulk_cancel_then_retry() {
    deterministic::Runner::default().start(|context| async move {
        let mut blob = ProbeBlob::new(3);
        blob.block_first = true;
        let cache = CacheRef::from_pooler(&context, NZU16!(PAGE as u16), NZUsize!(3));
        let offsets = [0, (2 * PAGE) as u64];
        let mut out = [0; 8];
        let view = View {
            blob: &blob,
            cache_ref: &cache,
            id: 0,
            size: (3 * PAGE) as u64,
            tail_offset: (3 * PAGE) as u64,
            tail: &[],
        };
        let mut fetch = view.read_many_into(&mut out, &offsets, NZUsize!(4)).boxed();
        assert!(futures::poll!(&mut fetch).is_pending());
        drop(fetch);
        assert_eq!(blob.active.load(Ordering::Relaxed), 0);
        view.read_many_into(&mut out, &offsets, NZUsize!(4))
            .await
            .unwrap();
        assert_eq!(&out[..4], logical(0, 4));
        assert_eq!(&out[4..], logical(2 * PAGE, 4));
    });
}

#[test]
fn test_later_wave_error_is_not_blocked_by_pending_read() {
    deterministic::Runner::default().start(|context| async move {
        let mut blob = ProbeBlob::new(18);
        blob.block_first = true;
        blob.fail_offset = Some((16 * PHYSICAL) as u64);
        let cache = CacheRef::from_pooler(&context, NZU16!(PAGE as u16), NZUsize!(18));
        let view = View {
            blob: &blob,
            cache_ref: &cache,
            id: 0,
            size: (18 * PAGE) as u64,
            tail_offset: (18 * PAGE) as u64,
            tail: &[],
        };
        let offsets: Vec<_> = (0..9).map(|p| (p * 2 * PAGE) as u64).collect();
        let mut out = vec![0; offsets.len() * 4];
        let result = view
            .read_many_into(&mut out, &offsets, NZUsize!(4))
            .now_or_never();
        assert!(
            matches!(result, Some(Err(Error::ReadFailed))),
            "result: {result:?}, issued reads: {:?}",
            *blob.reads.lock()
        );
    });
}

#[test]
fn test_sparse_small_cache_does_not_double_io() {
    deterministic::Runner::default().start(|context| async move {
        let requested = 32;
        let blob = ProbeBlob::new(requested * 2);
        let cache = CacheRef::from_pooler(&context, NZU16!(PAGE as u16), NZUsize!(1));
        let view = View {
            blob: &blob,
            cache_ref: &cache,
            id: 0,
            size: (requested * 2 * PAGE) as u64,
            tail_offset: (requested * 2 * PAGE) as u64,
            tail: &[],
        };
        let offsets: Vec<_> = (0..requested).map(|p| (p * 2 * PAGE) as u64).collect();
        let mut out = vec![0; requested * 4];
        view.read_many_into(&mut out, &offsets, NZUsize!(4))
            .await
            .unwrap();
        for (&offset, actual) in offsets.iter().zip(out.as_chunks::<4>().0) {
            assert_eq!(actual.as_slice(), logical(offset as usize, 4));
        }
        let reads = blob.reads.lock().len();
        assert!(reads <= requested, "{reads} reads for {requested} pages");
    });
}

#[test]
fn test_bulk_limits_pending_reads() {
    deterministic::Runner::default().start(|context| async move {
        let mut blob = ProbeBlob::new(32);
        blob.block_all = true;
        let cache = CacheRef::from_pooler(&context, NZU16!(PAGE as u16), NZUsize!(1));
        let view = View {
            blob: &blob,
            cache_ref: &cache,
            id: 0,
            size: (32 * PAGE) as u64,
            tail_offset: (32 * PAGE) as u64,
            tail: &[],
        };
        let offsets: Vec<_> = (0..16).map(|p| (p * 2 * PAGE) as u64).collect();
        let mut out = vec![0; offsets.len() * 4];
        let mut read = view.read_many_into(&mut out, &offsets, NZUsize!(4)).boxed();
        assert!(futures::poll!(&mut read).is_pending());
        assert_eq!(blob.active.load(Ordering::Relaxed), 8);
        assert_eq!(blob.reads.lock().len(), 8);
        drop(read);
        assert_eq!(blob.active.load(Ordering::Relaxed), 0);
    });
}

#[rstest]
fn test_read_ranges_mixed_cache_and_tail(#[values(1, 200)] capacity: usize) {
    deterministic::Runner::default().start(|context| async move {
        let blob = ProbeBlob::new(129);
        let cache = CacheRef::from_pooler(&context, NZU16!(PAGE as u16), NZUsize!(capacity));
        for page in [2, 62] {
            cache.cache(0, &logical(page * PAGE, PAGE), (page * PAGE) as u64);
        }
        let tail = logical(129 * PAGE, 11);
        let view = View {
            blob: &blob,
            cache_ref: &cache,
            id: 0,
            size: (129 * PAGE + tail.len()) as u64,
            tail_offset: (129 * PAGE) as u64,
            tail: &tail,
        };
        let ranges = [
            (0, 0),
            (1, 2),
            ((PAGE - 1) as u64, PAGE * 65 + 3),
            ((100 * PAGE + 17) as u64, 5),
            ((129 * PAGE) as u64, 11),
        ];
        let out = view.read_ranges(&ranges).await.unwrap().coalesce();
        let expected: Vec<_> = ranges
            .iter()
            .flat_map(|&(off, len)| logical(off as usize, len))
            .collect();
        assert_eq!(out.as_ref(), expected);
        let mut seen = std::collections::BTreeSet::new();
        for &(offset, len) in blob.reads.lock().iter() {
            for page in offset as usize / PHYSICAL..(offset as usize + len) / PHYSICAL {
                assert!(seen.insert(page), "page {page} was fetched twice");
            }
        }
    });
}

#[test]
fn test_read_ranges_validate_before_io() {
    deterministic::Runner::default().start(|context| async move {
        let blob = ProbeBlob::new(1);
        let cache = CacheRef::from_pooler(&context, NZU16!(PAGE as u16), NZUsize!(1));
        let view = View {
            blob: &blob,
            cache_ref: &cache,
            id: 0,
            size: PAGE as u64,
            tail_offset: PAGE as u64,
            tail: &[],
        };
        assert!(view.read_ranges(&[]).await.unwrap().coalesce().is_empty());
        assert!(
            view.read_ranges(&[(PAGE as u64, 0)])
                .await
                .unwrap()
                .coalesce()
                .is_empty()
        );
        assert!(matches!(
            view.read_ranges(&[(u64::MAX, 1)]).await,
            Err(Error::OffsetOverflow)
        ));
        assert!(matches!(
            view.read_ranges(&[(0, PAGE + 1)]).await,
            Err(Error::BlobInsufficientLength)
        ));
        assert!(blob.reads.lock().is_empty());
    });
}

const PAGE_SIZE: NonZeroU16 = NZU16!(103);
const BUFFER_SIZE: usize = PAGE_SIZE.get() as usize * 2;

/// A read straddling the persisted prefix and the in-memory tail is served synchronously once
/// the prefix page is cached (the unified `View` serves the prefix from the cache and the
/// suffix from the tail in one call).
#[test]
fn test_view_try_read_sync_straddles_cache_and_tail() {
    let executor = deterministic::Runner::default();
    executor.start(|context: deterministic::Context| async move {
        let cache_ref = super::CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
        let (blob, blob_size) = context
            .open("test_partition", b"view_straddle")
            .await
            .unwrap();
        let mut writer = Writer::new(blob, blob_size, BUFFER_SIZE, cache_ref)
            .await
            .unwrap();

        // A full page (flushed to the blob) followed by a partial tail kept in the tip buffer.
        let page_size = PAGE_SIZE.get() as usize;
        writer.append(&vec![0xAA; page_size]).await.unwrap();
        writer.append(b"TAIL").await.unwrap();
        writer.sync().await.unwrap();

        // Warm the cache for the first page, then read across the page/tail boundary.
        writer.read_at(0, page_size).await.unwrap();
        let mut buf = [0u8; 4];
        assert!(writer.try_read_sync_into(&mut buf, page_size as u64 - 2));
        assert_eq!(&buf, &[0xAA, 0xAA, b'T', b'A']);
    });
}
