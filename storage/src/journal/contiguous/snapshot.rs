//! The owned view a reader holds.

use crate::journal::Error;
use commonware_runtime::{
    buffer::paged::{self, Sealed},
    Blob, IoBufs,
};
use std::{
    num::NonZeroUsize,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};

/// Return the first retained logical position in `blob`.
#[inline]
pub(super) fn first_in_blob(
    pruning_boundary: u64,
    blob: u64,
    items_per_blob: u64,
) -> Result<u64, Error> {
    let start = blob
        .checked_mul(items_per_blob)
        .ok_or(Error::OffsetOverflow)?;
    Ok(pruning_boundary.max(start))
}

/// A read handle for one blob, resolved from a [`Snapshot`].
pub(super) enum BlobHandle<'a, B: Blob> {
    Sealed(&'a Sealed<B>),
    Tail(&'a paged::Reader<B>),
}

impl<B: Blob> BlobHandle<'_, B> {
    pub(super) async fn read_at(&self, offset: u64, len: usize) -> Result<IoBufs, Error> {
        match self {
            Self::Sealed(s) => s.read_at(offset, len).await.map_err(Error::Runtime),
            Self::Tail(t) => t.read_at(offset, len).await.map_err(Error::Runtime),
        }
    }

    pub(super) async fn read_many_into(
        &self,
        buf: &mut [u8],
        offsets: &[u64],
        item_size: NonZeroUsize,
    ) -> Result<(), Error> {
        match self {
            Self::Sealed(s) => s
                .read_many_into(buf, offsets, item_size)
                .await
                .map_err(Error::Runtime),
            Self::Tail(t) => t
                .read_many_into(buf, offsets, item_size)
                .await
                .map_err(Error::Runtime),
        }
    }

    pub(super) fn try_read_sync(&self, offset: u64, buf: &mut [u8]) -> bool {
        match self {
            Self::Sealed(s) => s.try_read_sync(offset, buf),
            Self::Tail(t) => t.try_read_sync(offset, buf),
        }
    }
}

/// A frozen view of the journal's blobs and the bounds they back. Counts itself in `readers`
/// for its lifetime; the count gates in-place truncation during rewind.
pub(super) struct Snapshot<B: Blob> {
    /// Number of the first blob in [Self::sealed].
    pub(super) base_blob: u64,

    /// Sealed historical blobs, ascending and dense from `base_blob`.
    pub(super) sealed: Arc<[Sealed<B>]>,

    /// Read handle for the tail, blob [`Self::tail_blob`].
    pub(super) tail_reader: paged::Reader<B>,

    /// Total items appended, including pruned.
    pub(super) size: u64,

    /// Items below this position are pruned.
    pub(super) pruning_boundary: u64,

    readers: Arc<AtomicUsize>,
}

impl<B: Blob> Snapshot<B> {
    pub(super) fn new(
        base_blob: u64,
        sealed: Arc<[Sealed<B>]>,
        tail_reader: paged::Reader<B>,
        size: u64,
        pruning_boundary: u64,
        readers: Arc<AtomicUsize>,
    ) -> Self {
        readers.fetch_add(1, Ordering::Relaxed);
        Self {
            base_blob,
            sealed,
            tail_reader,
            size,
            pruning_boundary,
            readers,
        }
    }

    pub(super) const fn bounds(&self) -> std::ops::Range<u64> {
        self.pruning_boundary..self.size
    }

    /// Validate a position to be read: must lie within `[pruning_boundary, size)`.
    pub(super) const fn check_readable(&self, pos: u64) -> Result<(), Error> {
        if pos >= self.size {
            return Err(Error::ItemOutOfRange(pos));
        }
        if pos < self.pruning_boundary {
            return Err(Error::ItemPruned(pos));
        }
        Ok(())
    }

    /// Validate a replay start cursor, which may also sit at the end: `[pruning_boundary, size]`.
    pub(super) const fn check_cursor(&self, pos: u64) -> Result<(), Error> {
        if pos > self.size {
            return Err(Error::ItemOutOfRange(pos));
        }
        if pos < self.pruning_boundary {
            return Err(Error::ItemPruned(pos));
        }
        Ok(())
    }

    /// The tail's blob.
    pub(super) fn tail_blob(&self) -> u64 {
        self.base_blob + self.sealed.len() as u64
    }

    /// Resolve the read handle for `blob`, if retained.
    pub(super) fn handle(&self, blob: u64) -> Option<BlobHandle<'_, B>> {
        if blob == self.tail_blob() {
            return Some(BlobHandle::Tail(&self.tail_reader));
        }
        let idx = blob.checked_sub(self.base_blob)?;
        self.sealed.get(idx as usize).map(BlobHandle::Sealed)
    }
}

impl<B: Blob> Drop for Snapshot<B> {
    fn drop(&mut self) {
        self.readers.fetch_sub(1, Ordering::Release);
    }
}
