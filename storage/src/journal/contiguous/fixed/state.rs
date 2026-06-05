//! State shared between the journal and its snapshot readers, and the publication protocol.

use super::first_in_blob;
use crate::journal::Error;
use commonware_runtime::{
    buffer::paged::{AppendReader, Sealed},
    Blob, IoBufs,
};
use commonware_utils::sync::RwLock;
use std::{
    num::{NonZeroU64, NonZeroUsize},
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Arc,
    },
};

/// A read handle for one blob, resolved from a [`BlobTable`].
pub(super) enum BlobHandle<'a, B: Blob> {
    Sealed(&'a Sealed<B>),
    Tail(&'a AppendReader<B>),
}

/// Maps each retained blob to its read handle. Immutable once published: operations that
/// add or drop blobs (roll, prune, rewind, clear) build a new table and publish it with a
/// single pointer swap. `sealed[i]` is blob `base_blob + i`; the tail is blob
/// `base_blob + sealed.len()`.
pub(super) struct BlobTable<B: Blob> {
    /// Strictly increasing across publications (see [`Shared::snapshot`]).
    pub(super) version: u64,

    /// Number of first blob in [sealed].
    pub(super) base_blob: u64,

    /// Sealed historical blobs, ascending and dense from `base_blob`.
    pub(super) sealed: Arc<[Sealed<B>]>,

    /// Read capability for the live tail, blob [`Self::tail_blob`].
    pub(super) tail_reader: AppendReader<B>,

    /// Items below this position are pruned.
    pub(super) pruning_boundary: u64,
}

impl<B: Blob> Clone for BlobTable<B> {
    fn clone(&self) -> Self {
        Self {
            version: self.version,
            base_blob: self.base_blob,
            sealed: self.sealed.clone(),
            tail_reader: self.tail_reader.clone(),
            pruning_boundary: self.pruning_boundary,
        }
    }
}

impl<B: Blob> BlobTable<B> {
    /// The tail's blob.
    pub(super) fn tail_blob(&self) -> u64 {
        self.base_blob + self.sealed.len() as u64
    }

    /// A copy of this table with the next version. The only way to build a successor.
    pub(super) fn successor(&self) -> Self {
        Self {
            version: self.version + 1,
            ..self.clone()
        }
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

/// State shared between the journal and its snapshot readers. The lock is held only to clone
/// or swap the `Arc`, never across I/O or `.await`.
pub(super) struct Shared<B: Blob> {
    /// Total items appended, including pruned. Release-stored after the backing bytes and
    /// table are visible.
    pub(super) size: AtomicU64,

    /// The current blob table. Replaced whole; never modified in place.
    pub(super) table: RwLock<Arc<BlobTable<B>>>,

    /// Number of live [Reader] snapshots. Gates in-place truncation during rewind.
    pub(super) readers: AtomicUsize,
}

impl<B: Blob> Shared<B> {
    /// Capture a [`Snapshot`]. The writer publishes a new table before release-storing any
    /// `size` that depends on it, so an unchanged `version` across the size load proves the
    /// pair is consistent.
    pub(super) fn snapshot(&self, items_per_blob: NonZeroU64) -> Snapshot<B> {
        loop {
            let table = self.table.read().clone();
            let size = self.size.load(Ordering::Acquire);
            if self.table.read().version == table.version {
                return Snapshot {
                    table,
                    size,
                    items_per_blob,
                };
            }
        }
    }

    /// Publish a new blob table. Writer-only.
    pub(super) fn publish_table(&self, new: BlobTable<B>) {
        let mut current = self.table.write();
        assert_eq!(
            new.version,
            current.version + 1,
            "table versions must be sequential"
        );
        *current = Arc::new(new);
    }

    /// Publish a new size. Writer-only; called after the backing bytes and table are visible.
    pub(super) fn publish_size(&self, size: u64) {
        self.size.store(size, Ordering::Release);
    }
}

/// A blob table paired with a size it backs. The only constructor is [`Shared::snapshot`].
pub(super) struct Snapshot<B: Blob> {
    pub(super) table: Arc<BlobTable<B>>,
    pub(super) size: u64,
    pub(super) items_per_blob: NonZeroU64,
}

impl<B: Blob> Snapshot<B> {
    pub(super) fn bounds(&self) -> std::ops::Range<u64> {
        self.table.pruning_boundary..self.size
    }

    /// Resolve `pos` to its read handle and byte offset within the blob.
    pub(super) fn locate(&self, pos: u64, chunk_size: u64) -> Result<(BlobHandle<'_, B>, u64), Error> {
        if pos >= self.size {
            return Err(Error::ItemOutOfRange(pos));
        }
        if pos < self.table.pruning_boundary {
            return Err(Error::ItemPruned(pos));
        }
        let items_per_blob = self.items_per_blob.get();
        let blob = pos / items_per_blob;
        let pos_in_blob = pos - first_in_blob(self.table.pruning_boundary, blob, items_per_blob)?;
        let offset = pos_in_blob
            .checked_mul(chunk_size)
            .ok_or(Error::OffsetOverflow)?;
        let handle = self
            .table
            .handle(blob)
            .ok_or_else(|| Error::Corruption(format!("blob {blob} missing from snapshot")))?;
        Ok((handle, offset))
    }
}

