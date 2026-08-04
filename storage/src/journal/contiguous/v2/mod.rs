//! V2-native contiguous journals with eager legacy migration.
//!
//! These journals use append-only atomic blobs and embedded batch decisions. On the first V2 open
//! of a base partition that still contains a legacy contiguous journal, initialization runs the
//! normal legacy recovery path and then replaces the recovered sections one at a time. Once init
//! succeeds, the returned journal and every later reopen use only the native V2 implementation.
//!
//! The atomic root's application tag is split between journal authority and checked-page state:
//!
//! ```text
//! +---------------------+-------------------------+----------------------+
//! | start + 1 (8 B, BE) | reserved zeroes (52 B) | partial CRC32C (4 B) |
//! +---------------------+-------------------------+----------------------+
//! ```
//!
//! A zero start field means that section is not active. Exactly one section (or one matching
//! data/offsets pair for a variable journal) carries a nonzero field. Its name identifies the
//! active tail, its tag identifies the exact retained start, and its committed length identifies
//! the tail end. Sealed section names fill the interval between start and tail. This is sufficient
//! to reconstruct bounds without a separate `Metadata` object or a frame scan.
//!
//! ```text
//! append bytes (unpublished)               sync
//!          |                                 |
//!          v                                 v
//! +----------------+              +-------------------------+
//! | active payload | ------------>| root(s) + marker move   |
//! +----------------+              | one embedded UNO group  |
//!          |                      +-------------------------+
//!          | rollover stages sealed         |
//!          | unmarked roots                  |
//!          v                    old state <--+--> new state
//! ```
//!
//! Payload reaches storage as each append arrives. A rollover may durably stage a sealed section,
//! but its unmarked root remains unreachable. Until publication, recovery selects the old roots
//! and discards any surviving subset of unpublished writes. Publication makes the new length,
//! partial-page checksum, and marker durable together. The decision includes only the previous
//! authority and current tail, regardless of how many sections were crossed. Variable journals
//! place their data and fixed-width offsets roots in the same group, so neither side can advance
//! alone. Rewind and clear first publish a bounded marker move, then remove sections that the new
//! marker makes unreachable.
//!
//! Opening scans section names and bounded atomic roots. A fixed section may read its final partial
//! checked page. Sealed variable sections are page-complete and retain a final offset sentinel, so
//! only the active data and offsets tails need the equivalent validation. Historical data pages are
//! otherwise validated lazily when read. Opening never walks frames or hashes complete sections.
//!
//! # Legacy migration
//!
//! Legacy and native checked pages have different application framing, so migrating only the
//! outer blob layout cannot convert a journal. Init instead decodes recovered logical items and
//! writes them into native V2 sections. A temporary witness in the V2 data partition records the
//! exact retained start and makes unmarked V2 roots recognizable as migration staging:
//!
//! ```text
//! recover legacy
//!      |
//!      v
//! [legacy section N] --copy--> [unmarked V2 section N] --sync--> prune legacy N
//!      ...                                                        |
//!                                                                 v
//!                                  activate final V2 marker(s) atomically
//!                                                 |
//!                                                 v
//!                                  remove legacy state + witness
//! ```
//!
//! A section is pruned from legacy storage only after its native replacement is durable. Before
//! final activation, the witness, durable V2 prefix, and normally recovered legacy suffix form the
//! resumable conversion state. Copy batches retain roughly one MiB of encoded data, except that one
//! individually larger item must fit in memory. Activation is the single authority switch: fixed
//! journals publish the final tail root, while variable journals publish the data/offsets tail pair
//! in one batch. After activation, cleanup is idempotent and does not recover legacy contents. The
//! witness is removed before init returns; it is not part of native reopen or the hot-path sync
//! protocol.

use super::{Contiguous, Many, scan_rewind_size};
use crate::{Context, journal::Error};
use commonware_runtime::{
    ATOMIC_BLOB_TAG_LEN, AtomicBlob as _, AtomicStorage, Blob as _, Error as RuntimeError, Handle,
    buffer::paged::{ATOMIC_MARKER_LEN, CacheRef},
};
use std::num::{NonZeroU16, NonZeroUsize};

/// Temporary in-partition witness used only while legacy sections are being replaced.
///
/// Native V2 reopen has no coordinator. This witness exists solely to distinguish an incomplete
/// init-time conversion (whose unmarked V2 sections are staging) from malformed native V2 state.
const MIGRATION_NAME: &[u8] = b"_COMMONWARE_STORAGE_CONTIGUOUS_V2_MIGRATION";
const MIGRATION_MAGIC: [u8; 4] = *b"CWM2";
const LEGACY_CRC_OVERHEAD_DELTA: u16 = 8;
const MIGRATION_CACHE_PAGES: NonZeroUsize = NonZeroUsize::new(2).unwrap();
const MIGRATION_BATCH_BYTES: usize = 1024 * 1024;
const MIGRATION_BATCH_ITEMS: usize = 1_024;
const NO_START_MARKER: [u8; ATOMIC_MARKER_LEN] = [0; ATOMIC_MARKER_LEN];

fn encode_start_marker(start: u64) -> Result<[u8; ATOMIC_MARKER_LEN], Error> {
    let mut marker = NO_START_MARKER;
    marker[..8].copy_from_slice(
        &start
            .checked_add(1)
            .ok_or(Error::SizeOverflow)?
            .to_be_bytes(),
    );
    Ok(marker)
}

fn decode_start_marker(marker: [u8; ATOMIC_MARKER_LEN]) -> Result<Option<u64>, Error> {
    if marker[8..].iter().any(|byte| *byte != 0) {
        return Err(Error::Corruption(
            "contiguous V2 start marker has nonzero reserved bytes".into(),
        ));
    }
    let encoded = u64::from_be_bytes(marker[..8].try_into().expect("start marker is u64"));
    Ok(encoded.checked_sub(1))
}

fn fixed_migration_batch_items(item_size: usize) -> usize {
    debug_assert_ne!(item_size, 0);
    (MIGRATION_BATCH_BYTES / item_size).clamp(1, MIGRATION_BATCH_ITEMS)
}

fn encode_migration_tag(start: u64) -> Result<[u8; ATOMIC_BLOB_TAG_LEN], Error> {
    let mut tag = [0; ATOMIC_BLOB_TAG_LEN];
    tag[..8].copy_from_slice(
        &start
            .checked_add(1)
            .ok_or(Error::SizeOverflow)?
            .to_be_bytes(),
    );
    tag[8..12].copy_from_slice(&MIGRATION_MAGIC);
    Ok(tag)
}

fn decode_migration_tag(tag: [u8; ATOMIC_BLOB_TAG_LEN]) -> Result<Option<u64>, Error> {
    if tag == [0; ATOMIC_BLOB_TAG_LEN] {
        return Ok(None);
    }
    if tag[8..12] != MIGRATION_MAGIC || tag[12..].iter().any(|byte| *byte != 0) {
        return Err(Error::Corruption(
            "invalid contiguous V2 migration witness".into(),
        ));
    }
    let encoded = u64::from_be_bytes(tag[..8].try_into().expect("migration start is u64"));
    encoded
        .checked_sub(1)
        .map(Some)
        .ok_or_else(|| Error::Corruption("invalid contiguous V2 migration start".into()))
}

#[cfg(test)]
mod tag_tests {
    use super::*;

    #[test]
    fn migration_tag_layout_is_canonical() {
        assert_eq!(
            decode_migration_tag([0; ATOMIC_BLOB_TAG_LEN]).unwrap(),
            None
        );

        let tag = encode_migration_tag(u64::MAX - 1).unwrap();
        assert_eq!(&tag[..8], &u64::MAX.to_be_bytes());
        assert_eq!(&tag[8..12], &MIGRATION_MAGIC);
        assert!(tag[12..].iter().all(|byte| *byte == 0));
        assert_eq!(decode_migration_tag(tag).unwrap(), Some(u64::MAX - 1));
        assert!(matches!(
            encode_migration_tag(u64::MAX),
            Err(Error::SizeOverflow)
        ));

        let mut invalid = tag;
        invalid[12] = 1;
        assert!(matches!(
            decode_migration_tag(invalid),
            Err(Error::Corruption(_))
        ));

        let mut zero_start = tag;
        zero_start[..8].fill(0);
        assert!(matches!(
            decode_migration_tag(zero_start),
            Err(Error::Corruption(_))
        ));
    }
}

async fn scan_partition<E: Context>(context: &E, partition: &str) -> Result<Vec<Vec<u8>>, Error> {
    match context.scan(partition).await {
        Ok(names) => Ok(names),
        Err(RuntimeError::PartitionMissing(_)) => Ok(Vec::new()),
        Err(error) => Err(error.into()),
    }
}

async fn partition_has_state<E: Context>(
    context: &E,
    partitions: &[String],
) -> Result<bool, Error> {
    for partition in partitions {
        if !scan_partition(context, partition).await?.is_empty() {
            return Ok(true);
        }
    }
    Ok(false)
}

async fn remove_partition<E: Context>(context: &E, partition: &str) -> Result<(), Error> {
    match context.remove(partition, None).await {
        Ok(()) | Err(RuntimeError::PartitionMissing(_)) => Ok(()),
        Err(error) => Err(error.into()),
    }
}

async fn migration_start<E: Context + AtomicStorage>(
    context: &E,
    partition: &str,
    names: &[Vec<u8>],
) -> Result<Option<Option<u64>>, Error> {
    if !names.iter().any(|name| name == MIGRATION_NAME) {
        return Ok(None);
    }
    let (blob, size) = context.open_atomic(partition, MIGRATION_NAME).await?;
    if size != 0 {
        return Err(Error::Corruption(
            "contiguous V2 migration witness has payload".into(),
        ));
    }
    Ok(Some(decode_migration_tag(blob.tag().await?)?))
}

async fn start_migration<E: Context + AtomicStorage>(
    context: &E,
    partition: &str,
    start: u64,
) -> Result<(), Error> {
    let (blob, size) = context.open_atomic(partition, MIGRATION_NAME).await?;
    if size != 0 {
        return Err(Error::Corruption(
            "contiguous V2 migration witness has payload".into(),
        ));
    }
    let expected = encode_migration_tag(start)?;
    let current = blob.tag().await?;
    if current != [0; ATOMIC_BLOB_TAG_LEN] && current != expected {
        return Err(Error::Corruption(
            "contiguous V2 migration witness changed".into(),
        ));
    }
    blob.set_tag(expected).await?;
    blob.sync().await?;
    Ok(())
}

async fn finish_migration<E: Context>(context: &E, partition: &str) -> Result<(), Error> {
    match context.remove(partition, Some(MIGRATION_NAME)).await {
        Ok(()) | Err(RuntimeError::PartitionMissing(_)) => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn legacy_page_size(page_size: NonZeroU16) -> Result<NonZeroU16, Error> {
    // Legacy checked pages use a 12-byte dual checksum record while V2 uses a four-byte footer.
    // Keeping the same physical page alignment therefore reduces the legacy logical page by 8.
    page_size
        .get()
        .checked_sub(LEGACY_CRC_OVERHEAD_DELTA)
        .and_then(NonZeroU16::new)
        .ok_or_else(|| {
            Error::InvalidConfiguration(
                "V2 page size is too small to recover legacy checked pages".into(),
            )
        })
}

fn legacy_cache<E: Context>(context: &E, page_size: NonZeroU16) -> Result<CacheRef, Error> {
    Ok(CacheRef::from_pooler(
        context,
        legacy_page_size(page_size)?,
        MIGRATION_CACHE_PAGES,
    ))
}

fn legacy_write_buffer(page_size: NonZeroU16) -> Result<NonZeroUsize, Error> {
    let page_size = usize::from(legacy_page_size(page_size)?.get());
    NonZeroUsize::new(page_size.checked_mul(2).ok_or(Error::UsizeTooSmall)?)
        .ok_or(Error::UsizeTooSmall)
}

/// A V2-native [`Contiguous`] journal that supports append, rewind, prune, and atomic sync.
///
/// Mutating methods consume the journal. If one fails or its future is cancelled, reopen the
/// journal rather than reusing partially updated in-memory state.
pub trait MutableV2: Contiguous + Sized {
    /// Append one item and return its stable position.
    fn append(
        self,
        item: &Self::Item,
    ) -> impl std::future::Future<Output = Result<(Self, u64), Error>> + Send;

    /// Append one or more item slices and return the last appended position.
    ///
    /// Returns [`Error::EmptyAppend`] if `items` is empty.
    fn append_many(
        self,
        items: Many<'_, Self::Item>,
    ) -> impl std::future::Future<Output = Result<(Self, u64), Error>> + Send
    where
        Self::Item: Sync;

    /// Prune items strictly before `min_position` where section alignment permits.
    ///
    /// Returns whether any data was pruned.
    fn prune(
        self,
        min_position: u64,
    ) -> impl std::future::Future<Output = Result<(Self, bool), Error>> + Send;

    /// Rewind the journal to contain exactly `size` items.
    fn rewind(self, size: u64) -> impl std::future::Future<Output = Result<Self, Error>> + Send;

    /// Begin atomically publishing the current journal state.
    ///
    /// A successful call starts publication of the state present when the call began and returns
    /// that state as a new journal value. Awaiting the returned handle waits until publication is
    /// durable and active. Mutations made through the returned journal belong to the next epoch
    /// and require another sync. Dropping the handle does not cancel publication.
    fn start_sync(
        self,
    ) -> impl std::future::Future<Output = Result<(Self, Handle<()>), Error>> + Send;

    /// Atomically publish the current journal state and wait until it is active.
    fn sync(self) -> impl std::future::Future<Output = Result<Self, Error>> + Send;

    /// Destroy all journal storage.
    ///
    /// This final teardown is not crash-safe. Use a concrete journal's reset operation when the
    /// journal must remain recoverable if teardown is interrupted.
    fn destroy(self) -> impl std::future::Future<Output = Result<(), Error>> + Send;

    /// Rewind to the last item matching `predicate`, or to the pruning boundary if none match.
    fn rewind_to<P>(
        mut self,
        predicate: P,
    ) -> impl std::future::Future<Output = Result<(Self, u64), Error>> + Send
    where
        P: FnMut(&Self::Item) -> bool + Send,
    {
        async move {
            let rewind_size = scan_rewind_size(&self, predicate).await?;
            if rewind_size != self.bounds().end {
                self = self.rewind(rewind_size).await?;
            }
            Ok((self, rewind_size))
        }
    }
}

pub mod fixed;
pub mod variable;
