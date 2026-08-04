//! Opt-in append-only atomic storage interfaces.

use crate::{Blob, DEFAULT_BLOB_VERSION, Error, Handle, IoBufs, Storage};
use std::future::Future;

/// An operation in a durable [`BatchStorage::apply`] batch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BatchOperation<B> {
    /// Delete the current atomic blob generation.
    Remove(B),
    /// Publish pending appends to a retained atomic blob.
    Publish(B),
    /// Rewind a retained atomic blob to `len` bytes.
    Rewind {
        /// Current atomic blob handle to rewind.
        blob: B,
        /// New logical blob length in bytes, which cannot exceed its current length.
        len: u64,
    },
}

/// Opt-in interface for opening blobs that support crash-atomic journal mutations.
///
/// Ordinary [`Storage::open`] and [`Storage::open_versioned`] retain the flat blob layout and
/// behavior used by runtimes that do not opt into this capability. Atomic blobs use a distinct
/// append-only layout. Appended payload occupies its final offset and is written once. A rewind
/// that crosses the last published length fences further appends until synchronization publishes
/// the shorter length and truncates the file. Recovery exposes either the preceding synced epoch
/// or the complete new epoch while reading only bounded metadata and, for an unresolved batch, a
/// bounded appended suffix. A failed or canceled mutation after physical I/O admission poisons
/// that open generation.
pub trait AtomicStorage: Storage {
    /// Blob type returned by atomic opens.
    type AtomicBlob: AtomicBlob;

    /// Consume an opened blob and durably replace its current name with an atomic blob.
    ///
    /// The blob's logical contents and application-owned blob version are preserved. Pending
    /// writes on `blob` are synchronized before migration. If the blob already uses the atomic
    /// layout, it is synchronized and left in place.
    ///
    /// The caller must ensure no other handle mutates the blob during migration. Handles that
    /// remain open across a replacement continue to refer to the prior blob generation and may
    /// remain readable, as described by [`Storage::remove`]. Their mutation behavior is
    /// unspecified. After this method succeeds, reopen the name with
    /// [`AtomicStorage::open_atomic`] or [`AtomicStorage::open_atomic_versioned`].
    ///
    /// An `Ok` result means the current name durably refers to the atomic layout. An error or
    /// cancellation may leave either layout at the current name; retry by reopening the name
    /// rather than reusing an existing handle. Filesystem implementations stream through a
    /// replacement inode with bounded memory, but temporarily require enough free space for
    /// another complete copy. Migrating names independently is resumable because migrating an
    /// existing atomic blob is idempotent.
    fn migrate_atomic(&self, blob: Self::Blob) -> impl Future<Output = Result<(), Error>> + Send;

    /// [`AtomicStorage::open_atomic_versioned`] with [`DEFAULT_BLOB_VERSION`] as the only accepted
    /// blob version.
    fn open_atomic(
        &self,
        partition: &str,
        name: &[u8],
    ) -> impl Future<Output = Result<(Self::AtomicBlob, u64), Error>> + Send {
        async move {
            let (blob, size, _) = self
                .open_atomic_versioned(partition, name, DEFAULT_BLOB_VERSION..=DEFAULT_BLOB_VERSION)
                .await?;
            Ok((blob, size))
        }
    }

    /// Open an existing atomic blob or create a new one, returning its logical length and
    /// application-owned blob version.
    ///
    /// A blob previously created through ordinary [`Storage`] methods is not converted in place.
    /// Implementations return an error rather than rewriting its format implicitly.
    fn open_atomic_versioned(
        &self,
        partition: &str,
        name: &[u8],
        versions: std::ops::RangeInclusive<u16>,
    ) -> impl Future<Output = Result<(Self::AtomicBlob, u64, u16), Error>> + Send;
}

/// Opt-in interface for publishing atomic blobs and applying namespace mutations atomically.
///
/// The filesystem implementations publish batches without a separate coordinator. Each
/// participant retains a checksummed local witness that describes its candidate and points to the
/// next exact participant incarnation. These links form a closed ring, so opening any participant
/// after a restart discovers and repairs the complete group without scanning unrelated blobs. A
/// deleted participant first becomes a durable tombstone and is unlinked only after every
/// participant has an independently recoverable final root.
///
/// Before links are constructed, participants are ordered lexicographically by partition and then
/// raw blob-name bytes. The same order determines ring ordinals and filesystem lock acquisition,
/// so equivalent participant sets produce the same ring regardless of caller order.
pub trait BatchStorage: AtomicStorage {
    /// Start publishing, deleting, and rewinding atomic blobs as one durable batch.
    ///
    /// A mutated handle must belong to this storage instance and still refer to the current blob at
    /// its partition and name. Missing mutation targets fail the batch. Each blob may have at most
    /// one distinct mutation: identical duplicates are permitted, while conflicting mutations are
    /// rejected. Deletion requires a current atomic blob handle; whole-partition deletion remains
    /// available through [`Storage::remove`] but is not an atomic batch operation. Empty batches
    /// succeed.
    ///
    /// Deletion unlinks the name without truncating its inode. Existing handles remain readable,
    /// including pending bytes, but can no longer authorize a batch for a same-name replacement. As
    /// with [`Storage::remove`], mutating a deleted handle is unspecified.
    ///
    /// If this method returns `Ok`, the entire batch is durably committed and will finish applying
    /// even if the returned handle is dropped or aborted. Awaiting the handle waits until the
    /// committed logical state is active and any required namespace effects finish. A conflicting
    /// namespace operation waits for the batch to finish. Rejecting an invalid batch leaves every
    /// target unchanged. Other errors, or cancellation of this future, may leave the outcome
    /// indeterminate. Only `Ok` proves the batch is durably committed.
    ///
    /// Publishing or rewinding a blob makes its pending mutation durable. A rewind preserves
    /// existing bytes below `len` and cannot extend a blob. Once this method returns `Ok`, retained
    /// participant handles may begin their next pending epoch. Implementations serialize that
    /// access until the committed in-memory epoch is active. Implementations may retain the durable
    /// batch decision while participant roots are folded into a later batch. Reopening or
    /// performing a conflicting non-batch operation completes that bounded repair transparently.
    /// An unresolved write-only batch may verify a bounded amount of newly written payload during
    /// that repair. It never scans whole blobs or historical payload. Operations on disjoint,
    /// already-open blobs may proceed concurrently. Deletion-bearing batches instead materialize
    /// retained roots and payload-preserving tombstones eagerly, then unlink and synchronize
    /// affected parent directories before the returned completion handle resolves.
    ///
    /// # Filesystem Eligibility
    ///
    /// Group membership has no UNO-specific limit and is not coupled to aggregate blob-name bytes:
    /// each 2 KiB root slot stores only a 296-byte fixed local witness plus one successor path of at
    /// most 1,644 combined partition/name bytes. The format's `u32` count is the only participant-
    /// count bound. Implementations use at most 32 installation workers at once; worker fanout does
    /// not limit group membership. Total pending append bytes have no protocol batch limit. At most
    /// 64 MiB is left for revalidation after a crash; larger or non-contiguous pending epochs make
    /// older immutable payload durable before roots are staged rather than being rejected. Clean
    /// publishes do not count as participants.
    fn start_apply(
        &self,
        operations: Vec<BatchOperation<Self::AtomicBlob>>,
    ) -> impl Future<Output = Result<Handle<()>, Error>> + Send;

    /// Publish, delete, and rewind atomic blobs as one durable batch.
    fn apply(
        &self,
        operations: Vec<BatchOperation<Self::AtomicBlob>>,
    ) -> impl Future<Output = Result<(), Error>> + Send {
        async move { self.start_apply(operations).await?.await }
    }
}

/// Number of application-owned bytes carried by an atomic blob root.
///
/// The tag is published atomically with the blob's logical length.
pub const ATOMIC_BLOB_TAG_LEN: usize = crate::storage::ATOMIC_BLOB_TAG_LEN;

/// Opt-in interface for atomic, immediately visible journal mutations.
///
/// On an atomic blob, [`Blob::write_at`] accepts only the current logical tail and [`Blob::resize`]
/// accepts only a shorter length. Prefer the explicit methods below. Rewinding below the last
/// synchronized length fences appends until a successful [`Blob::sync`] or completed
/// [`Blob::start_sync`] publishes the rewind.
pub trait AtomicBlob: Blob {
    /// Return the application-owned tag in the blob's current root.
    ///
    /// A newly created blob starts with an all-zero tag. Changes made through
    /// [`AtomicBlob::set_tag`] are immediately visible through this handle and become durable with
    /// the same [`Blob::sync`], [`Blob::start_sync`], or batch publication as the blob's pending
    /// append or rewind.
    fn tag(&self) -> impl Future<Output = Result<[u8; ATOMIC_BLOB_TAG_LEN], Error>> + Send;

    /// Stage an application-owned tag to publish with this blob's logical length.
    ///
    /// Setting the current tag is a no-op. The tag is covered by the atomic root checksum and
    /// participates in batch recovery, so it must contain only state whose meaning is local to this
    /// blob or to the exact batch that publishes it.
    fn set_tag(
        &self,
        tag: [u8; ATOMIC_BLOB_TAG_LEN],
    ) -> impl Future<Output = Result<(), Error>> + Send;

    /// Append `data` and return its starting logical offset.
    ///
    /// The bytes become immediately visible but require a subsequent successful sync to become
    /// durable. Empty data succeeds without changing the blob. An append after rewinding committed
    /// bytes returns `InvalidInput` until that rewind is synchronized.
    fn append(
        &self,
        data: impl Into<IoBufs> + Send,
    ) -> impl Future<Output = Result<u64, Error>> + Send;

    /// Append `data` and stage `tag` as one in-memory mutation.
    ///
    /// A concurrent sync observes either both changes or neither change. The bytes and tag still
    /// require a subsequent successful sync to become durable.
    fn append_tagged(
        &self,
        data: impl Into<IoBufs> + Send,
        tag: [u8; ATOMIC_BLOB_TAG_LEN],
    ) -> impl Future<Output = Result<u64, Error>> + Send;

    /// Rewind the blob to `len`, which must not exceed its current logical length.
    ///
    /// Rewinding only unpublished appends permits immediate reuse of their physical tail.
    /// Rewinding committed bytes becomes durable at the next sync and fences appends until that
    /// sync completes successfully.
    fn rewind(&self, len: u64) -> impl Future<Output = Result<(), Error>> + Send;

    /// Rewind to `len` and stage `tag` as one in-memory mutation.
    ///
    /// A concurrent sync observes either both changes or neither change. The rewind and tag still
    /// require a subsequent successful sync to become durable.
    fn rewind_tagged(
        &self,
        len: u64,
        tag: [u8; ATOMIC_BLOB_TAG_LEN],
    ) -> impl Future<Output = Result<(), Error>> + Send;
}
