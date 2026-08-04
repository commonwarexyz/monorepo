//! The atomic blob handle: append-only, WAL-owned length, all-or-nothing publication.
//!
//! Mutations stage in memory (visible to this handle's reads immediately) and become
//! durable only at [crate::AtomicBlob::publish]. An epoch of staged operations folds to a
//! canonical pair: at most one rewind (to the lowest cut) followed by one contiguous
//! run of appended bytes. Two publication routes:
//!
//! - **Inline**: the folded run rides inside records (one atomic frame). One WAL
//!   barrier, no file I/O; the bytes live in the WAL (the row's overlay) until a bulk
//!   publication or a checkpoint snapshot carries them forward.
//! - **Bulk**: materialize everything unapplied (the row's overlay plus the folded
//!   run) into the file at final offsets, barrier the file and, first time, its
//!   dentry chain (the wave), then journal one CommitAtomic. Rule M: the record
//!   asserting file content is written only after the barrier covering that content
//!   completed, which [super::medium::Checked] verifies in tests.
//!
//! A rewind lowers the committed length by record alone: reads clamp at the trust
//! watermark, so file bytes above the cut are dead without any truncation. One case
//! splits publication: a bulk epoch whose cut reaches below the *trusted* length
//! journals its rewind (one barrier) before reusing file offsets, so a torn write
//! can never destroy committed bytes recovery may still serve. The inline route
//! writes no file bytes and never splits: rewind-then-append below trusted is a
//! single barrier.
//!
//! Publications on one handle family serialize; several blobs of one partition
//! publish all-or-nothing through [super::Storage::publish_all]. Reads resolve
//! sources under locks and perform file I/O with the locks released.

use super::{
    committer::{Ack, Committer, Stage},
    format::{INLINE_APPEND_MAX, Kind, OVERLAY_MAX, Record},
    medium::{Claim, File as _, Medium},
};
use crate::{Error, Handle, IoBufMut, IoBufsMut};
use bytes::Bytes;
use commonware_formatting::hex;
use commonware_utils::sync::Mutex;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

/// One staged, unpublished mutation.
#[derive(Clone)]
pub(super) enum Op {
    Append(Bytes),
    Rewind(u64),
}

/// State shared by clones of one atomic handle.
struct Core {
    /// Staged operations, in order.
    ops: Vec<Op>,
    /// Logical length including staged operations (what this handle reads).
    visible: u64,
    /// True while a publication owns the staged prefix; publications serialize.
    publishing: bool,
}

/// A handle to one atomic blob. Clones share staged state.
pub struct AtomicBlob<M: Medium> {
    medium: M,
    file: M::File,
    committer: Committer,
    id: u64,
    partition: String,
    name: Vec<u8>,
    filename: String,
    data_offset: u64,
    core: Arc<Mutex<Core>>,
    /// Whether some handle already completed the dentry wave (see [super::blob]).
    dentry_synced: Arc<AtomicBool>,
}

impl<M: Medium> Clone for AtomicBlob<M> {
    fn clone(&self) -> Self {
        Self {
            medium: self.medium.clone(),
            file: self.file.clone(),
            committer: self.committer.clone(),
            id: self.id,
            partition: self.partition.clone(),
            name: self.name.clone(),
            filename: self.filename.clone(),
            data_offset: self.data_offset,
            core: self.core.clone(),
            dentry_synced: self.dentry_synced.clone(),
        }
    }
}

/// The row's committed state, snapshotted from the catalog.
struct Committed {
    committed: u64,
    trusted: u64,
    overlay: Vec<u8>,
}

/// An epoch folded to canonical form: rewind to `anchor` (when below the base
/// committed length), then append `run` at `anchor`. Every mix of appends and
/// rewinds reduces to this, because appends only ever extend the tail.
struct Folded {
    anchor: u64,
    run: Vec<u8>,
}

impl Folded {
    /// Folds `ops` against a committed length of `base`.
    fn new(base: u64, ops: &[Op]) -> Self {
        let mut anchor = base;
        let mut tail = base;
        let mut run: Vec<u8> = Vec::new();
        for op in ops {
            match op {
                Op::Append(data) => {
                    debug_assert_eq!(anchor + run.len() as u64, tail);
                    run.extend_from_slice(data);
                    tail += data.len() as u64;
                }
                Op::Rewind(cut) => {
                    run.truncate(cut.saturating_sub(anchor) as usize);
                    anchor = anchor.min(*cut);
                    tail = *cut;
                }
            }
        }
        Self { anchor, run }
    }

    /// The epoch's final logical length.
    const fn len(&self) -> u64 {
        self.anchor + self.run.len() as u64
    }
}

impl<M: Medium> AtomicBlob<M> {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        medium: M,
        file: M::File,
        committer: Committer,
        id: u64,
        partition: &str,
        name: &[u8],
        data_offset: u64,
        committed: u64,
    ) -> Self {
        Self {
            medium,
            file,
            committer,
            id,
            partition: partition.to_string(),
            name: name.to_vec(),
            filename: hex(name),
            data_offset,
            core: Arc::new(Mutex::new(Core {
                ops: Vec::new(),
                visible: committed,
                publishing: false,
            })),
            dentry_synced: Arc::new(AtomicBool::new(false)),
        }
    }

    /// The blob's logical length, including staged (unpublished) operations.
    fn size_inner(&self) -> u64 {
        self.core.lock().visible
    }

    /// Stages `data` at the end of the blob: visible to this handle's reads
    /// immediately, durable once a publication containing it acknowledges.
    fn append_inner(&self, data: impl Into<Bytes>) -> Result<(), Error> {
        let data = data.into();
        let mut core = self.core.lock();
        core.visible = core
            .visible
            .checked_add(data.len() as u64)
            .ok_or(Error::OffsetOverflow)?;
        core.ops.push(Op::Append(data));
        Ok(())
    }

    /// Stages a rewind to `len`. Fails if `len` exceeds the visible length.
    fn rewind_inner(&self, len: u64) -> Result<(), Error> {
        let mut core = self.core.lock();
        if len > core.visible {
            return Err(Error::BlobInsufficientLength);
        }
        core.visible = len;
        core.ops.push(Op::Rewind(len));
        Ok(())
    }

    /// The row's committed state. A deleted row reads as closed.
    fn committed(&self) -> Result<Committed, Error> {
        self.committer.shared().read(|catalog| {
            let row = catalog
                .get(&self.partition, &self.name)
                .filter(|row| row.id == self.id)
                .ok_or(Error::Closed)?;
            match &row.kind {
                Kind::Atomic {
                    committed,
                    trusted,
                    overlay,
                } => Ok(Committed {
                    committed: *committed,
                    trusted: *trusted,
                    overlay: overlay.clone(),
                }),
                Kind::Ordinary => Err(Error::Closed),
            }
        })
    }

    /// Reads `len` bytes at `offset`. Sources resolve under locks (committed state,
    /// staged fold); file I/O happens with the locks released. Assembly order is
    /// file, then overlay, then the staged fold, so later state shadows earlier.
    async fn read_at_inner(&self, offset: u64, len: usize) -> Result<IoBufsMut, Error> {
        let end = offset
            .checked_add(len as u64)
            .ok_or(Error::OffsetOverflow)?;
        let (state, folded) = {
            let state = self.committed()?;
            let core = self.core.lock();
            if end > core.visible {
                return Err(Error::BlobInsufficientLength);
            }
            let folded = Folded::new(state.committed, &core.ops);
            (state, folded)
        };

        let mut assembled = vec![0u8; len];
        // File bytes serve [0, trusted), except where the staged fold cut below.
        let file_end = state.trusted.min(folded.anchor).min(end);
        if offset < file_end {
            let file_len = (file_end - offset) as usize;
            let bytes = self
                .file
                .read_at(self.data_offset + offset, file_len)
                .await?;
            assembled[..file_len].copy_from_slice(&bytes);
        }
        copy_range(&mut assembled, offset, state.trusted, &state.overlay);
        copy_range(&mut assembled, offset, folded.anchor, &folded.run);

        let mut bufs: IoBufsMut = IoBufMut::with_capacity(len).into();
        // SAFETY: `copy_from_slice` fills exactly `len` bytes below.
        unsafe { bufs.set_len(len) };
        bufs.copy_from_slice(&assembled);
        Ok(bufs)
    }

    /// Runs the publication protocol up to staging, returning the acknowledgment to
    /// await (None when nothing was staged). Used directly by multi-blob batches.
    pub(super) async fn stage_publish(&self) -> Result<Option<Ack>, Error> {
        let Some(ops) = self.freeze()? else {
            return Ok(None);
        };
        let count = ops.len();
        let result = match self.plan(&ops, true).await {
            Ok(records) if records.is_empty() => Ok(None),
            Ok(records) => self.stage(records).map(Some),
            Err(error) => Err(error),
        };
        self.unfreeze(count, result.is_err());
        result
    }

    /// Freezes the staged epoch for publication: clones the current prefix and
    /// claims it, leaving the operations in place so this handle's reads stay
    /// continuous throughout (the staged records reproduce the same content, so the
    /// still-staged prefix is idempotent against the applied catalog). Returns None
    /// when nothing is staged. Hand the claim back through [Self::unfreeze].
    pub(super) fn freeze(&self) -> Result<Option<Vec<Op>>, Error> {
        let mut core = self.core.lock();
        if core.publishing {
            return Err(Error::Io(Arc::new(std::io::Error::other(
                "a publication is already in flight for this blob",
            ))));
        }
        if core.ops.is_empty() {
            return Ok(None);
        }
        core.publishing = true;
        Ok(Some(core.ops.clone()))
    }

    /// Releases the publication claim over the first `count` staged operations: a
    /// successful publication retires them (their records now carry the state); a
    /// failed one leaves them staged, keeping this handle's view coherent.
    pub(super) fn unfreeze(&self, count: usize, failed: bool) {
        let mut core = self.core.lock();
        core.publishing = false;
        if !failed {
            core.ops.drain(..count);
        }
    }

    /// Prepares one frozen epoch (see the module docs for the two routes): performs
    /// any file work and its wave, and returns the records to stage (empty when the
    /// epoch folded to nothing).
    ///
    /// `allow_split` permits journaling a below-trusted rewind on its own barrier
    /// first, which single-blob publication needs for bulk epochs. A multi-blob
    /// batch forbids it (the early rewind would be visible without its batch) and
    /// rejects such epochs instead.
    pub(super) async fn plan(&self, ops: &[Op], allow_split: bool) -> Result<Vec<Record>, Error> {
        let state = self.committed()?;
        let folded = Folded::new(state.committed, ops);

        // Inline: the whole epoch as records, one barrier, no file I/O. The
        // resulting overlay is bounded, so snapshot rows stay bounded too.
        let overlay_after = folded.len() - state.trusted.min(folded.anchor).min(folded.len());
        if folded.run.len() <= INLINE_APPEND_MAX && overlay_after <= OVERLAY_MAX as u64 {
            let mut records = Vec::new();
            if folded.anchor < state.committed {
                records.push(Record::Rewind {
                    id: self.id,
                    len: folded.anchor,
                });
            }
            if !folded.run.is_empty() {
                records.push(Record::InlineAppend {
                    id: self.id,
                    offset: folded.anchor,
                    bytes: folded.run.clone(),
                });
            }
            // An empty fold (e.g. rewind to the committed length) is a no-op.
            return Ok(records);
        }

        // Bulk. A cut below the trusted length journals first (its own barrier):
        // file offsets in [cut, trusted) hold committed bytes recovery may still
        // serve, and they must be dead before a torn write can land on them.
        let mut trusted = state.trusted;
        if folded.anchor < trusted {
            if !allow_split {
                return Err(Error::Io(Arc::new(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "a bulk epoch rewinding below the trusted length cannot join a \
                     multi-blob batch; publish this blob alone",
                ))));
            }
            let (ack, ()) = self.committer.transact(|_| {
                (
                    Stage::Record(Record::Rewind {
                        id: self.id,
                        len: folded.anchor,
                    }),
                    (),
                )
            })?;
            ack.expect("rewind staged")
                .await
                .map_err(|_| Error::Closed)??;
            trusted = folded.anchor;
        }

        // Materialize everything the file lacks, [trusted, len), from the overlay
        // and the folded run; wave; then one CommitAtomic supersedes the epoch.
        let len = folded.len();
        let mut image = vec![0u8; (len - trusted) as usize];
        copy_range(&mut image, trusted, state.trusted, &state.overlay);
        copy_range(&mut image, trusted, folded.anchor, &folded.run);
        self.file
            .write_at(self.data_offset + trusted, image)
            .await?;
        self.file.sync().await?;
        if !self.dentry_synced.load(Ordering::Acquire) {
            self.medium.sync_dir(&self.partition).await?;
            self.medium.sync_root().await?;
            self.dentry_synced.store(true, Ordering::Release);
        }
        Ok(vec![Record::CommitAtomic { id: self.id, len }])
    }

    /// The committer this blob publishes through (for same-family checks).
    pub(super) const fn committer(&self) -> &Committer {
        &self.committer
    }

    /// The partition this blob lives in.
    pub(super) fn partition(&self) -> &str {
        &self.partition
    }

    /// Verifies this record's rule-M claims (for batch staging).
    pub(super) fn verify_claims(&self, record: &Record) {
        self.debug_claims(record);
    }

    /// Stages this epoch's records (as one atomic frame when several), after
    /// verifying rule-M claims.
    fn stage(&self, mut records: Vec<Record>) -> Result<Ack, Error> {
        for record in &records {
            self.debug_claims(record);
        }
        let record = if records.len() == 1 {
            records.pop().expect("one record")
        } else {
            Record::Batch(records)
        };
        let (ack, ()) = self.committer.transact(|_| (Stage::Record(record), ()))?;
        Ok(ack.expect("publication staged"))
    }

    /// Rule M, machine-checked in tests: a record asserting file durability must be
    /// staged only after the barrier covering that state completed.
    fn debug_claims(&self, record: &Record) {
        if let Record::CommitAtomic { len, .. } = record {
            debug_assert!(
                self.medium.covered(&Claim::FileBytes {
                    dir: &self.partition,
                    name: &self.filename,
                    start: self.data_offset,
                    end: self.data_offset + len,
                }),
                "CommitAtomic asserts uncovered file bytes"
            );
            debug_assert!(
                self.medium.covered(&Claim::Dentry {
                    dir: &self.partition,
                    name: &self.filename,
                }),
                "CommitAtomic asserts an uncovered dentry"
            );
        }
    }
}

impl<M: Medium> crate::AtomicBlob for AtomicBlob<M> {
    fn size(&self) -> u64 {
        self.size_inner()
    }

    fn append(&self, data: impl Into<Bytes>) -> Result<(), Error> {
        self.append_inner(data)
    }

    fn rewind(&self, len: u64) -> Result<(), Error> {
        self.rewind_inner(len)
    }

    async fn read_at(&self, offset: u64, len: usize) -> Result<IoBufsMut, Error> {
        self.read_at_inner(offset, len).await
    }

    async fn publish(&self) -> Result<(), Error> {
        match self.stage_publish().await? {
            Some(ack) => ack.await.map_err(|_| Error::Closed)?,
            None => Ok(()),
        }
    }

    async fn start_publish(&self) -> Handle<()> {
        match self.stage_publish().await {
            Ok(Some(ack)) => Handle::from_receiver(ack),
            Ok(None) => Handle::ready(Ok(())),
            Err(error) => Handle::ready(Err(error)),
        }
    }
}

/// Copies the overlap between `source` (logically starting at `source_start`) and
/// the window starting at `window_start` into `window`.
fn copy_range(window: &mut [u8], window_start: u64, source_start: u64, source: &[u8]) {
    let window_end = window_start + window.len() as u64;
    let source_end = source_start + source.len() as u64;
    let start = window_start.max(source_start);
    let end = window_end.min(source_end);
    if start >= end {
        return;
    }
    let len = (end - start) as usize;
    window[(start - window_start) as usize..][..len]
        .copy_from_slice(&source[(start - source_start) as usize..][..len]);
}
