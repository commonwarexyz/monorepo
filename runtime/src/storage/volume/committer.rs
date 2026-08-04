//! The committer: one task per volume that turns staged state into journal records and
//! group-commits any number of concurrent requests under a single barrier.
//!
//! A batch normally appends its records to the live extent and syncs once. When the
//! extent cannot hold the records, the batch instead becomes a checkpoint: the entire
//! catalog is written as a snapshot at the head of a fresh extent and a new root is
//! published. The snapshot subsumes the batch (its changes are already applied in
//! memory), so the batch's records are simply discarded.
//!
//! Why an acknowledged request is durable: its payload writes completed before it was
//! staged, its record write completed before the barrier was issued, and the barrier is
//! the inner blob's `sync` on the one file holding both.

use super::{
    format::{MAX_EXTENT_BYTES, PAGE, ROOT_OFFSETS, Record, Root},
    state::Core,
    volume::{Journal, Shared, write_zeros},
};
use crate::{Blob as _, Error, WriteOptions};
use commonware_utils::channel::{mpsc, oneshot};
use std::sync::{Arc, Weak, atomic::Ordering};

/// Most requests drained into one batch.
const MAX_BATCH_REQUESTS: usize = 1024;

/// Zero-write budget per batch: how much raw-pool space each commit converts back into
/// allocatable (durably zero) space. Riding the batch's own barrier makes zeroing free of
/// extra flushes, and any workload that allocates also commits, so the pools converge
/// without dedicated zeroing machinery.
const ZERO_BUDGET: u64 = 2 << 20;

/// Capacity floor for a fresh journal extent.
const MIN_EXTENT_BYTES: u64 = 256 << 10;

/// A fresh extent holds this multiple of its snapshot, bounding both checkpoint frequency
/// (amortization) and replay cost at open.
const EXTENT_SLACK: u64 = 4;

/// One operation submitted to the committer.
pub(super) enum Request {
    /// Journal the blob's staged state, or just ride the barrier if it has none.
    Sync {
        core: Arc<Core>,
        done: oneshot::Sender<Result<(), Error>>,
    },
    /// Journal a creation.
    Create {
        core: Arc<Core>,
        done: oneshot::Sender<Result<(), Error>>,
    },
    /// Journal a deletion. `chunks` is the blob's whole chunk set, frozen at removal
    /// (mutations through surviving handles fail after removal).
    Delete {
        id: u64,
        chunks: Vec<u32>,
        holder: Weak<Core>,
        done: oneshot::Sender<Result<(), Error>>,
    },
}

/// Runs the volume's commit loop until every request sender is dropped or a commit fails.
pub(super) async fn run<S: crate::Storage>(
    shared: Arc<Shared<S>>,
    mut journal: Journal,
    mut requests: mpsc::UnboundedReceiver<Request>,
) {
    while let Some(first) = requests.recv().await {
        let mut batch = vec![first];
        while batch.len() < MAX_BATCH_REQUESTS {
            match requests.try_recv() {
                Ok(request) => batch.push(request),
                Err(_) => break,
            }
        }

        journal.batch += 1;
        let (records, acks) = prepare(&shared, journal.batch, batch);
        match execute(&shared, &mut journal, records).await {
            Ok(()) => {
                shared.durable_batch.store(journal.batch, Ordering::Release);
                shared.allocator.lock().exhume(journal.batch, &shared.pins);
                for ack in acks {
                    let _ = ack.send(Ok(()));
                }
            }
            Err(error) => {
                // The file's page-cache state is unknowable after a failed write or
                // barrier. Poison the volume and exit; queued and future requests fail
                // through the closed channel.
                tracing::error!(partition = %shared.partition, %error, "volume commit failed");
                shared.poisoned.store(true, Ordering::Release);
                for ack in acks {
                    let _ = ack.send(Err(shared.poisoned_error()));
                }
                return;
            }
        }
    }
}

/// Drains a batch's staged state into records, tagging graves and creations with `batch`.
fn prepare<S: crate::Storage>(
    shared: &Shared<S>,
    batch: u64,
    requests: Vec<Request>,
) -> (Vec<Record>, Vec<oneshot::Sender<Result<(), Error>>>) {
    let mut records = Vec::new();
    let mut acks = Vec::with_capacity(requests.len());
    for request in requests {
        match request {
            Request::Sync { core, done } => {
                let (drained, freed) = core.state.lock().drain();
                shared.allocator.lock().bury(freed, None, batch);
                if let Some(drained) = drained {
                    records.push(Record::Update {
                        id: core.id,
                        trunc_floor: drained.trunc_floor,
                        len: drained.len,
                        mappings: drained.mappings,
                    });
                }
                acks.push(done);
            }
            Request::Create { core, done } => {
                // A checkpoint may have subsumed this creation into a snapshot row
                // before we drained the request; a second create would corrupt replay.
                if core.created_batch.load(Ordering::Acquire) == u64::MAX {
                    core.created_batch.store(batch, Ordering::Release);
                    records.push(Record::Create {
                        id: core.id,
                        version: core.version,
                        name: core.name.clone(),
                        len: 0,
                        mappings: Vec::new(),
                    });
                }
                acks.push(done);
            }
            Request::Delete {
                id,
                chunks,
                holder,
                done,
            } => {
                shared.allocator.lock().bury(chunks, Some(holder), batch);
                records.push(Record::Delete { id });
                acks.push(done);
            }
        }
    }
    (records, acks)
}

/// Commits a batch: appends its records under one barrier, or checkpoints when the live
/// extent cannot hold them.
async fn execute<S: crate::Storage>(
    shared: &Shared<S>,
    journal: &mut Journal,
    records: Vec<Record>,
) -> Result<(), Error> {
    let chunk_size = shared.geometry.chunk_size;
    let mut bytes = Vec::new();
    for record in &records {
        record.encode(journal.epoch, &mut bytes);
    }
    if journal.used + bytes.len() as u64 > journal.extent.len(chunk_size) {
        return checkpoint(shared, journal).await;
    }

    // Piggyback zero-writes: convert raw chunks back into allocatable space under this
    // batch's barrier.
    let budget = (ZERO_BUDGET / u64::from(chunk_size)).max(1) as usize;
    let zeroing = shared.allocator.lock().take_raw(budget);
    for &chunk in &zeroing {
        let offset = shared.geometry.chunk_offset(chunk);
        write_zeros(&shared.file, offset, u64::from(chunk_size)).await?;
        shared.high_water.extend(offset + u64::from(chunk_size));
    }

    if !bytes.is_empty() {
        let offset = journal.extent.offset(chunk_size) + journal.used;
        journal.used += bytes.len() as u64;
        shared
            .file
            .write_at(offset, bytes, WriteOptions::default())
            .await?;
    }

    shared.file.sync().await?;
    shared.allocator.lock().zeroed(zeroing);
    Ok(())
}

/// Writes the whole catalog as the head of a fresh extent and flips the root to it.
async fn checkpoint<S: crate::Storage>(
    shared: &Shared<S>,
    journal: &mut Journal,
) -> Result<(), Error> {
    let chunk_size = shared.geometry.chunk_size;
    // Unreachable by counting; reachable from adversarial roots. Erroring poisons the
    // volume rather than wrapping into an invalid root.
    let epoch = journal.epoch.checked_add(1).ok_or(Error::OffsetOverflow)?;
    let seq = journal
        .root_seq
        .checked_add(1)
        .ok_or(Error::OffsetOverflow)?;

    // Snapshot every row and reset all staged state: the snapshot journals everything,
    // including staged changes of blobs that never asked for this commit (an early
    // durability over-delivery the contract permits).
    let cores: Vec<Arc<Core>> = shared.catalog.lock().blobs.values().cloned().collect();
    let mut rows = Vec::with_capacity(cores.len());
    let mut freed = Vec::new();
    for core in cores {
        let mut state = core.state.lock();
        // Snapshot rows subsume pending creations; their queued create requests must
        // not journal a second create (see `prepare`).
        let _ = core.created_batch.compare_exchange(
            u64::MAX,
            journal.batch,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
        freed.extend(state.snapshotted());
        rows.push(Record::Create {
            id: core.id,
            version: core.version,
            name: core.name.clone(),
            len: state.len,
            mappings: state
                .map
                .iter()
                .map(|(&slot, &chunk)| (slot, chunk))
                .collect(),
        });
    }
    shared.allocator.lock().bury(freed, None, journal.batch);

    // Replay requires create ids to increase within an epoch.
    rows.sort_by_key(|row| match row {
        Record::Create { id, .. } => *id,
        _ => unreachable!("snapshot rows are creates"),
    });
    let mut bytes = Vec::new();
    for row in &rows {
        row.encode(epoch, &mut bytes);
    }

    // Size the new extent to amortize: it fits several snapshots' worth of records, so
    // replay at open is bounded by a small multiple of live catalog size. The hard cap
    // exists so recovery can reject hostile extents; a snapshot too large to fit is a
    // catalog beyond the volume's design capacity.
    if bytes.len() as u64 > MAX_EXTENT_BYTES {
        return Err(Error::OffsetOverflow);
    }
    let target = (bytes.len() as u64 * EXTENT_SLACK).clamp(MIN_EXTENT_BYTES, MAX_EXTENT_BYTES);
    let chunks = target
        .div_ceil(u64::from(chunk_size))
        .try_into()
        .map_err(|_| Error::OffsetOverflow)?;
    let (extent, needs_zero) = shared.allocator.lock().allocate_extent(chunks);

    // The extent must be durably zero before the root names it: that is what makes the
    // first zero byte at a record boundary an exact end-of-log at replay, and what
    // guarantees the extent's bytes physically exist (replay treats a file shorter than
    // the extent as damage).
    if needs_zero {
        write_zeros(
            &shared.file,
            extent.offset(chunk_size),
            extent.len(chunk_size),
        )
        .await?;
        shared.file.sync().await?;
    }
    shared.high_water.extend(extent.end(chunk_size));

    // Snapshot, then root, each under its own barrier: a crash between them leaves the
    // old root governing an intact old extent.
    let used = bytes.len() as u64;
    shared
        .file
        .write_at(extent.offset(chunk_size), bytes, WriteOptions::default())
        .await?;
    shared.file.sync().await?;

    let root = Root { seq, epoch, extent };
    debug_assert_eq!(root.encode().len(), PAGE);
    shared
        .file
        .write_at(
            ROOT_OFFSETS[(root.seq & 1) as usize],
            root.encode(),
            WriteOptions::default(),
        )
        .await?;
    shared.file.sync().await?;

    // The old extent is unreachable once the new root is durable.
    let old = journal.extent;
    shared.allocator.lock().bury(
        (old.first_chunk..old.first_chunk + old.chunks).collect(),
        None,
        journal.batch,
    );

    journal.root_seq = root.seq;
    journal.epoch = epoch;
    journal.extent = extent;
    journal.used = used;
    Ok(())
}
