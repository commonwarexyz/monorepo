//! The committer: one task per family that group-commits staged records under shared
//! barriers.
//!
//! Staging applies a record to the shared catalog (validated and visible immediately,
//! as filesystem namespaces behave) and enqueues it; the committer drains any number
//! of concurrent requests, appends their frames as one contiguous write, syncs once,
//! and acknowledges. K concurrent operations cost one barrier.
//!
//! When the live extent cannot hold a batch, the batch becomes a checkpoint instead:
//! the catalog snapshot at the head of the fresh extent already contains every staged
//! record, so the batch's own frames are discarded and its requests acknowledge on the
//! checkpoint's final barrier. The `subsumed` watermark extends the same argument to
//! requests staged before the snapshot but drained after it: journaling them again
//! would replay as duplicates, so they acknowledge frameless.
//!
//! A record-append or barrier failure poisons the family: the file's writeback state
//! is unknowable after a failed fdatasync, so every subsequent mutation fails. Poison
//! is scoped to this instance and never persisted; reopening runs recovery, which
//! judges the on-disk state on its own evidence.

use super::{
    catalog::Catalog,
    format::{MAX_RECORD_LEN, Record},
    journal::{Journal, MAX_DRAIN_BYTES},
    medium::Medium,
};
use crate::Error;
use commonware_utils::{
    channel::{mpsc, oneshot},
    sync::Mutex,
};
use futures::future::BoxFuture;
use std::{
    collections::VecDeque,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

/// Most requests drained into one batch. The byte bound in [MAX_DRAIN_BYTES] governs;
/// this just keeps a single drain's bookkeeping small.
const MAX_BATCH_REQUESTS: usize = 1024;

/// Spawns the committer task of each opened family. Runtime-owning code supplies this
/// from whatever executor it has.
pub type Spawn = Arc<dyn Fn(BoxFuture<'static, ()>) + Send + Sync>;

/// Receives one staged request's acknowledgment; Ok proves durability.
pub(super) type Ack = oneshot::Receiver<Result<(), Error>>;

/// State shared between stagers and the committer.
pub(super) struct Shared {
    state: Mutex<State>,
    /// Set on the first commit failure; checked before every staging.
    poisoned: AtomicBool,
}

struct State {
    catalog: Catalog,
    /// Stamps each staged request, in order.
    staged: u64,
    /// Requests stamped at or below this are contained in the last checkpoint's
    /// snapshot: durable already, and journaling them again would replay as
    /// duplicates.
    subsumed: u64,
}

/// One staged record awaiting durability, or a rider (no record) that just awaits
/// its batch's completion: because the queue is ordered, a rider acknowledges only
/// after everything staged before it is durable.
pub(super) struct Request {
    record: Option<Record>,
    seq: u64,
    done: oneshot::Sender<Result<(), Error>>,
}

/// What one catalog transaction stages.
pub(super) enum Stage {
    /// Nothing: the transaction only read (or failed validation).
    Nothing,
    /// No record, but an acknowledgment that rides the next batch: proof that every
    /// earlier-staged record is durable.
    Rider,
    /// A record to journal.
    Record(Record),
}

fn poisoned_error() -> Error {
    Error::Io(Arc::new(std::io::Error::other(
        "family poisoned by an earlier commit failure",
    )))
}

impl Shared {
    pub const fn new(catalog: Catalog) -> Self {
        Self {
            state: Mutex::new(State {
                catalog,
                staged: 0,
                subsumed: 0,
            }),
            poisoned: AtomicBool::new(false),
        }
    }

    /// Runs `f` over the catalog (reads only; every mutation goes through staging).
    pub fn read<T>(&self, f: impl FnOnce(&Catalog) -> T) -> T {
        f(&self.state.lock().catalog)
    }

    /// Mints a blob id for a record about to be staged.
    pub fn mint_id(&self) -> u64 {
        self.state.lock().catalog.mint_id()
    }
}

/// A handle staging records to one family's committer. Dropping every clone shuts the
/// committer down once its queue drains.
#[derive(Clone)]
pub(super) struct Committer {
    shared: Arc<Shared>,
    requests: mpsc::UnboundedSender<Request>,
}

impl Committer {
    /// Spawns the commit task for `journal` and returns the staging handle.
    pub fn spawn<M: Medium>(spawn: &Spawn, journal: Journal<M>, shared: Arc<Shared>) -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        spawn(Box::pin(run(journal, shared.clone(), rx)));
        Self {
            shared,
            requests: tx,
        }
    }

    pub const fn shared(&self) -> &Arc<Shared> {
        &self.shared
    }

    /// One atomic catalog transaction: runs `f` over the catalog and stages whatever
    /// it returns, all under one critical section, so catalog order is queue order is
    /// journal order. A staged record was already applied by `f`'s caller contract:
    /// this method applies it, and an apply failure is an internal invariant breach
    /// (callers validate inside `f`, under the same lock).
    ///
    /// Returns `f`'s output and, if anything was staged, the ack receiver: awaiting
    /// it proves durability.
    pub fn transact<T>(
        &self,
        f: impl FnOnce(&mut Catalog) -> (Stage, T),
    ) -> Result<(Option<Ack>, T), Error> {
        if self.shared.poisoned.load(Ordering::Acquire) {
            return Err(poisoned_error());
        }
        let mut state = self.shared.state.lock();
        let (stage, out) = f(&mut state.catalog);
        let record = match stage {
            Stage::Nothing => return Ok((None, out)),
            Stage::Rider => None,
            Stage::Record(record) => {
                state
                    .catalog
                    .apply(&record)
                    .map_err(|reason| Error::Io(Arc::new(std::io::Error::other(reason))))?;
                Some(record)
            }
        };
        state.staged += 1;
        let (done, ack) = oneshot::channel();
        let request = Request {
            record,
            seq: state.staged,
            done,
        };
        // Enqueued under the lock, so queue order is staging order.
        self.requests.send(request).map_err(|_| Error::Closed)?;
        Ok((Some(ack), out))
    }

    /// Applies `record` to the catalog and journals it, returning when durable. The
    /// catalog change is visible to reads immediately (as filesystem namespaces
    /// behave); Ok proves durability.
    pub async fn submit(&self, record: Record) -> Result<(), Error> {
        let (ack, ()) = self.transact(|_| (Stage::Record(record), ()))?;
        ack.expect("record staged")
            .await
            .map_err(|_| Error::Closed)?
    }
}

/// Runs the family's commit loop until every staging handle is dropped.
async fn run<M: Medium>(
    mut journal: Journal<M>,
    shared: Arc<Shared>,
    mut requests: mpsc::UnboundedReceiver<Request>,
) {
    // Reused across cycles: the encode buffer and the acknowledgment list.
    let mut frames: Vec<u8> = Vec::new();
    let mut acks: Vec<oneshot::Sender<Result<(), Error>>> = Vec::new();
    // Requests drained but deferred to a later cycle by the byte bound.
    let mut carry: VecDeque<Request> = VecDeque::new();

    loop {
        // Block for the first request, then drain whatever else is ready.
        let first = match carry.pop_front() {
            Some(request) => request,
            None => match requests.recv().await {
                Some(request) => request,
                None => return,
            },
        };
        let mut batch = vec![first];
        while batch.len() + carry.len() < MAX_BATCH_REQUESTS {
            match carry.pop_front() {
                Some(request) => batch.push(request),
                None => match requests.try_recv() {
                    Ok(request) => batch.push(request),
                    Err(_) => break,
                },
            }
        }

        if shared.poisoned.load(Ordering::Acquire) {
            for request in batch {
                let _ = request.done.send(Err(poisoned_error()));
            }
            continue;
        }

        // Encode this cycle's frames under the live salt. Requests the last snapshot
        // subsumed acknowledge frameless: their durability barrier (the checkpoint's
        // root flip) already completed, strictly before this cycle. Requests past the
        // byte bound carry to the next cycle.
        frames.clear();
        acks.clear();
        let subsumed = shared.state.lock().subsumed;
        let mut batch = batch.into_iter();
        for request in batch.by_ref() {
            if let Some(record) = &request.record
                && request.seq > subsumed
            {
                // Headroom for one maximum record keeps the batch's total within the
                // drain bound, which is exactly recovery's scrub window.
                if frames.len() as u64 + u64::from(MAX_RECORD_LEN) + 16 > MAX_DRAIN_BYTES {
                    carry.push_back(request);
                    carry.extend(batch);
                    break;
                }
                record.encode(journal.salt(), &mut frames);
            }
            acks.push(request.done);
        }

        let result = execute(&mut journal, &shared, &mut frames).await;
        if result.is_err() {
            shared.poisoned.store(true, Ordering::Release);
        }
        for done in acks.drain(..) {
            let _ = done.send(result.clone());
        }
    }
}

/// Makes one cycle's frames durable: append and sync, or checkpoint when they no
/// longer fit (the snapshot contains every staged record, so the frames are simply
/// discarded and the checkpoint's final barrier is the acknowledgment).
async fn execute<M: Medium>(
    journal: &mut Journal<M>,
    shared: &Shared,
    frames: &mut Vec<u8>,
) -> Result<(), Error> {
    if frames.is_empty() {
        // Every request was subsumed; their barrier already completed.
        return Ok(());
    }
    if journal.fits(frames.len() as u64) {
        journal.append(std::mem::take(frames)).await?;
        return journal.sync().await;
    }
    let (snapshot, next_blob_id, staged) = {
        let state = shared.state.lock();
        (
            state.catalog.snapshot(),
            state.catalog.next_blob_id(),
            state.staged,
        )
    };
    journal.checkpoint(&snapshot, next_blob_id).await?;
    // Everything staged before the snapshot was taken is now durably inside it,
    // including requests still queued behind this cycle.
    shared.state.lock().subsumed = staged;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::wal::{format::Kind, medium::Sim};
    use futures::future::join_all;

    const INCARNATION: [u8; 16] = *b"test-incarnation";

    fn test_spawn() -> Spawn {
        Arc::new(|future| {
            tokio::spawn(future);
        })
    }

    async fn open_family(sim: &Sim) -> Committer {
        let (journal, catalog) = Journal::open(sim, ".wal", "family.cww", INCARNATION)
            .await
            .unwrap();
        let shared = Arc::new(Shared::new(catalog));
        Committer::spawn::<Sim>(&test_spawn(), journal, shared)
    }

    fn create_record(committer: &Committer, partition: &str, name: &[u8]) -> Record {
        Record::Create {
            id: committer.shared().mint_id(),
            kind: Kind::Ordinary,
            version: 1,
            partition: partition.into(),
            name: name.to_vec(),
        }
    }

    #[tokio::test]
    async fn group_commit_collapses_barriers() {
        let sim = Sim::new(1);
        let committer = open_family(&sim).await;
        let before = sim.sync_count();

        // Submit concurrently; every ack is Ok and far fewer barriers than
        // submissions complete (all of them can share one).
        let submissions: Vec<_> = (0..64)
            .map(|i| {
                let record = create_record(&committer, "p", format!("blob-{i:02}").as_bytes());
                let committer = committer.clone();
                async move { committer.submit(record).await }
            })
            .collect();
        for result in join_all(submissions).await {
            result.unwrap();
        }
        let barriers = sim.sync_count() - before;
        assert!(barriers < 16, "64 submissions took {barriers} barriers");

        // Everything acknowledged survives a crash.
        sim.crash();
        let (_, catalog) = Journal::open(&sim, ".wal", "family.cww", INCARNATION)
            .await
            .unwrap();
        assert_eq!(catalog.scan("p").unwrap().len(), 64);
    }

    #[tokio::test]
    async fn duplicate_create_rejected_at_staging() {
        let sim = Sim::new(2);
        let committer = open_family(&sim).await;
        committer
            .submit(create_record(&committer, "p", b"a"))
            .await
            .unwrap();
        // Same name again: rejected before any I/O, and the family stays healthy.
        let duplicate = create_record(&committer, "p", b"a");
        assert!(committer.submit(duplicate).await.is_err());
        committer
            .submit(create_record(&committer, "p", b"b"))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn checkpoint_on_full_extent() {
        let sim = Sim::new(3);
        let committer = open_family(&sim).await;

        // Overflow the 64 KiB initial extent; the committer must checkpoint and keep
        // acknowledging. Long names make each record ~1 KiB.
        for i in 0..128u32 {
            let name = format!("{i:04}-{}", "x".repeat(1000));
            committer
                .submit(create_record(&committer, "p", name.as_bytes()))
                .await
                .unwrap();
        }

        sim.crash();
        let (_, catalog) = Journal::open(&sim, ".wal", "family.cww", INCARNATION)
            .await
            .unwrap();
        assert_eq!(catalog.scan("p").unwrap().len(), 128);
    }

    #[tokio::test]
    async fn commit_failure_poisons_family() {
        let sim = Sim::new(4);
        let committer = open_family(&sim).await;
        committer
            .submit(create_record(&committer, "p", b"before"))
            .await
            .unwrap();

        sim.fail_syncs_after(0);
        let record = create_record(&committer, "p", b"during");
        assert!(committer.submit(record).await.is_err());
        // Poison is sticky for this instance: staging fails fast now.
        let record = create_record(&committer, "p", b"after");
        assert!(committer.submit(record).await.is_err());

        // A restart recovers from disk evidence: the acknowledged record is there;
        // the failed one is indeterminate (its record write may have survived).
        sim.crash();
        let (_, catalog) = Journal::open(&sim, ".wal", "family.cww", INCARNATION)
            .await
            .unwrap();
        assert!(catalog.get("p", b"before").is_some());
        assert!(catalog.get("p", b"after").is_none());
    }

    #[tokio::test]
    async fn acknowledged_records_survive_crashes_mid_traffic() {
        for seed in 0..16 {
            let sim = Sim::new(seed);
            let committer = open_family(&sim).await;
            for i in 0..8u32 {
                committer
                    .submit(create_record(
                        &committer,
                        "p",
                        format!("acked-{i}").as_bytes(),
                    ))
                    .await
                    .unwrap();
            }
            sim.crash();
            let (_, catalog) = Journal::open(&sim, ".wal", "family.cww", INCARNATION)
                .await
                .unwrap();
            for i in 0..8u32 {
                assert!(
                    catalog.get("p", format!("acked-{i}").as_bytes()).is_some(),
                    "seed {seed}: acked-{i} lost"
                );
            }
        }
    }

    #[tokio::test]
    async fn committer_shuts_down_when_handles_drop() {
        let sim = Sim::new(5);
        let (journal, catalog) = Journal::open(&sim, ".wal", "family.cww", INCARNATION)
            .await
            .unwrap();
        let shared = Arc::new(Shared::new(catalog));
        let (task_done_tx, mut task_done_rx) = mpsc::unbounded_channel::<()>();
        let spawn: Spawn = Arc::new(move |future| {
            // Wrap so the test observes task exit.
            let done = task_done_tx.clone();
            tokio::spawn(async move {
                future.await;
                let _ = done.send(());
            });
        });
        let committer = Committer::spawn::<Sim>(&spawn, journal, shared);
        committer
            .submit(create_record(&committer, "p", b"a"))
            .await
            .unwrap();
        drop(committer);
        // The task drains its queue and exits; the message is the signal.
        assert_eq!(task_done_rx.recv().await, Some(()));
    }
}
