//! Tests for concurrent update reads in ordered databases: error propagation, cancellation, and
//! completion order.

use super::*;
use crate::{
    index::ordered::Index as OrderedIndex,
    journal::{
        Error as JournalError, authenticated,
        contiguous::{self, fixed::Journal},
    },
    mmr,
    qmdb::{any::BITMAP_CHUNK_BYTES, floor::Proportional},
    translator::TwoCap,
};
use commonware_cryptography::{Sha256, sha256::Digest};
use commonware_parallel::Sequential;
use commonware_runtime::{Clock as _, ReadOptions, Runner as _, Supervisor as _, deterministic};
use commonware_utils::{channel::oneshot, sync::Mutex};
use futures::future::pending;
use std::{
    num::NonZeroUsize,
    ops::Range,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

/// How `Controlled` treats reads of its `blocked` and `failed` positions.
#[derive(Clone, Copy, Debug)]
enum Mode {
    /// The `failed` read returns an error while the `blocked` read stays pending.
    Error,

    /// The `blocked` read stays pending until the test drops the outer future.
    Cancel,

    /// The `blocked` read waits until the `failed` read succeeds.
    Reorder,
}

/// Progress of the controlled reads, shared between the journal and the test.
#[derive(Default)]
struct State {
    /// Receiver the blocked read awaits in `Reorder` mode.
    release: Mutex<Option<oneshot::Receiver<()>>>,
    /// Sender the `failed` read uses to release the blocked read in `Reorder` mode.
    releaser: Mutex<Option<oneshot::Sender<()>>>,
    /// Positions whose reads succeeded, in completion order.
    completed: Mutex<Vec<u64>>,
    /// Set when the blocked read starts.
    blocked_started: AtomicBool,
    /// Set when the blocked read stops waiting, whether released or dropped.
    blocked_dropped: AtomicBool,
    /// Set when the `failed` read returns its error.
    error_seen: AtomicBool,
}

/// Sets `blocked_dropped` when the blocked read stops waiting, whether released or dropped.
struct PendingGuard(Arc<State>);

impl Drop for PendingGuard {
    fn drop(&mut self) {
        self.0.blocked_dropped.store(true, Ordering::SeqCst);
    }
}

/// Wraps a journal so that reads of `blocked` and `failed` behave as `mode` directs.
struct Controlled<C> {
    inner: C,
    mode: Mode,
    blocked: u64,
    failed: u64,
    state: Arc<State>,
}

impl<C: Contiguous> Contiguous for Controlled<C> {
    type Item = C::Item;

    fn bounds(&self) -> Range<u64> {
        self.inner.bounds()
    }

    async fn read(&self, position: u64) -> Result<Self::Item, JournalError> {
        if position == self.blocked {
            let _guard = PendingGuard(self.state.clone());
            self.state.blocked_started.store(true, Ordering::SeqCst);
            if matches!(self.mode, Mode::Reorder) {
                let release = self.state.release.lock().take().unwrap();
                release.await.unwrap();
            } else {
                pending::<()>().await;
            }
        }
        if position == self.failed && matches!(self.mode, Mode::Error) {
            self.state.error_seen.store(true, Ordering::SeqCst);
            return Err(JournalError::Runtime(commonware_runtime::Error::ReadFailed));
        }
        let item = self.inner.read(position).await?;
        self.state.completed.lock().push(position);
        if position == self.failed && matches!(self.mode, Mode::Reorder) {
            self.state.releaser.lock().take().unwrap().send(()).unwrap();
        }
        Ok(item)
    }

    async fn read_many(&self, positions: &[u64]) -> Result<Vec<Self::Item>, JournalError> {
        self.inner.read_many(positions).await
    }

    fn try_read_sync(&self, position: u64) -> Option<Self::Item> {
        self.inner.try_read_sync(position)
    }

    fn try_read_many_sync(&self, positions: &[u64]) -> Vec<Option<Self::Item>> {
        self.inner.try_read_many_sync(positions)
    }

    async fn replay(
        &self,
        range: Range<u64>,
        buffer: NonZeroUsize,
        read_options: ReadOptions,
    ) -> Result<
        impl Stream<Item = Result<contiguous::Batch<Self::Item>, JournalError>> + Send,
        JournalError,
    > {
        self.inner.replay(range, buffer, read_options).await
    }
}

/// An ordered fixed database whose log reads go through `Controlled`.
type ControlledDb = Db<
    mmr::Family,
    deterministic::Context,
    Controlled<Journal<deterministic::Context, fixed::Operation<mmr::Family, Digest, Digest>>>,
    OrderedIndex<TwoCap, Location<mmr::Family>>,
    Sha256,
    fixed::Update<Digest, Digest>,
    BITMAP_CHUNK_BYTES,
    Sequential,
>;

/// Builds a database holding `count` keys whose journal controls reads of the two lowest key
/// locations. Returns the database, the ascending key locations, and the shared read state.
async fn make_db(
    context: deterministic::Context,
    count: usize,
    mode: Mode,
) -> (ControlledDb, Vec<Location<mmr::Family>>, Arc<State>) {
    // Write `count` keys that differ only in their last byte and collect their log locations.
    let db = fixed::test::create_test_db(context).await;
    let keys: Vec<_> = (0..count)
        .map(|i| {
            let mut key = [0u8; 32];
            key[31] = i as u8;
            Digest::from(key)
        })
        .collect();
    let mut batch = db.new_batch();
    for key in &keys {
        batch = batch.write(*key, Some(Sha256::fill(7)));
    }
    let batch = batch.merkleize(&db, None, &mut Proportional).await.unwrap();
    let db = db.apply_batch(batch).await.unwrap();
    let mut locs = Vec::new();
    for key in &keys {
        locs.push(db.get_with_loc(key).await.unwrap().unwrap().1);
    }
    locs.sort();

    // Rebuild the database around a controlled journal that blocks the lowest location and treats
    // the next one as `mode` directs.
    let (releaser, release) = oneshot::channel();
    let state = Arc::new(State {
        release: Mutex::new(Some(release)),
        releaser: Mutex::new(Some(releaser)),
        ..State::default()
    });
    let Db {
        log,
        root,
        inactivity_floor_loc,
        snapshot,
        active_keys,
        bitmap,
        metrics,
        _update,
    } = db;
    let authenticated::Journal {
        merkle,
        journal,
        hasher,
    } = log;
    let log = authenticated::Journal {
        merkle,
        journal: Controlled {
            inner: journal,
            mode,
            blocked: *locs[0],
            failed: *locs[1],
            state: state.clone(),
        },
        hasher,
    };
    (
        Db {
            log,
            root,
            inactivity_floor_loc,
            snapshot,
            active_keys,
            bitmap,
            metrics,
            _update,
        },
        locs,
        state,
    )
}

/// Checks the read outcome for `mode` and returns the updates of a successful read.
///
/// In `Error` mode, the batch polls the blocked read before the failing one on its first pass.
/// The error must then arrive without waiting for the blocked read, and that read must already
/// be dropped. In `Cancel` mode, the blocked read must still be held, so the caller can check
/// that dropping the outer future releases it. In `Reorder` mode, the second location's read
/// must complete before the first.
fn check_completion<T>(
    result: Option<Result<T, crate::qmdb::Error<mmr::Family>>>,
    state: &State,
    mode: Mode,
    locs: &[Location<mmr::Family>],
) -> Option<T> {
    assert!(state.blocked_started.load(Ordering::SeqCst));
    match mode {
        Mode::Error => {
            assert!(state.error_seen.load(Ordering::SeqCst));
            assert!(
                matches!(
                    result,
                    Some(Err(crate::qmdb::Error::Journal(JournalError::Runtime(
                        commonware_runtime::Error::ReadFailed
                    ))))
                ),
                "the batch must return the failed read's error while the blocked read is pending"
            );
            assert!(state.blocked_dropped.load(Ordering::SeqCst));
            None
        }
        Mode::Cancel => {
            assert!(result.is_none());
            assert!(!state.blocked_dropped.load(Ordering::SeqCst));
            None
        }
        Mode::Reorder => {
            let completed = state.completed.lock();
            let first = completed.iter().position(|loc| *loc == *locs[0]).unwrap();
            let second = completed.iter().position(|loc| *loc == *locs[1]).unwrap();
            assert!(second < first);
            Some(
                result
                    .expect("reordered reads must finish")
                    .expect("reordered reads must succeed"),
            )
        }
    }
}

#[rstest::rstest]
#[case(30)]
#[case(31)]
#[case(64)]
fn test_ordered_concurrent_reads(
    #[case] count: usize,
    #[values(Mode::Error, Mode::Cancel, Mode::Reorder)] mode: Mode,
) {
    deterministic::Runner::default().start(|context| async move {
        // Production batches take either path, because the snapshot iterators of `OrderedIndex`
        // report an unknown size hint while those of the partitioned ordered index report an
        // exact one. This test passes an exact-size slice, so the 30 case runs on the small
        // collector and the larger cases on the unordered path. Error and Reorder batches must
        // finish before the timeout, and a Cancel batch must still be pending when it fires.
        let (db, locs, state) = make_db(context.child("db"), count, mode).await;
        let mut read = Box::pin(db.fetch_all_updates(locs.iter().copied()));
        let result = commonware_macros::select! {
            result = &mut read => Some(result),
            _ = context.sleep(Duration::from_secs(1)) => None,
        };
        let updates = check_completion(result, &state, mode, &locs);

        // Dropping the batch must leave no blocked read alive in any mode.
        drop(read);
        assert!(state.blocked_dropped.load(Ordering::SeqCst));

        // Updates come back in descending key order.
        if let Some(updates) = updates {
            let keys: Vec<_> = updates
                .iter()
                .map(|update| update.key.as_ref()[31])
                .collect();
            assert_eq!(keys, (0..count as u8).rev().collect::<Vec<_>>());
        }
    });
}
