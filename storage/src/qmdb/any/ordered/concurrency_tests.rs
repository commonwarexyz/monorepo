use super::*;
use crate::{
    index::ordered::Index as OrderedIndex,
    journal::{Error as JournalError, authenticated, contiguous::fixed::Journal},
    merkle::{conformance::build_test_mem, mem::Mem},
    mmr,
    qmdb::{
        any::BITMAP_CHUNK_BYTES,
        current::proof::{RangeProof, RangeProofSpec},
    },
    translator::TwoCap,
};
use commonware_cryptography::{Sha256, sha256::Digest};
use commonware_parallel::Sequential;
use commonware_runtime::{Clock as _, ReadOptions, Runner as _, Supervisor as _, deterministic};
use commonware_utils::{bitmap::Prunable, channel::oneshot, sync::Mutex};
use futures::future::pending;
use std::{
    num::{NonZeroU64, NonZeroUsize},
    ops::Range,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

#[derive(Clone, Copy, Debug)]
enum Mode {
    Error,
    Cancel,
    Reorder,
}

#[derive(Default)]
struct State {
    release: Mutex<Option<oneshot::Receiver<()>>>,
    releaser: Mutex<Option<oneshot::Sender<()>>>,
    completed: Mutex<Vec<u64>>,
    blocked_started: AtomicBool,
    blocked_dropped: AtomicBool,
    error_seen: AtomicBool,
}

struct PendingGuard(Arc<State>);

impl Drop for PendingGuard {
    fn drop(&mut self) {
        self.0.blocked_dropped.store(true, Ordering::SeqCst);
    }
}

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
        start_pos: u64,
        buffer: NonZeroUsize,
        read_options: ReadOptions,
    ) -> Result<impl Stream<Item = Result<(u64, Self::Item), JournalError>> + Send, JournalError>
    {
        self.inner.replay(start_pos, buffer, read_options).await
    }
}

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

async fn make_db(
    context: deterministic::Context,
    count: usize,
    mode: Mode,
) -> (ControlledDb, Vec<Location<mmr::Family>>, Arc<State>) {
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
    let batch = batch.merkleize(&db, None).await.unwrap();
    let (db, _) = db.apply_batch(batch).await.unwrap();
    let mut locs = Vec::new();
    for key in &keys {
        locs.push(db.get_with_loc(key).await.unwrap().unwrap().1);
    }
    locs.sort();

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

/// Check error cleanup before dropping the completed outer future, and cancellation cleanup
/// after dropping a still-pending one. Reordered reads must complete the second read first.
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
                "completed error hidden behind a pending read"
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
            Some(result.expect("reads did not finish").expect("reads failed"))
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
        let (db, locs, state) = make_db(context.child("db"), count, mode).await;
        let mut read = Box::pin(db.fetch_all_updates(locs.iter()));
        let result = commonware_macros::select! {
            result = &mut read => Some(result),
            _ = context.sleep(Duration::from_secs(1)) => None,
        };
        let updates = check_completion(result, &state, mode, &locs);
        drop(read);
        assert!(state.blocked_dropped.load(Ordering::SeqCst));
        if let Some(updates) = updates {
            let keys: Vec<_> = updates
                .iter()
                .map(|update| update.key.as_ref()[31])
                .collect();
            assert_eq!(keys, (0..count as u8).rev().collect::<Vec<_>>());
        }
    });
}

#[rstest::rstest]
#[case(30)]
#[case(31)]
#[case(64)]
fn test_range_concurrent_reads(
    #[case] count: usize,
    #[values(Mode::Error, Mode::Cancel, Mode::Reorder)] mode: Mode,
) {
    deterministic::Runner::default().start(|context| async move {
        let (db, locs, state) = make_db(context.child("db"), count, mode).await;
        const N: usize = 64;
        let leaf_count = db.log.bounds().end;
        let mut status = Prunable::<N>::new();
        for _ in 0..leaf_count {
            status.push(true);
        }
        let hasher = crate::qmdb::hasher::<Sha256>();
        let ops = build_test_mem(&hasher, Mem::<mmr::Family, Digest>::new(), leaf_count);
        let ops_root = ops.root(&hasher, 0).unwrap();
        let mut read = Box::pin(RangeProof::new_with_ops::<Sha256, _, _, N>(
            &status,
            &ops,
            &db.log,
            RangeProofSpec {
                start_loc: locs[0],
                max_ops: NonZeroU64::new(count as u64).unwrap(),
                inactivity_floor: Location::new(0),
                ops_root,
            },
        ));
        let result = commonware_macros::select! {
            result = &mut read => Some(result),
            _ = context.sleep(Duration::from_secs(1)) => None,
        };
        let result = check_completion(result, &state, mode, &locs);
        drop(read);
        assert!(state.blocked_dropped.load(Ordering::SeqCst));
        if let Some((_, operations, _)) = result {
            let mut expected = Vec::new();
            for loc in *locs[0]..*locs[0] + count as u64 {
                expected.push(db.log.journal.inner.read(loc).await.unwrap());
            }
            assert_eq!(operations, expected);
        }
    });
}
