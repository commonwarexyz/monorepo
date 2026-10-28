//! Fanning one collection operation out over a pool's workers and the calling thread.
//!
//! A collection operation that a thread outside the pool places on the whole pool cuts its input
//! into chunks that participants claim from one queue, each exactly once. Every group gets one
//! detached spreader job, placed on the whole pool and offered first to that group's idle workers,
//! starting with the caller's group. A spreader offers a drain to each worker of its group's width
//! by splitting with joins, so the groups wake their workers in parallel and each split wakes one
//! more worker while the splitting one goes on. Every drain claims chunks until none is left.
//!
//! The calling thread drains chunks too when the pool has fewer idle workers than chunks. With an
//! idle worker for every chunk, the workers can take all of them at once, and the calling thread
//! could only oversubscribe the CPUs they run on, so it waits until the last chunk is claimed. A
//! crowded pool leaves chunks for it instead. A group whose workers are busy runs its spreader late
//! and finds nothing, so a caller that drains never waits for a busy group, and a caller that waits
//! does only if the workers it counted as idle took other work first. Once no chunk is left to
//! claim, the call waits only for the drains still working on chunks they claimed. A caller that
//! is a worker of another pool runs its own pool's jobs while it waits, since such a drain may
//! itself wait on one of them.
//!
//! The pool's own workers, and calls placed on one group, split their collection operations with
//! the scheduler's bridge instead, which forks with joins under the placement they run in.
//!
//! The chunks and the operation's closures borrow from the caller's stack, while a drain may run
//! after the call returned. The shared state is therefore reference counted and type-erased, and
//! a drain touches borrowed data only while it is counted inside the operation. A drain never
//! unwinds and keeps the operation's panics for the caller. The call closes the queue, waits
//! until no drain is inside the operation, and takes the unclaimed chunks out before dropping
//! any, so no borrowed data is reachable once it returns or unwinds.

use crate::{
    ThreadPool,
    scheduler::{self, CountLatch, Latch, Placement, WorkerThread},
};
use commonware_utils::sync::Mutex;
use std::{
    any::Any,
    panic::{self, AssertUnwindSafe},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

/// Each claim takes this fraction of the remaining items per participant, so early chunks are
/// large and the last ones small enough that no participant holds the call back for long.
const GUIDED_DIVISOR: usize = 2;

/// Set in [`Shared::state`] while the call admits drains.
const OPEN: usize = 1;

/// The weight of one drain inside the operation in [`Shared::state`].
const DRAIN: usize = 2;

/// The part of a call's state that a drain needs, without the call's lifetime.
trait Work: Send + Sync {
    /// Drains chunks on the calling thread until none is left, or returns at once when the
    /// call is already closed. Never unwinds.
    fn drain(&self);
}

/// The input of one call, cut into chunks, with the bookkeeping that lets drains outlive the
/// call safely.
struct Shared<'a, I> {
    /// The input, one slot per chunk, emptied by the claim that wins it or by `finish`.
    chunks: Vec<Mutex<Option<Vec<I>>>>,
    /// Index of the next chunk to claim. A claim at or past the chunk count fails, and closing
    /// the queue, after an error or a panic or in `finish`, raises it to the count for good. It
    /// only grows, so exactly one claim or close takes it to the count: the claim of the last
    /// chunk, or a close before that claim. That one sets [`Self::claimed`].
    next: AtomicUsize,
    /// [`OPEN`] while the call admits drains, plus [`DRAIN`] for each drain inside the operation.
    /// Every claim is made inside a drain, and no drain enters once `finish` clears [`OPEN`], so
    /// the count then only falls, and when it reaches zero every claimed chunk has completed.
    state: AtomicUsize,
    /// Panics caught in drains. A drain never drops a payload, because its destructor may
    /// panic, so every payload is kept until `finish`.
    panics: Mutex<Vec<Box<dyn Any + Send>>>,
    /// Set once no chunk is left to claim, for a caller that leaves every chunk to the pool's
    /// workers. It waits on it as on [`Self::done`].
    claimed: CountLatch,
    /// Set by the drain that takes [`Self::state`] to zero after the close. A caller that is a
    /// worker of another pool runs that pool's jobs while it waits on it, and any other caller
    /// blocks.
    done: CountLatch,
    /// The operation's loop over claims, on the caller's stack. Dereferenced only by a drain
    /// inside the operation, which the caller waits for before returning.
    run: *const (dyn Fn(&Self) + Sync + 'a),
}

// SAFETY: the raw pointer is only dereferenced while the caller, which owns the pointee, waits
// for the drains inside the operation; every other field is Send and Sync on its own.
unsafe impl<I: Send> Send for Shared<'_, I> {}
// SAFETY: as for Send; the closure behind the pointer is Sync.
unsafe impl<I: Send> Sync for Shared<'_, I> {}

/// The calling thread's worker state, if it is a worker of a pool.
fn worker_thread<'w>() -> Option<&'w WorkerThread> {
    // SAFETY: a non-null pointer is the calling thread's worker state, which lives until the
    // thread leaves its pool, and a thread cannot leave its pool while one of its calls runs.
    unsafe { WorkerThread::current().as_ref() }
}

impl<'a, I> Shared<'a, I> {
    /// Cuts `items` for `width` participants with guided sizes: each chunk takes a fixed share
    /// of what remains, so the sequence shrinks geometrically and the tail is fine-grained.
    fn new(items: Vec<I>, width: usize, run: &'a (dyn Fn(&Self) + Sync + 'a)) -> Self {
        let share = width.max(1) * GUIDED_DIVISOR;
        let mut chunks = Vec::new();
        let mut items = items.into_iter();
        let mut remaining = items.len();
        while remaining > 0 {
            let size = (remaining / share).max(1);
            let chunk: Vec<I> = items.by_ref().take(size).collect();
            chunks.push(Mutex::new(Some(chunk)));
            remaining -= size;
        }
        Self {
            chunks,
            next: AtomicUsize::new(0),
            state: AtomicUsize::new(OPEN),
            panics: Mutex::new(Vec::new()),
            claimed: CountLatch::new(worker_thread()),
            done: CountLatch::new(worker_thread()),
            run,
        }
    }

    const fn len(&self) -> usize {
        self.chunks.len()
    }

    /// The next unclaimed chunk with its index, or `None` once the queue is exhausted or closed.
    fn claim(&self) -> Option<(usize, Vec<I>)> {
        let index = self.next.fetch_add(1, Ordering::SeqCst);
        let chunk = self.chunks.get(index)?.lock().take();
        if index + 1 == self.len() {
            // SAFETY: the latch is a field of `self`, which is borrowed for the whole call.
            unsafe { Latch::set(&self.claimed) };
        }
        chunk.map(|chunk| (index, chunk))
    }

    /// Runs `per_chunk` on every chunk this participant claims.
    fn drain_with(&self, mut per_chunk: impl FnMut(usize, Vec<I>)) {
        while let Some((index, chunk)) = self.claim() {
            per_chunk(index, chunk);
        }
    }

    /// Closes the queue, so every later claim fails.
    fn close_queue(&self) {
        if self.next.fetch_max(self.len(), Ordering::SeqCst) < self.len() {
            // SAFETY: the latch is a field of `self`, which is borrowed for the whole call.
            unsafe { Latch::set(&self.claimed) };
        }
    }

    /// Counts the calling drain inside the operation if the call is still open.
    fn enter(&self) -> bool {
        let mut state = self.state.load(Ordering::SeqCst);
        while state & OPEN != 0 {
            match self.state.compare_exchange_weak(
                state,
                state + DRAIN,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => return true,
                Err(current) => state = current,
            }
        }
        false
    }

    /// Closes the queue, waits until no drain is inside the operation, and drops the unclaimed
    /// chunks. Returns the first panic caught in a drain. Must run on the thread that created
    /// the call, after its own drain if it runs one.
    fn finish(&self) -> Option<Box<dyn Any + Send>> {
        // Every claim after the close fails, and a closed call admits no drain, so once the
        // drains inside have left, every claimed chunk has completed and no drain can reach the
        // operation. The last of them to leave sets `done`.
        self.close_queue();
        if self.state.fetch_and(!OPEN, Ordering::SeqCst) != OPEN {
            self.done.wait(worker_thread());
        }

        // Every unclaimed chunk leaves `Shared` before any is dropped, so an input destructor
        // that panics cannot leave input behind for a late drain to drop.
        let unclaimed: Vec<Vec<I>> = self
            .chunks
            .iter()
            .filter_map(|slot| slot.lock().take())
            .collect();
        drop(unclaimed);

        // The caller resumes the first panic. The others are dropped here, where a destructor
        // that panics finds the call already cleaned up.
        self.panics.lock().drain(..).next()
    }
}

impl<I: Send> Work for Shared<'_, I> {
    fn drain(&self) {
        // A drain enters only while the call is open and counts itself as it does, and the
        // caller closes the call before it checks for drains inside, so a drain either sees the
        // close or is waited for.
        if !self.enter() {
            return;
        }
        if self.next.load(Ordering::SeqCst) < self.len() {
            // SAFETY: the pointee on the caller's stack outlives `finish`, which waits until no
            // drain is inside the operation. This drain stays counted in `state` until it leaves
            // below, which it always reaches because the operation's panics, including those
            // raised by destructors, are caught here.
            let run = unsafe { &*self.run };
            if let Err(payload) = panic::catch_unwind(AssertUnwindSafe(|| run(self))) {
                self.close_queue();
                self.panics.lock().push(payload);
            }
        }

        // No drain enters a closed call, so the count falls to zero after the close exactly
        // once, and the drain that takes it there wakes the caller.
        if self.state.fetch_sub(DRAIN, Ordering::SeqCst) == DRAIN {
            // SAFETY: the caller's own drain, if it runs one, leaves before the close, so this is
            // a drain of a detached spreader, whose job holds a reference to the shared state
            // until its joins have returned from every drain it offered. No other drain sees the
            // count reach zero after the close, so `done` is set once.
            unsafe { Latch::set(&self.done) };
        }
    }
}

/// The number of threads a call cuts its chunks for, which are the pool's workers and the
/// calling thread.
fn width(pool: &ThreadPool) -> usize {
    pool.current_num_threads() + 1
}

/// Runs `run` over the chunks of `items` on the idle workers of `pool`, offered first to the
/// workers of group `near` and then to the other groups in turn, and returns once every claimed
/// chunk has completed. The calling thread must not be a worker of `pool`.
///
/// The calling thread drains chunks too when the pool has fewer idle workers than chunks. With an
/// idle worker for every chunk, the workers can take all of them at once, and the calling thread
/// could only oversubscribe the CPUs they run on, so it waits until the last chunk is claimed. A
/// crowded pool leaves chunks for it instead.
fn fan_out<I: Send>(
    pool: &ThreadPool,
    near: usize,
    items: Vec<I>,
    run: &(dyn Fn(&Shared<'_, I>) + Sync),
) {
    debug_assert!(
        pool.current_worker().is_none(),
        "a worker of the pool splits its calls with the bridge"
    );
    // Without chunks there is no last claim to wake a caller that waits for it.
    if items.is_empty() {
        return;
    }
    let shared: Arc<Shared<'_, I>> = Arc::new(Shared::new(items, width(pool), run));

    // Counted before any spreader is offered, since a worker that takes one no longer counts as
    // idle although it drains this call.
    let covered = pool.idle_workers() >= shared.len();

    let work: Arc<dyn Work + '_> = Arc::clone(&shared) as Arc<dyn Work + '_>;
    // SAFETY: drains never unwind, and neither does a wait on a latch, so this function reaches
    // `finish`, which closes the queue, waits until no drain is inside the operation, and takes
    // every unclaimed chunk out of `Shared` before dropping any. A spreader that holds a clone of
    // this reference afterwards offers only drains that see the closed call and only read its
    // state, and the `Shared` it eventually drops holds no borrowed data.
    let work: Arc<dyn Work + 'static> = unsafe { std::mem::transmute(work) };

    // One spreader per group, each placed on the whole pool near its group, so every group's idle
    // workers start on the call at once instead of waiting for one worker to wake them in turn.
    let widths = pool.group_widths();
    for offset in 0..widths.len() {
        let group = (near + offset) % widths.len();
        let width = widths[group];
        let work = Arc::clone(&work);
        pool.spawn_in(Placement::Wide { near: group }, move || {
            spread(&*work, width)
        });
    }
    if covered {
        // Every drain claims until no chunk is left, so the last claim sets `claimed` unless an
        // error or a panic closed the queue first, which sets it instead. Either way no chunk is
        // left to claim when the wait returns, and `finish` waits for the drains still inside.
        shared.claimed.wait(worker_thread());
    } else {
        shared.drain();
    }
    if let Some(payload) = shared.finish() {
        panic::resume_unwind(payload);
    }
}

/// Offers `width` drains by splitting them in halves with joins, and returns once all of them
/// have returned. A spreader runs as a job placed on the whole pool, so the half it offers at each
/// split waits in its worker's wide deque, where an idle worker of any group steals it and wakes
/// the next one by splitting again, and the worker runs any half left over, so busy workers never
/// hold it back.
fn spread(work: &dyn Work, width: usize) {
    if width <= 1 {
        work.drain();
        return;
    }
    let half = width / 2;
    scheduler::join(|| spread(work, half), || spread(work, width - half));
}

/// Results per chunk, filled in any order and read back in chunk order.
struct Outputs<T> {
    slots: Vec<Mutex<Option<T>>>,
}

impl<T> Outputs<T> {
    fn new(count: usize) -> Self {
        Self {
            slots: (0..count).map(|_| Mutex::new(None)).collect(),
        }
    }

    fn set(&self, index: usize, output: T) {
        let previous = self.slots[index].lock().replace(output);
        assert!(previous.is_none(), "a chunk is claimed exactly once");
    }

    /// The results in chunk order, skipping chunks that set none.
    fn into_ordered(self) -> impl Iterator<Item = T> {
        self.slots.into_iter().filter_map(Mutex::into_inner)
    }
}

/// Chunks needed for `len` items, as `fan_out` cuts them for the same pool.
fn chunk_count(len: usize, pool: &ThreadPool) -> usize {
    let share = width(pool) * GUIDED_DIVISOR;
    let mut count = 0;
    let mut remaining = len;
    while remaining > 0 {
        remaining -= (remaining / share).max(1);
        count += 1;
    }
    count
}

pub(super) fn map_collect_vec<I, F, T>(
    pool: &ThreadPool,
    near: usize,
    items: Vec<I>,
    map_op: &F,
) -> Vec<T>
where
    I: Send,
    F: Fn(I) -> T + Sync,
    T: Send,
{
    let outputs: Outputs<Vec<T>> = Outputs::new(chunk_count(items.len(), pool));
    fan_out(pool, near, items, &|shared| {
        shared
            .drain_with(|index, chunk| outputs.set(index, chunk.into_iter().map(map_op).collect()));
    });
    outputs.into_ordered().flatten().collect()
}

pub(super) fn try_map_collect_vec<I, F, T, E>(
    pool: &ThreadPool,
    near: usize,
    items: Vec<I>,
    map_op: &F,
) -> Result<Vec<T>, E>
where
    I: Send,
    F: Fn(I) -> Result<T, E> + Sync,
    T: Send,
    E: Send,
{
    let outputs: Outputs<Vec<T>> = Outputs::new(chunk_count(items.len(), pool));
    let error: Mutex<Option<E>> = Mutex::new(None);
    fan_out(pool, near, items, &|shared| {
        shared.drain_with(
            |index, chunk| match chunk.into_iter().map(map_op).collect() {
                Ok(output) => outputs.set(index, output),
                Err(e) => {
                    error.lock().get_or_insert(e);
                    shared.close_queue();
                }
            },
        );
    });
    error
        .into_inner()
        .map_or_else(|| Ok(outputs.into_ordered().flatten().collect()), Err)
}

pub(super) fn map_init_collect_vec<I, INIT, S, F, T>(
    pool: &ThreadPool,
    near: usize,
    items: Vec<I>,
    init: &INIT,
    map_op: &F,
) -> Vec<T>
where
    I: Send,
    INIT: Fn() -> S + Sync,
    F: Fn(&mut S, I) -> T + Sync,
    T: Send,
{
    let outputs: Outputs<Vec<T>> = Outputs::new(chunk_count(items.len(), pool));
    fan_out(pool, near, items, &|shared| {
        let mut state = None;
        shared.drain_with(|index, chunk| {
            let state = state.get_or_insert_with(init);
            outputs.set(
                index,
                chunk.into_iter().map(|item| map_op(state, item)).collect(),
            );
        });
    });
    outputs.into_ordered().flatten().collect()
}

pub(super) fn fold_init<I, INIT, S, R, ID, F, RD>(
    pool: &ThreadPool,
    near: usize,
    items: Vec<I>,
    init: &INIT,
    identity: &ID,
    fold_op: &F,
    reduce_op: &RD,
) -> R
where
    I: Send,
    INIT: Fn() -> S + Sync,
    R: Send,
    ID: Fn() -> R + Sync,
    F: Fn(R, &mut S, I) -> R + Sync,
    RD: Fn(R, R) -> R + Sync,
{
    // Each chunk folds into its own partial and the partials reduce in chunk order, so the
    // result is the sequential fold's for any associative `reduce_op`. A participant keeps its
    // `init` state across the chunks it claims.
    let partials = Outputs::new(chunk_count(items.len(), pool));
    fan_out(pool, near, items, &|shared| {
        let mut state = None;
        shared.drain_with(|index, chunk| {
            let state = state.get_or_insert_with(init);
            partials.set(
                index,
                chunk
                    .into_iter()
                    .fold(identity(), |acc, item| fold_op(acc, state, item)),
            );
        });
    });
    partials.into_ordered().fold(identity(), reduce_op)
}

pub(super) fn try_fold<I, R, E, ID, F, RD>(
    pool: &ThreadPool,
    near: usize,
    items: Vec<I>,
    identity: &ID,
    fold_op: &F,
    reduce_op: &RD,
) -> Result<R, E>
where
    I: Send,
    R: Send,
    E: Send,
    ID: Fn() -> R + Sync,
    F: Fn(R, I) -> Result<R, E> + Sync,
    RD: Fn(R, R) -> R + Sync,
{
    // One partial per chunk, reduced in chunk order, as in `fold_init`.
    let partials = Outputs::new(chunk_count(items.len(), pool));
    let error: Mutex<Option<E>> = Mutex::new(None);
    fan_out(pool, near, items, &|shared| {
        shared.drain_with(
            |index, chunk| match chunk.into_iter().try_fold(identity(), fold_op) {
                Ok(folded) => partials.set(index, folded),
                Err(e) => {
                    error.lock().get_or_insert(e);
                    shared.close_queue();
                }
            },
        );
    });
    if let Some(e) = error.into_inner() {
        return Err(e);
    }
    Ok(partials.into_ordered().fold(identity(), reduce_op))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        collections::HashSet,
        sync::{Barrier, atomic::AtomicBool, mpsc},
        thread::{self, ThreadId},
        time::{Duration, Instant},
    };

    /// A pool of `threads` workers in groups of `group_width`, whose worker `j` of group `i` is
    /// named `fan{i}-{j}`.
    fn pool(threads: usize, group_width: usize) -> ThreadPool {
        Arc::new(
            crate::ThreadPoolBuilder::new()
                .num_threads(threads)
                .group_width(group_width)
                .thread_name(move |index| {
                    format!("fan{}-{}", index / group_width, index % group_width)
                })
                .build()
                .unwrap(),
        )
    }

    /// A pool of two groups of one worker each, both workers held until the returned closure
    /// runs, so the spreaders offered to the pool meanwhile start only after their call returned.
    /// The closure releases the workers and returns once every queued spreader has run its drains.
    fn held_pool() -> (ThreadPool, impl FnOnce()) {
        const WORKERS: usize = 2;
        let pool = pool(WORKERS, 1);
        let held = Arc::new(AtomicBool::new(true));
        let (started_tx, started_rx) = mpsc::channel();
        for group in 0..WORKERS {
            let (held, started_tx) = (Arc::clone(&held), started_tx.clone());
            pool.spawn_in(Placement::Local(group), move || {
                started_tx.send(()).unwrap();
                while held.load(Ordering::SeqCst) {
                    thread::sleep(Duration::from_millis(1));
                }
            });
        }
        for _ in 0..WORKERS {
            started_rx.recv().unwrap();
        }
        let release = {
            let pool = Arc::clone(&pool);
            move || {
                held.store(false, Ordering::SeqCst);

                // The pool takes the jobs queued for the whole pool in order, so a worker takes
                // one of these after every queued spreader was taken. Each holds it until every
                // worker holds one, which a worker does only once the drains of the spreaders it
                // took have returned, or while it waits on a drain that another worker runs.
                let barrier = Arc::new(Barrier::new(WORKERS + 1));
                for _ in 0..WORKERS {
                    let barrier = Arc::clone(&barrier);
                    pool.spawn_in(Placement::Wide { near: 0 }, move || {
                        barrier.wait();
                    });
                }
                barrier.wait();
            }
        };
        (pool, release)
    }

    /// Runs `scenario` on its own thread and fails if it does not finish in time, so a call that
    /// deadlocks fails the test rather than hanging it.
    fn within<R: Send + 'static>(scenario: impl FnOnce() -> R + Send + 'static) -> R {
        let (tx, rx) = mpsc::channel();
        let handle = thread::spawn(move || {
            let _ = tx.send(scenario());
        });
        match rx.recv_timeout(Duration::from_secs(30)) {
            Ok(result) => result,
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                panic::resume_unwind(handle.join().unwrap_err())
            }
            Err(mpsc::RecvTimeoutError::Timeout) => panic!("the call deadlocked"),
        }
    }

    /// Waits until `condition` holds, failing with `what` after a bound.
    fn wait_until(what: &str, condition: impl Fn() -> bool) {
        let start = Instant::now();
        while !condition() {
            assert!(start.elapsed() < Duration::from_secs(10), "{what}");
            thread::sleep(Duration::from_millis(1));
        }
    }

    /// Waits until every worker of `pool` is idle.
    fn wait_until_idle(pool: &ThreadPool) {
        wait_until("the pool never went idle", || {
            pool.idle_workers() == pool.current_num_threads()
        });
    }

    /// A worker of one pool that fans out over another keeps running its own pool's jobs while it
    /// waits for the other pool's drains. A drain here waits on a job of the caller's pool, whose
    /// only worker is the caller.
    #[test]
    fn a_waiting_worker_runs_its_pool_while_another_pool_drains() {
        for groups in [1, 2] {
            let caller_pool = pool(1, 1);
            let other = pool(groups, 1);
            let out = within(move || {
                let claimed = AtomicBool::new(false);
                caller_pool.install_in(Placement::Wide { near: 0 }, || {
                    let caller = thread::current().id();
                    map_collect_vec(&other, 0, (0..64).collect(), &|x: u64| {
                        if thread::current().id() == caller {
                            // The caller holds its chunk until the other pool has claimed one.
                            wait_until("no other worker claimed a chunk", || {
                                claimed.load(Ordering::SeqCst)
                            });
                        } else if !claimed.swap(true, Ordering::SeqCst) {
                            caller_pool.install_in(Placement::Wide { near: 0 }, || ());
                        }
                        x
                    })
                })
            });
            assert_eq!(out, (0..64).collect::<Vec<_>>());
        }
    }

    /// A worker of one pool that leaves every chunk to another pool's idle workers keeps running
    /// its own pool's jobs while it waits for their claims. Each drain here waits on a job of the
    /// caller's pool, whose only worker is the caller, before it claims a chunk.
    #[test]
    fn a_waiting_worker_runs_its_pool_until_the_chunks_are_claimed() {
        let caller_pool = pool(1, 1);
        let other = pool(2, 1);
        wait_until_idle(&other);
        let claims = within(move || {
            caller_pool.install_in(Placement::Wide { near: 0 }, || {
                let caller = thread::current().id();
                let claims = AtomicUsize::new(0);
                let run = |shared: &Shared<'_, u64>| {
                    assert_ne!(thread::current().id(), caller);
                    caller_pool.install_in(Placement::Wide { near: 0 }, || ());
                    shared.drain_with(|_, _| {
                        claims.fetch_add(1, Ordering::SeqCst);
                    });
                };
                fan_out(&other, 0, vec![1, 2], &run);
                claims.into_inner()
            })
        });
        assert_eq!(claims, 2);
    }

    /// A pool with an idle worker for every chunk takes all of them while the calling thread
    /// waits, and every chunk is claimed before the call returns.
    #[test]
    fn idle_workers_for_every_chunk_leave_the_caller_waiting() {
        for (threads, group_width) in [(2, 1), (2, 2), (8, 4)] {
            let pool = pool(threads, group_width);
            let items: Vec<u64> = (0..threads as u64).collect();
            assert_eq!(chunk_count(items.len(), &pool), threads);
            wait_until_idle(&pool);
            let (out, on_caller) = within(move || {
                let caller = thread::current().id();
                let on_caller = AtomicUsize::new(0);
                let out = map_collect_vec(&pool, 0, items, &|x: u64| {
                    if thread::current().id() == caller {
                        on_caller.fetch_add(1, Ordering::SeqCst);
                    }
                    x * 10
                });
                (out, on_caller.into_inner())
            });
            assert_eq!(out, (0..threads as u64).map(|x| x * 10).collect::<Vec<_>>());
            assert_eq!(on_caller, 0);
        }
    }

    /// A pool whose workers are all busy leaves every chunk to the calling thread, which returns
    /// before the workers are free.
    #[test]
    fn busy_workers_leave_every_chunk_to_the_caller() {
        let on_caller = within(|| {
            let (pool, release) = held_pool();
            assert_eq!(pool.idle_workers(), 0);
            let caller = thread::current().id();
            let on_caller = AtomicUsize::new(0);
            let out = map_collect_vec(&pool, 0, vec![1u64, 2], &|x: u64| {
                if thread::current().id() == caller {
                    on_caller.fetch_add(1, Ordering::SeqCst);
                }
                x * 10
            });
            release();
            assert_eq!(out, vec![10, 20]);
            on_caller.into_inner()
        });
        assert_eq!(on_caller, 2);
    }

    /// A drain that panics on the only chunk of a call whose caller waits hands the panic to the
    /// caller, and the call returns with no input left.
    #[test]
    fn a_waiting_caller_gets_the_panic_of_a_drain() {
        struct Input<'a>(&'a AtomicUsize);
        impl Drop for Input<'_> {
            fn drop(&mut self) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }

        let pool = pool(2, 1);
        wait_until_idle(&pool);
        within(move || {
            let caller = thread::current().id();
            let drops = AtomicUsize::new(0);
            let outcome = panic::catch_unwind(AssertUnwindSafe(|| {
                map_collect_vec(&pool, 0, vec![Input(&drops)], &|_: Input<'_>| -> u64 {
                    assert_ne!(thread::current().id(), caller);
                    panic!("map failed")
                })
            }));
            let payload = outcome.expect_err("the panic reaches the caller");
            assert_eq!(payload.downcast_ref::<&str>(), Some(&"map failed"));
            assert_eq!(drops.load(Ordering::SeqCst), 1);
        });
    }

    /// A pool with fewer idle workers than chunks leaves some to the calling thread. Each worker
    /// here holds its chunk until the caller has run an item, so the call finishes only if the
    /// caller takes part.
    #[test]
    fn chunks_beyond_the_idle_workers_have_the_caller_take_part() {
        let pool = pool(2, 1);
        assert!(chunk_count(64, &pool) > 2);
        wait_until_idle(&pool);
        let out = within(move || {
            let caller = thread::current().id();
            let caller_ran = AtomicBool::new(false);
            map_collect_vec(&pool, 0, (0..64).collect(), &|x: u64| {
                if thread::current().id() == caller {
                    caller_ran.store(true, Ordering::SeqCst);
                } else {
                    wait_until("the caller never took part", || {
                        caller_ran.load(Ordering::SeqCst)
                    });
                }
                x
            })
        });
        assert_eq!(out, (0..64).collect::<Vec<_>>());
    }

    /// The claims end exactly once, by the claim of the last chunk or by a close of the queue
    /// before it, and whichever ends them sets `claimed`: the drain where they end, or `finish`
    /// when no drain ended them.
    #[test]
    fn claimed_is_set_once_by_whatever_ends_the_claims() {
        fn claim_all(shared: &Shared<'_, u64>) {
            shared.drain_with(|_, _| ());
        }
        fn close_on_claim(shared: &Shared<'_, u64>) {
            shared.drain_with(|_, _| shared.close_queue());
        }
        fn panic_on_claim(shared: &Shared<'_, u64>) {
            shared.drain_with(|_, _| panic!("chunk failed"));
        }
        fn claim_none(_: &Shared<'_, u64>) {}

        for (run, ends_in_drain) in [
            (claim_all as fn(&Shared<'_, u64>), true),
            (close_on_claim, true),
            (panic_on_claim, true),
            (claim_none, false),
        ] {
            let shared = Shared::new((0..64).collect(), 3, &run);
            assert!(shared.len() > 1);
            shared.drain();
            assert_eq!(shared.claimed.count(), usize::from(!ends_in_drain));
            shared.drain();
            drop(shared.finish());
            assert_eq!(shared.claimed.count(), 0);
        }
    }

    /// A spreader runs exactly as many drains as the width it spreads over, and idle workers take
    /// some of them.
    #[test]
    fn a_spreader_offers_one_drain_per_worker_of_its_width() {
        struct Count {
            drains: AtomicUsize,
            threads: Mutex<HashSet<ThreadId>>,
        }
        impl Work for Count {
            fn drain(&self) {
                self.drains.fetch_add(1, Ordering::SeqCst);
                self.threads.lock().insert(thread::current().id());
                thread::sleep(Duration::from_millis(5));
            }
        }

        let pool = pool(4, 4);
        for width in 1..=9 {
            let count = Count {
                drains: AtomicUsize::new(0),
                threads: Mutex::new(HashSet::new()),
            };
            pool.install_in(Placement::Wide { near: 0 }, || spread(&count, width));
            assert_eq!(count.drains.into_inner(), width);
            if width >= 4 {
                assert!(count.threads.into_inner().len() > 1);
            }
        }
    }

    /// Chunks are cut for the pool's workers and the calling thread, and `chunk_count` sizes the
    /// outputs for that cut.
    #[test]
    fn chunks_are_cut_for_the_threads_that_take_part() {
        fn cut(pool: &ThreadPool, len: usize) -> usize {
            let chunks = AtomicUsize::new(0);
            fan_out(pool, 0, vec![0u8; len], &|shared: &Shared<'_, u8>| {
                chunks.store(shared.len(), Ordering::SeqCst);
                shared.drain_with(|_, _| ());
            });
            let chunks = chunks.into_inner();
            assert_eq!(chunks, chunk_count(len, pool));
            chunks
        }

        within(|| {
            let narrow = pool(1, 1);
            let wide = pool(4, 2);
            for len in [1, 7, 64, 1000] {
                cut(&narrow, len);
                cut(&wide, len);
            }
            assert!(cut(&wide, 1000) > cut(&narrow, 1000));
        });
    }

    /// A call spreads over every group of the pool, and the calling thread takes part.
    #[test]
    fn a_map_keeps_order_and_uses_every_group_and_the_caller() {
        let pool = pool(8, 2);
        let caller = thread::current().id();
        let seen = Mutex::new(Vec::new());
        let out = map_collect_vec(&pool, 0, (0..64).collect(), &|x: u64| {
            thread::sleep(Duration::from_millis(2));
            let name = thread::current().name().unwrap_or("").to_string();
            seen.lock().push((thread::current().id() == caller, name));
            x * 2
        });
        assert_eq!(out, (0..64).map(|x| x * 2).collect::<Vec<_>>());
        let seen = seen.into_inner();
        for group in 0..4 {
            let prefix = format!("fan{group}-");
            assert!(
                seen.iter().any(|(_, n)| n.starts_with(&prefix)),
                "group {group} took no chunk"
            );
        }
        assert!(seen.iter().any(|(on_caller, _)| *on_caller));
    }

    #[test]
    fn empty_input_and_single_items_work() {
        let pool = pool(2, 2);
        wait_until_idle(&pool);
        within(move || {
            let out: Vec<u64> = map_collect_vec(&pool, 0, Vec::new(), &|x: u64| x);
            assert!(out.is_empty());
            let out = map_collect_vec(&pool, 0, vec![7u64], &|x| x + 1);
            assert_eq!(out, vec![8]);
        });
    }

    #[test]
    fn try_map_stops_after_an_error() {
        let pool = pool(2, 2);
        let calls = AtomicUsize::new(0);
        let result: Result<Vec<u64>, &str> =
            try_map_collect_vec(&pool, 0, (0..1000).collect(), &|x: u64| {
                calls.fetch_add(1, Ordering::Relaxed);
                if x == 3 { Err("three") } else { Ok(x) }
            });
        assert_eq!(result, Err("three"));
        assert!(calls.load(Ordering::Relaxed) < 1000);
    }

    #[test]
    fn fold_and_init_agree_with_serial() {
        let pool = pool(3, 2);
        let items: Vec<u64> = (1..=1000).collect();
        let sum = fold_init(
            &pool,
            0,
            items.clone(),
            &|| 0u64,
            &|| 0u64,
            &|acc, state, x| {
                *state += 1;
                acc + x
            },
            &|a, b| a + b,
        );
        assert_eq!(sum, 500500);
        let doubled = map_init_collect_vec(&pool, 1, items.clone(), &|| 2u64, &|k, x| *k * x);
        assert_eq!(doubled, items.iter().map(|x| x * 2).collect::<Vec<_>>());
        let folded: Result<u64, ()> =
            try_fold(&pool, 1, items, &|| 0u64, &|acc, x| Ok(acc + x), &|a, b| {
                a + b
            });
        assert_eq!(folded, Ok(500500));
    }

    /// Folds reduce their partials in input order, so a reduce that is associative but not
    /// commutative returns the sequential result.
    #[test]
    fn folds_reduce_in_input_order() {
        let pool = pool(4, 2);
        let items: Vec<u64> = (0..1000).collect();
        let append = |mut a: Vec<u64>, b: Vec<u64>| {
            a.extend(b);
            a
        };
        let folded = fold_init(
            &pool,
            0,
            items.clone(),
            &|| (),
            &Vec::new,
            &|mut acc: Vec<u64>, _, x| {
                thread::sleep(Duration::from_micros(20));
                acc.push(x);
                acc
            },
            &append,
        );
        assert_eq!(folded, items);
        let folded: Result<Vec<u64>, ()> = try_fold(
            &pool,
            0,
            items.clone(),
            &Vec::new,
            &|mut acc: Vec<u64>, x| {
                thread::sleep(Duration::from_micros(20));
                acc.push(x);
                Ok(acc)
            },
            &append,
        );
        assert_eq!(folded, Ok(items));
    }

    #[test]
    fn a_panicking_chunk_waits_for_the_rest_then_propagates() {
        let pool = pool(4, 2);
        let finished = AtomicUsize::new(0);
        let result = panic::catch_unwind(AssertUnwindSafe(|| {
            map_collect_vec(&pool, 0, (0..8).collect(), &|x: u64| {
                if x == 2 {
                    panic!("chunk failed");
                }
                thread::sleep(Duration::from_millis(20));
                finished.fetch_add(1, Ordering::Relaxed);
                x
            })
        }));
        assert!(result.is_err());
        // Every chunk claimed before the panic stopped the claims has finished; none is running.
        let at_return = finished.load(Ordering::Relaxed);
        thread::sleep(Duration::from_millis(60));
        assert_eq!(finished.load(Ordering::Relaxed), at_return);
    }

    /// A group whose workers are all busy takes no chunks and does not delay the return.
    #[test]
    fn a_busy_group_does_not_gate_the_call() {
        let pool = pool(4, 2);
        let gate = AtomicBool::new(false);
        let spinning = AtomicUsize::new(0);
        let spin = || {
            spinning.fetch_add(1, Ordering::SeqCst);
            while !gate.load(Ordering::Relaxed) {
                thread::sleep(Duration::from_millis(1))
            }
        };
        thread::scope(|scope| {
            scope.spawn(|| {
                pool.install_in(Placement::Local(1), || {
                    crate::scheduler::join(spin, spin);
                });
            });
            // Both workers of group 1 hold a spinning closure before the call starts.
            wait_until("group 1 never got busy", || {
                spinning.load(Ordering::SeqCst) == 2
            });
            let start = Instant::now();
            let seen = Mutex::new(Vec::new());
            let out = map_collect_vec(&pool, 0, (0..16).collect(), &|x: u64| {
                thread::sleep(Duration::from_millis(5));
                seen.lock()
                    .push(thread::current().name().unwrap_or("").to_string());
                x
            });
            let elapsed = start.elapsed();
            gate.store(true, Ordering::Relaxed);
            assert_eq!(out, (0..16).collect::<Vec<_>>());
            assert!(seen.into_inner().iter().all(|n| !n.starts_with("fan1-")));
            assert!(
                elapsed < Duration::from_millis(150),
                "returned after {elapsed:?}"
            );
        });
    }

    /// Borrowed data dropped right after the call is never touched by a late drain.
    #[test]
    fn late_drains_touch_nothing_after_the_call() {
        within(|| {
            let (pool, release) = held_pool();
            for round in 0..20u64 {
                let data: Vec<u64> = (0..32).map(|x| x + round).collect();
                let out = map_collect_vec(&pool, 0, data.iter().collect(), &|x: &u64| *x * 2);
                assert_eq!(out, data.iter().map(|x| x * 2).collect::<Vec<_>>());
            }
            release();
        });
    }

    /// A call that fails before every chunk is claimed closes the queue, so a drain that starts
    /// after the call returned never enters the operation.
    #[test]
    fn a_late_drain_never_enters_a_failed_call() {
        within(|| {
            let (pool, release) = held_pool();
            let entered = AtomicUsize::new(0);
            // The operation outlives the call, so a late drain that enters it is counted rather
            // than touching freed memory.
            let run = |shared: &Shared<'_, u64>| {
                entered.fetch_add(1, Ordering::SeqCst);
                shared.drain_with(|_, _| shared.close_queue());
            };
            fan_out(&pool, 0, (0..16).collect(), &run);
            release();
            assert_eq!(entered.load(Ordering::SeqCst), 1);
        });
    }

    /// A participant's state whose destructor panics after a failure still lets the call close
    /// the queue, and the panic reaches the caller.
    #[test]
    fn a_panicking_state_destructor_still_closes_the_call() {
        struct State<'a>(&'a AtomicBool);
        impl Drop for State<'_> {
            fn drop(&mut self) {
                assert!(!self.0.swap(false, Ordering::SeqCst), "state destructor");
            }
        }

        within(|| {
            let (pool, release) = held_pool();
            let armed = AtomicBool::new(true);
            let entered = AtomicUsize::new(0);
            // The operation outlives the call, so a late drain that enters it is counted rather
            // than touching freed memory. Only the first state's destructor panics, so such a drain
            // runs to completion.
            let run = |shared: &Shared<'_, u64>| {
                entered.fetch_add(1, Ordering::SeqCst);
                let _state = State(&armed);
                shared.drain_with(|_, _| shared.close_queue());
            };
            let outcome = panic::catch_unwind(AssertUnwindSafe(|| {
                fan_out(&pool, 0, (0..16).collect(), &run);
            }));
            release();
            assert!(outcome.is_err());
            assert_eq!(entered.load(Ordering::SeqCst), 1);
        });
    }

    /// An unclaimed input whose destructor panics leaves no input behind. The call drops every
    /// unclaimed input before it unwinds, and none is dropped by a late drain.
    #[test]
    fn a_panicking_input_destructor_leaves_no_input_behind() {
        struct Input<'a> {
            bomb: bool,
            returned: &'a AtomicBool,
            late_drops: &'a AtomicUsize,
        }
        impl Drop for Input<'_> {
            fn drop(&mut self) {
                if self.returned.load(Ordering::SeqCst) {
                    self.late_drops.fetch_add(1, Ordering::SeqCst);
                }
                assert!(!self.bomb, "input destructor");
            }
        }

        within(|| {
            let (pool, release) = held_pool();
            let returned = AtomicBool::new(false);
            let late_drops = AtomicUsize::new(0);
            // The first chunk holds at most half of the input, so input 8 is unclaimed when that
            // chunk fails, and more unclaimed input follows it.
            let items = (0..16)
                .map(|index| Input {
                    bomb: index == 8,
                    returned: &returned,
                    late_drops: &late_drops,
                })
                .collect();
            let outcome = panic::catch_unwind(AssertUnwindSafe(|| {
                try_map_collect_vec(&pool, 0, items, &|_: Input<'_>| Err::<(), ()>(()))
            }));
            returned.store(true, Ordering::SeqCst);
            release();
            assert!(outcome.is_err());
            assert_eq!(late_drops.load(Ordering::SeqCst), 0);
        });
    }

    /// A drain keeps every panic it catches, so a payload whose destructor panics cannot unwind
    /// the drain, and the caller sees that panic only once the call is cleaned up.
    #[test]
    fn a_panicking_payload_destructor_does_not_unwind_a_drain() {
        static ARMED: AtomicBool = AtomicBool::new(true);
        struct Payload;
        impl Drop for Payload {
            fn drop(&mut self) {
                assert!(!ARMED.swap(false, Ordering::SeqCst), "payload destructor");
            }
        }

        // Both drains are inside the operation before either panics, so each keeps a payload.
        let barrier = Barrier::new(2);
        let run = |_: &Shared<'_, u64>| {
            barrier.wait();
            panic::panic_any(Payload);
        };
        let shared = Shared::new(vec![0], 1, &run);
        thread::scope(|scope| {
            scope.spawn(|| shared.drain());
            shared.drain();
        });
        assert_eq!(shared.state.load(Ordering::SeqCst), OPEN);
        assert!(panic::catch_unwind(AssertUnwindSafe(|| shared.finish())).is_err());
    }
}
