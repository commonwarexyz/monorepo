//! A wake-limited parked thread pool behind the [`Strategy`] trait.
//!
//! `Parked` replaces rayon's spin-then-yield idle behavior with immediate parking plus
//! wake-limited dispatch: idle workers cost zero, and a submission wakes only as many
//! workers as the job can use. Collection operations execute through a scoped chunk-claiming
//! core ([`scoped`]) in which the submitting caller participates. `spawn` hands one-shots to
//! an unbounded queue eagerly (a dropped future still runs its job) with a member-poller
//! help path (a pool worker polling a spawn future of its own pool runs pending work
//! instead of parking the only capable worker). `join` and `sort_by` are TEMPORARY serial
//! implementations until increment C.
//!
//! Pools with more than one worker always hand `spawn` jobs off to a worker; single-worker
//! pools execute them inline at submission (matching `Rayon` at one thread), so jobs that
//! block on external synchronization require a multi-worker pool.

mod pool;
mod scoped;
mod sync;

#[cfg(all(test, not(feature = "loom")))]
mod bench_tests;
#[cfg(all(test, feature = "loom"))]
mod loom_tests;
#[cfg(all(test, not(feature = "loom")))]
mod tests;

use crate::{Manual, Sequential, Strategy, policy};
use core::{
    cell::Cell, cmp::Ordering as CmpOrdering, convert::Infallible, fmt, num::NonZeroUsize,
    ops::Range, ptr,
};
use futures::{
    channel::oneshot,
    future::{self, Either},
};
use pool::Shared;
use scoped::Ctl;
use std::panic::{self, Location};
use sync::{Arc, Mutex, WorkerHandle, spawn_worker};

/// Sends the pool into shutdown when the last `Parked` handle drops.
struct Owner {
    shared: Arc<Shared>,
    workers: Mutex<Vec<WorkerHandle>>,
}

impl Drop for Owner {
    fn drop(&mut self) {
        self.shared.shutdown();
        // A spawned job can hold the last Parked clone, making this drop run ON a pool
        // worker: joining would self-deadlock, so detach in that case (the flag is set;
        // siblings exit after draining). Otherwise join so no thread outlives the pool.
        if pool::is_member(&self.shared) {
            return;
        }
        let handles: Vec<WorkerHandle> = self.workers.lock().unwrap().drain(..).collect();
        for handle in handles {
            let _ = handle.join();
        }
    }
}

/// A parallel execution strategy backed by parked worker threads.
///
/// See the module docs. `Parked::new(n)` spawns `n` background workers; a collection
/// operation wakes at most `n - 1` of them so that, with the participating caller, a single
/// job's executor count equals the configured parallelism.
#[derive(Clone)]
pub struct Parked {
    shared: Arc<Shared>,
    _owner: Arc<Owner>,
    // The parallelism assumed for policy decisions and manual partitioning.
    parallelism: usize,
    // `Some` enables adaptive serial-vs-parallel decisions; `None` (used by `manual`) runs
    // the parallel body whenever the parallelism exceeds one.
    policy: Option<policy::Policy>,
}

impl fmt::Debug for Parked {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Parked")
            .field("workers", &self.shared.workers())
            .field("parallelism", &self.parallelism)
            .finish()
    }
}

impl Parked {
    /// Creates a `Parked` strategy with `workers` background worker threads.
    pub fn new(workers: NonZeroUsize) -> Self {
        let shared = Arc::new(Shared::new(workers.get()));
        let handles: Vec<WorkerHandle> = (0..workers.get())
            .map(|id| {
                let s = Arc::clone(&shared);
                spawn_worker(id, move || pool::worker_loop(s, id))
            })
            .collect();
        Self {
            shared: Arc::clone(&shared),
            _owner: Arc::new(Owner {
                shared,
                workers: Mutex::new(handles),
            }),
            parallelism: workers.get(),
            policy: Some(policy::Policy::default()),
        }
    }

    /// Overrides the parallelism assumed for planning decisions.
    ///
    /// This does not resize the pool. By default a strategy plans with its worker count;
    /// override it when the strategy should expose a different parallelism.
    pub fn with_parallelism(mut self, parallelism: NonZeroUsize) -> Self {
        self.parallelism = parallelism.get();
        self
    }

    #[track_caller]
    fn execute<R>(
        &self,
        len: usize,
        multiplier: usize,
        run: impl FnOnce(policy::Execution) -> R,
    ) -> R {
        match self.try_execute(len, multiplier, |execution| {
            Ok::<_, Infallible>(run(execution))
        }) {
            Ok(result) => result,
            Err(e) => match e {},
        }
    }

    #[track_caller]
    fn try_execute<R, E>(
        &self,
        len: usize,
        multiplier: usize,
        run: impl FnOnce(policy::Execution) -> Result<R, E>,
    ) -> Result<R, E> {
        let Some(policy) = &self.policy else {
            let execution = if self.parallelism <= 1 {
                policy::Execution::Serial
            } else {
                policy::Execution::Parallel
            };
            return run(execution);
        };

        let work = len.saturating_mul(multiplier);
        policy.try_run(Location::caller(), len, work, self.parallelism, run)
    }
}

/// A raw pointer that may be shared with and used by pool workers.
///
/// SAFETY invariants are established by the scoped wrappers below: the pointee outlives the
/// scoped run (the wrapper's frame owns it), and range exclusivity ensures no two executors
/// touch the same index.
struct Ptr<T>(*mut T);

impl<T> Clone for Ptr<T> {
    fn clone(&self) -> Self {
        Self(self.0)
    }
}
impl<T> Copy for Ptr<T> {}

impl<T> Ptr<T> {
    /// Returns the raw pointer. A method (not field access) so closures capture the whole
    /// `Ptr` -- whose `Sync`/`Send` impls carry the safety argument -- rather than the bare
    /// `*mut T` field via edition-2021 disjoint capture.
    fn get(self) -> *mut T {
        self.0
    }
}

// SAFETY: `Ptr` is only used to move `T: Send` values across executors (reads) or to write
// `T: Send` values produced on an executor, under the wrappers' range-exclusivity and
// frame-lifetime invariants.
unsafe impl<T: Send> Send for Ptr<T> {}
// SAFETY: see above; concurrent executors access disjoint indexes only.
unsafe impl<T: Send> Sync for Ptr<T> {}

/// The scoped map core shared by every `map*_collect_vec` variant.
///
/// Consumes `items` by value across executors and produces the mapped outputs in input
/// order. On error or panic, every input item and every produced output is dropped exactly
/// once; the first error (or first panic payload) wins.
fn scoped_map<T, S, R, E, INIT, F>(
    shared: &Shared,
    parallelism: usize,
    items: Vec<T>,
    init: INIT,
    map_op: F,
) -> Result<Vec<R>, E>
where
    T: Send,
    S: Send,
    R: Send,
    E: Send,
    INIT: Fn() -> S + Send + Sync,
    F: Fn(&mut S, T) -> Result<R, E> + Send + Sync,
{
    let n = items.len();
    // The protocol takes ownership of the elements; the Vec keeps only the allocation.
    let mut items = items;
    let in_ptr = Ptr(items.as_mut_ptr());
    // SAFETY: len 0 <= capacity; the elements are dropped exactly once by the protocol
    // below (moved into `map_op`, or dropped during cleanup), never by the Vec.
    unsafe { items.set_len(0) };
    let mut out: Vec<R> = Vec::with_capacity(n);
    let out_ptr = Ptr(out.as_mut_ptr());

    // Output ranges fully written by completed chunks (consulted only for failure cleanup).
    let done: Mutex<Vec<Range<usize>>> = Mutex::new(Vec::new());
    // First error produced by any chunk.
    let error: Mutex<Option<E>> = Mutex::new(None);

    let body = |range: Range<usize>, ctl: &Ctl<'_>| {
        // Watermarks for exact-once cleanup if `init` or `map_op` panics mid-chunk:
        // inputs `[range.start, consumed)` were moved into `map_op` (it owns their drops);
        // outputs `[range.start, written)` were fully written and are ours to drop.
        let consumed = Cell::new(range.start);
        let written = Cell::new(range.start);
        let result = panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Option<E> {
            let mut state = init();
            for i in range.clone() {
                // SAFETY: range exclusivity: index `i` belongs to this claimed chunk only,
                // and each index is read exactly once. The buffer outlives the scoped run.
                let item = unsafe { in_ptr.get().add(i).read() };
                consumed.set(i + 1);
                match map_op(&mut state, item) {
                    Ok(value) => {
                        // SAFETY: same exclusivity for the output slot; capacity is `n`.
                        unsafe { out_ptr.get().add(i).write(value) };
                        written.set(i + 1);
                    }
                    Err(e) => return Some(e),
                }
            }
            None
        }));
        // Cleanup for the two failure shapes; a completed chunk records its output range.
        let clean_chunk = |range: &Range<usize>| {
            for j in range.start..written.get() {
                // SAFETY: outputs `[start, written)` were fully written by this chunk and
                // nobody else will drop them (the chunk did not enter `done`).
                unsafe { ptr::drop_in_place(out_ptr.get().add(j)) };
            }
            for j in consumed.get()..range.end {
                // SAFETY: inputs `[consumed, end)` were never read by anyone; this chunk
                // owns them exclusively.
                unsafe { ptr::drop_in_place(in_ptr.get().add(j)) };
            }
        };
        match result {
            Ok(None) => done.lock().unwrap().push(range),
            Ok(Some(e)) => {
                {
                    let mut slot = error.lock().unwrap();
                    if slot.is_none() {
                        *slot = Some(e);
                    }
                }
                ctl.close();
                clean_chunk(&range);
            }
            Err(payload) => {
                clean_chunk(&range);
                // Rethrow so the scoped core records the payload and closes the job.
                panic::resume_unwind(payload);
            }
        }
    };

    let outcome = scoped::run(shared, n, parallelism, &body);

    // Quiescent: no executor can touch the buffers anymore.
    let error = error.into_inner().unwrap();
    if outcome.panic.is_some() || error.is_some() {
        // Cleanup runs user `Drop` impls; catch their panics so the first chunk payload
        // still wins (a cleanup panic aborts remaining cleanup, leaking, which is safe).
        let cleanup = panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            for range in done.into_inner().unwrap() {
                for j in range {
                    // SAFETY: this range was fully written by a completed chunk, and is
                    // dropped only here (failure path returns before `out` gains length).
                    unsafe { ptr::drop_in_place(out_ptr.get().add(j)) };
                }
            }
            for j in outcome.claimed..n {
                // SAFETY: indexes past the claim watermark were never read by any executor.
                unsafe { ptr::drop_in_place(in_ptr.get().add(j)) };
            }
        }));
        if let Some(payload) = outcome.panic {
            // The chunk payload wins; leak secondary payloads rather than panic-in-unwind.
            if let Err(second) = cleanup {
                core::mem::forget(second);
            }
            if let Some(e) = error {
                core::mem::forget(e);
            }
            panic::resume_unwind(payload);
        }
        if let Err(payload) = cleanup {
            if let Some(e) = error {
                core::mem::forget(e);
            }
            panic::resume_unwind(payload);
        }
        return Err(error.expect("failure without panic must carry an error"));
    }

    // SAFETY: every index in `0..n` was written exactly once by a completed chunk.
    unsafe { out.set_len(n) };
    Ok(out)
}

/// The scoped fold core: folds items chunk-wise into per-chunk accumulators, returning the
/// partials for the caller to reduce. Same exact-once ownership discipline as [`scoped_map`].
fn scoped_fold<T, S, R, E, INIT, ID, F>(
    shared: &Shared,
    parallelism: usize,
    items: Vec<T>,
    init: INIT,
    identity: ID,
    fold_op: F,
) -> Result<Vec<R>, E>
where
    T: Send,
    S: Send,
    R: Send,
    E: Send,
    INIT: Fn() -> S + Send + Sync,
    ID: Fn() -> R + Send + Sync,
    F: Fn(R, &mut S, T) -> Result<R, E> + Send + Sync,
{
    let n = items.len();
    let mut items = items;
    let in_ptr = Ptr(items.as_mut_ptr());
    // SAFETY: as in `scoped_map`: elements are owned by the protocol from here on.
    unsafe { items.set_len(0) };

    // Partials are tagged with their chunk's start index and reduced in input order:
    // Sequential and Rayon both preserve segment order, so `reduce_op` may rely on
    // associativity alone (commutativity is NOT required by the trait contract).
    let partials: Mutex<Vec<(usize, R)>> = Mutex::new(Vec::new());
    let error: Mutex<Option<E>> = Mutex::new(None);

    let body = |range: Range<usize>, ctl: &Ctl<'_>| {
        let consumed = Cell::new(range.start);
        let result = panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<R, E> {
            let mut state = init();
            let mut acc = identity();
            for i in range.clone() {
                // SAFETY: range exclusivity; each index read exactly once.
                let item = unsafe { in_ptr.get().add(i).read() };
                consumed.set(i + 1);
                acc = fold_op(acc, &mut state, item)?;
            }
            Ok(acc)
        }));
        let clean_rest = || {
            for j in consumed.get()..range.end {
                // SAFETY: inputs `[consumed, end)` were never read; this chunk owns them.
                unsafe { ptr::drop_in_place(in_ptr.get().add(j)) };
            }
        };
        match result {
            Ok(Ok(acc)) => partials.lock().unwrap().push((range.start, acc)),
            Ok(Err(e)) => {
                {
                    let mut slot = error.lock().unwrap();
                    if slot.is_none() {
                        *slot = Some(e);
                    }
                }
                ctl.close();
                clean_rest();
            }
            Err(payload) => {
                clean_rest();
                panic::resume_unwind(payload);
            }
        }
    };

    let outcome = scoped::run(shared, n, parallelism, &body);

    let error = error.into_inner().unwrap();
    if outcome.panic.is_some() || error.is_some() {
        // All user Drop code (unclaimed inputs AND accumulated partials) runs under the
        // guard so a panicking Drop cannot race the payload hand-off below.
        let partials = partials.into_inner().unwrap();
        let cleanup = panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            drop(partials);
            for j in outcome.claimed..n {
                // SAFETY: never claimed, never read.
                unsafe { ptr::drop_in_place(in_ptr.get().add(j)) };
            }
        }));
        if let Some(payload) = outcome.panic {
            // The chunk payload wins; a cleanup panic during unwind would abort, so leak
            // its payload instead.
            if let Err(second) = cleanup {
                core::mem::forget(second);
            }
            if let Some(e) = error {
                core::mem::forget(e);
            }
            panic::resume_unwind(payload);
        }
        if let Err(payload) = cleanup {
            if let Some(e) = error {
                core::mem::forget(e);
            }
            panic::resume_unwind(payload);
        }
        return Err(error.expect("failure without panic must carry an error"));
    }
    let mut partials = partials.into_inner().unwrap();
    // Chunk starts are unique; stable sort restores input-segment order cheaply since
    // completion order is usually near claim order.
    partials.sort_by_key(|(start, _)| *start);
    Ok(partials.into_iter().map(|(_, acc)| acc).collect())
}

impl Strategy for Parked {
    fn manual(&self) -> Manual<Self> {
        Manual::new(
            Self {
                shared: Arc::clone(&self.shared),
                _owner: Arc::clone(&self._owner),
                parallelism: self.parallelism,
                policy: None,
            },
            NonZeroUsize::new(self.parallelism).expect("parallelism is nonzero"),
        )
    }

    fn spawn<F, T>(&self, f: F) -> impl core::future::Future<Output = T> + Send + 'static
    where
        F: FnOnce(Self) -> T + Send + 'static,
        T: Send + 'static,
    {
        // Mirror Rayon: a single-worker pool executes inline (offloading to the only
        // worker could deadlock a job that waits on work only the submitter can create).
        // A pool already shutting down also executes inline: post-close submissions are
        // the submitter's own work by contract.
        if self.shared.workers() <= 1 || self.shared.is_shutdown() {
            return Either::Left(future::ready(f(self.clone())));
        }

        let (tx, mut rx) = oneshot::channel();
        let s = self.clone();
        let shared = Arc::clone(&self.shared);
        // Eager submission: the job is queued before the future is returned, so a caller
        // that drops the future (detached spawn) still gets its job executed.
        self.shared.enqueue(Box::new(move || {
            // Catch the panic so a panicking job propagates to the awaiting task rather
            // than killing a pool worker.
            let result = panic::catch_unwind(std::panic::AssertUnwindSafe(|| f(s)));
            let _ = tx.send(result);
        }));
        Either::Right(async move {
            // When the polling thread is itself a member of THIS pool, waiting on the
            // channel could park the only worker able to run the job. Run pending pool
            // work inline until the job completes or an external poller takes over.
            // `is_member` checks pool identity, so a worker of another pool falls through
            // to the channel immediately.
            loop {
                if let Ok(Some(result)) = rx.try_recv() {
                    return match result {
                        Ok(value) => value,
                        Err(payload) => panic::resume_unwind(payload),
                    };
                }
                if !pool::is_member(&shared) || !shared.help_once() {
                    break;
                }
            }
            match rx.await {
                Ok(Ok(value)) => value,
                Ok(Err(payload)) => panic::resume_unwind(payload),
                Err(_) => panic!("strategy job dropped before completion"),
            }
        })
    }

    #[track_caller]
    fn run<R, SEQ, PAR>(&self, len: usize, serial: SEQ, parallel: PAR) -> R
    where
        R: Send,
        SEQ: FnOnce() -> R + Send,
        PAR: FnOnce() -> R + Send,
    {
        self.execute(len, 1, |execution| match execution {
            policy::Execution::Serial => serial(),
            policy::Execution::Parallel => parallel(),
        })
    }

    #[track_caller]
    fn try_run<R, E, SEQ, PAR>(&self, len: usize, serial: SEQ, parallel: PAR) -> Result<R, E>
    where
        R: Send,
        E: Send,
        SEQ: FnOnce() -> Result<R, E> + Send,
        PAR: FnOnce() -> Result<R, E> + Send,
    {
        self.try_execute(len, 1, |execution| match execution {
            policy::Execution::Serial => serial(),
            policy::Execution::Parallel => parallel(),
        })
    }

    #[track_caller]
    fn fold_init<I, INIT, T, R, ID, F, RD>(
        &self,
        iter: I,
        init: INIT,
        identity: ID,
        fold_op: F,
        reduce_op: RD,
    ) -> R
    where
        I: IntoIterator<IntoIter: Send, Item: Send> + Send,
        INIT: Fn() -> T + Send + Sync,
        T: Send,
        R: Send,
        ID: Fn() -> R + Send + Sync,
        F: Fn(R, &mut T, I::Item) -> R + Send + Sync,
        RD: Fn(R, R) -> R + Send + Sync,
    {
        let items: Vec<I::Item> = iter.into_iter().collect();
        self.execute(items.len(), 1, |execution| match execution {
            policy::Execution::Serial => {
                Sequential.fold_init(items, init, identity, fold_op, reduce_op)
            }
            policy::Execution::Parallel => {
                let partials = scoped_fold(
                    &self.shared,
                    self.parallelism,
                    items,
                    &init,
                    &identity,
                    |acc, state, item| Ok::<_, Infallible>(fold_op(acc, state, item)),
                );
                match partials {
                    Ok(partials) => partials.into_iter().fold(identity(), &reduce_op),
                    Err(e) => match e {},
                }
            }
        })
    }

    #[track_caller]
    fn try_fold<I, R, E, ID, F, RD>(
        &self,
        iter: I,
        identity: ID,
        fold_op: F,
        reduce_op: RD,
    ) -> Result<R, E>
    where
        I: IntoIterator<IntoIter: Send, Item: Send> + Send,
        R: Send,
        E: Send,
        ID: Fn() -> R + Send + Sync,
        F: Fn(R, I::Item) -> Result<R, E> + Send + Sync,
        RD: Fn(R, R) -> R + Send + Sync,
    {
        let items: Vec<I::Item> = iter.into_iter().collect();
        self.try_execute(items.len(), 1, |execution| match execution {
            policy::Execution::Serial => Sequential.try_fold(items, identity, fold_op, reduce_op),
            policy::Execution::Parallel => {
                let partials = scoped_fold(
                    &self.shared,
                    self.parallelism,
                    items,
                    || (),
                    &identity,
                    |acc, _state: &mut (), item| fold_op(acc, item),
                )?;
                Ok(partials.into_iter().fold(identity(), &reduce_op))
            }
        })
    }

    #[track_caller]
    fn map_collect_vec<I, F, T>(&self, iter: I, map_op: F) -> Vec<T>
    where
        I: IntoIterator<IntoIter: Send, Item: Send> + Send,
        F: Fn(I::Item) -> T + Send + Sync,
        T: Send,
    {
        let items: Vec<I::Item> = iter.into_iter().collect();
        self.execute(items.len(), 1, |execution| match execution {
            policy::Execution::Serial => Sequential.map_collect_vec(items, map_op),
            policy::Execution::Parallel => {
                let out = scoped_map(
                    &self.shared,
                    self.parallelism,
                    items,
                    || (),
                    |_state: &mut (), item| Ok::<_, Infallible>(map_op(item)),
                );
                match out {
                    Ok(out) => out,
                    Err(e) => match e {},
                }
            }
        })
    }

    #[track_caller]
    fn try_map_collect_vec<I, F, T, E>(&self, iter: I, map_op: F) -> Result<Vec<T>, E>
    where
        I: IntoIterator<IntoIter: Send, Item: Send> + Send,
        F: Fn(I::Item) -> Result<T, E> + Send + Sync,
        T: Send,
        E: Send,
    {
        let items: Vec<I::Item> = iter.into_iter().collect();
        self.try_execute(items.len(), 1, |execution| match execution {
            policy::Execution::Serial => Sequential.try_map_collect_vec(items, map_op),
            policy::Execution::Parallel => scoped_map(
                &self.shared,
                self.parallelism,
                items,
                || (),
                |_state: &mut (), item| map_op(item),
            ),
        })
    }

    #[track_caller]
    fn map_init_collect_vec<I, INIT, T, F, R>(&self, iter: I, init: INIT, map_op: F) -> Vec<R>
    where
        I: IntoIterator<IntoIter: Send, Item: Send> + Send,
        INIT: Fn() -> T + Send + Sync,
        T: Send,
        F: Fn(&mut T, I::Item) -> R + Send + Sync,
        R: Send,
    {
        let items: Vec<I::Item> = iter.into_iter().collect();
        self.execute(items.len(), 1, |execution| match execution {
            policy::Execution::Serial => Sequential.map_init_collect_vec(items, init, map_op),
            policy::Execution::Parallel => {
                let out = scoped_map(
                    &self.shared,
                    self.parallelism,
                    items,
                    &init,
                    |state, item| Ok::<_, Infallible>(map_op(state, item)),
                );
                match out {
                    Ok(out) => out,
                    Err(e) => match e {},
                }
            }
        })
    }

    #[track_caller]
    fn map_init_collect_vec_with_multiplier<I, INIT, T, F, R>(
        &self,
        iter: I,
        multiplier: usize,
        init: INIT,
        map_op: F,
    ) -> Vec<R>
    where
        I: IntoIterator<IntoIter: Send, Item: Send> + Send,
        INIT: Fn() -> T + Send + Sync,
        T: Send,
        F: Fn(&mut T, I::Item) -> R + Send + Sync,
        R: Send,
    {
        let items: Vec<I::Item> = iter.into_iter().collect();
        self.execute(items.len(), multiplier, |execution| match execution {
            policy::Execution::Serial => Sequential.map_init_collect_vec(items, init, map_op),
            policy::Execution::Parallel => {
                let out = scoped_map(
                    &self.shared,
                    self.parallelism,
                    items,
                    &init,
                    |state, item| Ok::<_, Infallible>(map_op(state, item)),
                );
                match out {
                    Ok(out) => out,
                    Err(e) => match e {},
                }
            }
        })
    }

    fn join<A, B, RA, RB>(&self, a: A, b: B) -> (RA, RB)
    where
        A: FnOnce() -> RA + Send,
        B: FnOnce() -> RB + Send,
        RA: Send,
        RB: Send,
    {
        // TEMPORARY (increment A): serial. The handoff-slot join lands in increment C.
        // No policy involvement so temporary timings cannot pollute adaptive estimates.
        (a(), b())
    }

    #[track_caller]
    fn sort_by<T, C>(&self, items: &mut [T], compare: C)
    where
        T: Send,
        C: Fn(&T, &T) -> CmpOrdering + Send + Sync,
    {
        // TEMPORARY (increment A): serial stable sort. The join-based parallel sort lands
        // in increment C. No policy involvement so temporary timings cannot pollute
        // adaptive estimates.
        items.sort_by(compare);
    }
}
