//! Fanning one collection operation over several pools and the calling thread.
//!
//! The call cuts its input into chunks that participants claim from one queue, each exactly
//! once. The calling thread, which is outside every pool, drains chunks itself and offers each
//! pool one detached drain job, which spreads over that pool's idle workers and drains until no
//! chunk is left. A pool whose workers are busy runs its drain late and finds nothing, so the call
//! never waits for a busy pool. Once the caller has drained, it waits only for the drains still
//! working on chunks they claimed.
//!
//! The chunks and the operation's closures borrow from the caller's stack, while a drain may run
//! after the call returned. The shared state is therefore reference counted and type-erased, and
//! a drain touches borrowed data only inside a claim it won. A drain never unwinds and keeps the
//! operation's panics for the caller. The call closes the queue, waits until no drain is inside
//! the operation, and takes the unclaimed chunks out before dropping any, so no borrowed data is
//! reachable once it returns or unwinds.

use crate::ThreadPool;
use commonware_utils::sync::{Condvar, Mutex};
use std::{
    any::Any,
    panic::{self, AssertUnwindSafe},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};

/// Each claim takes this fraction of the remaining items per participant, so early chunks are
/// large and the last ones small enough that no participant holds the call back for long.
const GUIDED_DIVISOR: usize = 2;

/// The part of a call's state that a drain needs, without the call's lifetime.
trait Work: Send + Sync {
    /// Drains chunks on the calling thread until none is left, or returns at once when the
    /// queue is already closed. Never unwinds.
    fn drain(&self);
}

/// The input of one call, cut into chunks, with the bookkeeping that lets drains outlive the
/// call safely.
struct Shared<'a, I> {
    /// The input, one slot per chunk, emptied by the claim that wins it or by `finish`.
    chunks: Vec<Mutex<Option<Vec<I>>>>,
    /// Index of the next chunk to claim. A claim at or past the chunk count fails, and closing
    /// the queue moves it past the count for good.
    next: AtomicUsize,
    /// Drains that announced themselves and have not left. Every claim is made inside one, so
    /// once the queue is closed and none is left, every claimed chunk has completed.
    active: AtomicUsize,
    /// Set by an error or a panic; claims fail once it is set.
    failed: AtomicBool,
    /// Panics caught in drains. A drain never drops a payload, because its destructor may
    /// panic, so every payload is kept until `finish`.
    panics: Mutex<Vec<Box<dyn Any + Send>>>,
    /// Wakes the caller when a drain leaves.
    wake: (Mutex<()>, Condvar),
    /// The operation's loop over claims, on the caller's stack. Dereferenced only by a drain
    /// that is active, which the caller waits for before returning.
    run: *const (dyn Fn(&Self) + Sync + 'a),
}

// SAFETY: the raw pointer is only dereferenced while the caller, which owns the pointee, waits
// for active drains; every other field is Send and Sync on its own.
unsafe impl<I: Send> Send for Shared<'_, I> {}
// SAFETY: as for Send; the closure behind the pointer is Sync.
unsafe impl<I: Send> Sync for Shared<'_, I> {}

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
            active: AtomicUsize::new(0),
            failed: AtomicBool::new(false),
            panics: Mutex::new(Vec::new()),
            wake: (Mutex::new(()), Condvar::new()),
            run,
        }
    }

    const fn len(&self) -> usize {
        self.chunks.len()
    }

    /// The next unclaimed chunk with its index, or `None` once the queue is exhausted, closed,
    /// or failed.
    fn claim(&self) -> Option<(usize, Vec<I>)> {
        if self.failed.load(Ordering::SeqCst) {
            return None;
        }
        let index = self.next.fetch_add(1, Ordering::SeqCst);
        let chunk = self.chunks.get(index)?.lock().take();
        chunk.map(|chunk| (index, chunk))
    }

    fn notify(&self) {
        let _guard = self.wake.0.lock();
        self.wake.1.notify_all();
    }

    /// Runs `per_chunk` on every chunk this participant claims.
    fn drain_with(&self, mut per_chunk: impl FnMut(usize, Vec<I>)) {
        while let Some((index, chunk)) = self.claim() {
            per_chunk(index, chunk);
        }
    }

    /// Marks the call failed so no further chunk is claimed.
    fn fail(&self) {
        self.failed.store(true, Ordering::SeqCst);
    }

    /// Closes the queue, waits until no drain is inside the operation, and drops the unclaimed
    /// chunks. Returns the first panic caught in a drain.
    fn finish(&self) -> Option<Box<dyn Any + Send>> {
        // Every claim after the close fails, and every claim before it was made by a drain
        // counted in `active`, so once none is active every claimed chunk has completed.
        self.next.fetch_add(self.len(), Ordering::SeqCst);
        let mut guard = self.wake.0.lock();
        while self.active.load(Ordering::SeqCst) != 0 {
            self.wake.1.wait(&mut guard);
        }
        drop(guard);

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
        // A drain announces itself before it looks at the queue, and the caller closes the
        // queue before it checks for active drains, so a drain either sees the close or is
        // waited for.
        self.active.fetch_add(1, Ordering::SeqCst);
        if self.next.load(Ordering::SeqCst) < self.len() {
            // SAFETY: the pointee on the caller's stack outlives `finish`, which waits until no
            // drain is active. This drain stays counted in `active` until it leaves below, which
            // it always reaches because the operation's panics, including those raised by
            // destructors, are caught here.
            let run = unsafe { &*self.run };
            if let Err(payload) = panic::catch_unwind(AssertUnwindSafe(|| run(self))) {
                self.failed.store(true, Ordering::SeqCst);
                self.panics.lock().push(payload);
            }
        }
        self.active.fetch_sub(1, Ordering::SeqCst);
        self.notify();
    }
}

/// Runs `run` over the chunks of `items` on the calling thread and on every idle worker of
/// `pools`, and returns once every claimed chunk has completed.
fn fan_out<I: Send>(pools: &[ThreadPool], items: Vec<I>, run: &(dyn Fn(&Shared<'_, I>) + Sync)) {
    let width = pools
        .iter()
        .map(|pool| pool.current_num_threads())
        .sum::<usize>()
        + 1;
    let shared: Arc<Shared<'_, I>> = Arc::new(Shared::new(items, width, run));
    let work: Arc<dyn Work + '_> = Arc::clone(&shared) as Arc<dyn Work + '_>;
    // SAFETY: drains never unwind, so this function reaches `finish`, which closes the queue,
    // waits until no drain is active, and takes every unclaimed chunk out of `Shared` before
    // dropping any. A drain that holds this reference afterwards sees the closed queue and only
    // updates counters, and the `Shared` it eventually drops holds no borrowed data.
    let work: Arc<dyn Work + 'static> = unsafe { std::mem::transmute(work) };
    for pool in pools {
        let work = Arc::clone(&work);
        pool.spawn(move || {
            rayon::scope(|scope| {
                for _ in 1..rayon::current_num_threads() {
                    let work = Arc::clone(&work);
                    scope.spawn(move |_| work.drain());
                }
                work.drain();
            });
        });
    }
    shared.drain();
    if let Some(payload) = shared.finish() {
        panic::resume_unwind(payload);
    }
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

/// Chunks needed for `len` items, as `Shared::new` cuts them.
fn chunk_count(len: usize, pools: &[ThreadPool]) -> usize {
    let width = pools
        .iter()
        .map(|pool| pool.current_num_threads())
        .sum::<usize>()
        + 1;
    let share = width * GUIDED_DIVISOR;
    let mut count = 0;
    let mut remaining = len;
    while remaining > 0 {
        remaining -= (remaining / share).max(1);
        count += 1;
    }
    count
}

pub(super) fn map_collect_vec<I, F, T>(pools: &[ThreadPool], items: Vec<I>, map_op: &F) -> Vec<T>
where
    I: Send,
    F: Fn(I) -> T + Sync,
    T: Send,
{
    let outputs: Outputs<Vec<T>> = Outputs::new(chunk_count(items.len(), pools));
    fan_out(pools, items, &|shared| {
        shared
            .drain_with(|index, chunk| outputs.set(index, chunk.into_iter().map(map_op).collect()));
    });
    outputs.into_ordered().flatten().collect()
}

pub(super) fn try_map_collect_vec<I, F, T, E>(
    pools: &[ThreadPool],
    items: Vec<I>,
    map_op: &F,
) -> Result<Vec<T>, E>
where
    I: Send,
    F: Fn(I) -> Result<T, E> + Sync,
    T: Send,
    E: Send,
{
    let outputs: Outputs<Vec<T>> = Outputs::new(chunk_count(items.len(), pools));
    let error: Mutex<Option<E>> = Mutex::new(None);
    fan_out(pools, items, &|shared| {
        shared.drain_with(
            |index, chunk| match chunk.into_iter().map(map_op).collect() {
                Ok(output) => outputs.set(index, output),
                Err(e) => {
                    error.lock().get_or_insert(e);
                    shared.fail();
                }
            },
        );
    });
    error
        .into_inner()
        .map_or_else(|| Ok(outputs.into_ordered().flatten().collect()), Err)
}

pub(super) fn map_init_collect_vec<I, INIT, S, F, T>(
    pools: &[ThreadPool],
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
    let outputs: Outputs<Vec<T>> = Outputs::new(chunk_count(items.len(), pools));
    fan_out(pools, items, &|shared| {
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
    pools: &[ThreadPool],
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
    let partials = Outputs::new(chunk_count(items.len(), pools));
    fan_out(pools, items, &|shared| {
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
    pools: &[ThreadPool],
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
    let partials = Outputs::new(chunk_count(items.len(), pools));
    let error: Mutex<Option<E>> = Mutex::new(None);
    fan_out(pools, items, &|shared| {
        shared.drain_with(
            |index, chunk| match chunk.into_iter().try_fold(identity(), fold_op) {
                Ok(folded) => partials.set(index, folded),
                Err(e) => {
                    error.lock().get_or_insert(e);
                    shared.fail();
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
        sync::mpsc,
        thread,
        time::{Duration, Instant},
    };

    fn pools(widths: &[usize]) -> Vec<ThreadPool> {
        widths
            .iter()
            .enumerate()
            .map(|(i, &w)| {
                Arc::new(
                    rayon::ThreadPoolBuilder::new()
                        .num_threads(w)
                        .thread_name(move |j| format!("fan{i}-{j}"))
                        .build()
                        .unwrap(),
                )
            })
            .collect()
    }

    /// A one-thread pool whose worker is held until the returned closure runs, so a drain
    /// offered to the pool meanwhile starts only after its call returned. The closure releases
    /// the worker and waits for the drains queued behind it.
    fn held_pool() -> (Vec<ThreadPool>, impl FnOnce()) {
        let pools = pools(&[1]);
        let (held_tx, held_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel::<()>();
        pools[0].spawn(move || {
            held_tx.send(()).unwrap();
            let _ = release_rx.recv();
        });
        held_rx.recv().unwrap();
        let pool = Arc::clone(&pools[0]);
        let release = move || {
            release_tx.send(()).unwrap();
            // The pool runs injected jobs in order, so this returns after the queued drains.
            pool.install(|| ());
        };
        (pools, release)
    }

    #[test]
    fn map_keeps_order_and_uses_every_pool_and_the_caller() {
        let pools = pools(&[2, 2]);
        let caller = thread::current().id();
        let seen = Mutex::new(Vec::new());
        let out = map_collect_vec(&pools, (0..64).collect(), &|x: u64| {
            thread::sleep(Duration::from_millis(2));
            let name = thread::current().name().unwrap_or("").to_string();
            seen.lock().push((thread::current().id() == caller, name));
            x * 2
        });
        assert_eq!(out, (0..64).map(|x| x * 2).collect::<Vec<_>>());
        let seen = seen.into_inner();
        assert!(seen.iter().any(|(_, n)| n.starts_with("fan0-")));
        assert!(seen.iter().any(|(_, n)| n.starts_with("fan1-")));
        assert!(seen.iter().any(|(on_caller, _)| *on_caller));
    }

    #[test]
    fn empty_input_and_single_items_work() {
        let pools = pools(&[2]);
        let out: Vec<u64> = map_collect_vec(&pools, Vec::new(), &|x: u64| x);
        assert!(out.is_empty());
        let out = map_collect_vec(&pools, vec![7u64], &|x| x + 1);
        assert_eq!(out, vec![8]);
    }

    #[test]
    fn try_map_stops_after_an_error() {
        let pools = pools(&[2]);
        let calls = AtomicUsize::new(0);
        let result: Result<Vec<u64>, &str> =
            try_map_collect_vec(&pools, (0..1000).collect(), &|x: u64| {
                calls.fetch_add(1, Ordering::Relaxed);
                if x == 3 { Err("three") } else { Ok(x) }
            });
        assert_eq!(result, Err("three"));
        assert!(calls.load(Ordering::Relaxed) < 1000);
    }

    #[test]
    fn fold_and_init_agree_with_serial() {
        let pools = pools(&[2, 1]);
        let items: Vec<u64> = (1..=1000).collect();
        let sum = fold_init(
            &pools,
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
        let doubled = map_init_collect_vec(&pools, items.clone(), &|| 2u64, &|k, x| *k * x);
        assert_eq!(doubled, items.iter().map(|x| x * 2).collect::<Vec<_>>());
        let folded: Result<u64, ()> =
            try_fold(&pools, items, &|| 0u64, &|acc, x| Ok(acc + x), &|a, b| {
                a + b
            });
        assert_eq!(folded, Ok(500500));
    }

    /// Folds reduce their partials in input order, so a reduce that is associative but not
    /// commutative returns the sequential result.
    #[test]
    fn folds_reduce_in_input_order() {
        let pools = pools(&[2, 2]);
        let items: Vec<u64> = (0..1000).collect();
        let append = |mut a: Vec<u64>, b: Vec<u64>| {
            a.extend(b);
            a
        };
        let folded = fold_init(
            &pools,
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
            &pools,
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
        let pools = pools(&[2, 2]);
        let finished = AtomicUsize::new(0);
        let result = panic::catch_unwind(AssertUnwindSafe(|| {
            map_collect_vec(&pools, (0..8).collect(), &|x: u64| {
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

    /// A pool whose workers are all busy takes no chunks and does not delay the return.
    #[test]
    fn a_busy_pool_does_not_gate_the_call() {
        let pools = pools(&[2, 2]);
        let gate = AtomicBool::new(false);
        thread::scope(|scope| {
            scope.spawn(|| {
                pools[1].install(|| {
                    rayon::join(
                        || {
                            while !gate.load(Ordering::Relaxed) {
                                thread::sleep(Duration::from_millis(1))
                            }
                        },
                        || {
                            while !gate.load(Ordering::Relaxed) {
                                thread::sleep(Duration::from_millis(1))
                            }
                        },
                    );
                });
            });
            thread::sleep(Duration::from_millis(20));
            let start = Instant::now();
            let seen = Mutex::new(Vec::new());
            let out = map_collect_vec(&pools, (0..16).collect(), &|x: u64| {
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
        let (pools, release) = held_pool();
        for round in 0..20u64 {
            let data: Vec<u64> = (0..32).map(|x| x + round).collect();
            let out = map_collect_vec(&pools, data.iter().collect(), &|x: &u64| *x * 2);
            assert_eq!(out, data.iter().map(|x| x * 2).collect::<Vec<_>>());
        }
        release();
    }

    /// A call that fails before every chunk is claimed closes the queue, so a drain that starts
    /// after the call returned never enters the operation.
    #[test]
    fn a_late_drain_never_enters_a_failed_call() {
        let (pools, release) = held_pool();
        let entered = AtomicUsize::new(0);
        // The operation outlives the call, so a late drain that enters it is counted rather
        // than touching freed memory.
        let run = |shared: &Shared<'_, u64>| {
            entered.fetch_add(1, Ordering::SeqCst);
            shared.drain_with(|_, _| shared.fail());
        };
        fan_out(&pools, (0..16).collect(), &run);
        release();
        assert_eq!(entered.load(Ordering::SeqCst), 1);
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

        let (pools, release) = held_pool();
        let armed = AtomicBool::new(true);
        let entered = AtomicUsize::new(0);
        // The operation outlives the call, so a late drain that enters it is counted rather
        // than touching freed memory. Only the first state's destructor panics, so such a drain
        // runs to completion.
        let run = |shared: &Shared<'_, u64>| {
            entered.fetch_add(1, Ordering::SeqCst);
            let _state = State(&armed);
            shared.drain_with(|_, _| shared.fail());
        };
        let outcome = panic::catch_unwind(AssertUnwindSafe(|| {
            fan_out(&pools, (0..16).collect(), &run);
        }));
        release();
        assert!(outcome.is_err());
        assert_eq!(entered.load(Ordering::SeqCst), 1);
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

        let (pools, release) = held_pool();
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
            try_map_collect_vec(&pools, items, &|_: Input<'_>| Err::<(), ()>(()))
        }));
        returned.store(true, Ordering::SeqCst);
        release();
        assert!(outcome.is_err());
        assert_eq!(late_drops.load(Ordering::SeqCst), 0);
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
        fn run(_: &Shared<'_, u64>) {
            panic::panic_any(Payload)
        }

        let shared = Shared::new(vec![0], 1, &run);
        shared.drain();
        shared.drain();
        assert_eq!(shared.active.load(Ordering::SeqCst), 0);
        assert!(panic::catch_unwind(AssertUnwindSafe(|| shared.finish())).is_err());
    }
}
