//! Parallel collection operations that split a vector of items over the calling worker's pool.
//!
//! Each operation drains its vector through a producer that can be split at any index, and feeds
//! the items to a consumer that splits at the same index and reduces the results of its two
//! halves. [`bridge_producer_consumer`] splits both in half with [`join_context`] while its
//! splitter allows, folds each remaining piece sequentially, and reduces the halves of every split
//! in order, so outputs keep the order of their items and reductions follow the tree of splits.
//!
//! The splitter starts with an allowance equal to the pool's thread count, splits while that
//! allowance is positive, and halves it at every split. When the second half runs as a queued
//! job, usually on a thread that stole it, its allowance is reset to at least the thread count
//! so the work can be divided again for idle threads.
//!
//! A consumer can report that it is full, after an error or once it takes no more items. The
//! bridge then stops splitting and folding, and drops the items that no piece consumed.
//!
//! Each operation composes the producer, consumers, folders, and reducers that rayon builds for
//! the parallel iterator expression named in its documentation.

#![allow(
    clippy::disallowed_types,
    reason = "Preserve upstream synchronization semantics."
)]

use super::{SendPtr, current_num_threads, join::join_context};
use std::{
    collections::LinkedList,
    iter,
    marker::PhantomData,
    mem, ptr, slice,
    sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

/// Maps every item with `map` and collects the outputs in the order of their items.
///
/// This is rayon's `items.into_par_iter().map(map).collect::<Vec<_>>()`.
///
/// # Panics
///
/// Panics if the calling thread is not a worker of a thread pool. A panic of `map` is resumed
/// once every other piece has finished, after every output and every item `map` did not take
/// has been dropped.
pub(crate) fn map_collect_vec<I: Send, T: Send>(
    items: Vec<I>,
    map: &(impl Fn(I) -> T + Sync),
) -> Vec<T> {
    let mut vec = Vec::new();
    let len = items.len();
    collect_with_consumer(&mut vec, len, |consumer| {
        bridge(items, MapConsumer::new(consumer, map))
    });
    vec
}

/// Maps every item with `map` and collects the outputs in the order of their items, or returns
/// an error `map` returned.
///
/// An error stops the operation early. Each piece in progress maps at most one more item and
/// drops its output, pieces not yet started are skipped, and the items no piece mapped are
/// dropped. If several items fail, which of their errors is returned is not specified.
///
/// This is rayon's `items.into_par_iter().map(map).collect::<Result<Vec<_>, _>>()`.
///
/// # Panics
///
/// Panics if the calling thread is not a worker of a thread pool. A panic of `map` is resumed
/// once every other piece has finished, after every output and every item `map` did not take
/// has been dropped.
pub(crate) fn try_map_collect_vec<I: Send, T: Send, E: Send>(
    items: Vec<I>,
    map: &(impl Fn(I) -> Result<T, E> + Sync),
) -> Result<Vec<T>, E> {
    let saved_error = Mutex::new(None);
    let list = {
        let ok = ok(&saved_error);
        let full = AtomicBool::new(false);
        let consumer = WhileSomeConsumer {
            base: ListVecConsumer,
            full: &full,
        };
        bridge(
            items,
            MapConsumer::new(MapConsumer::new(consumer, &ok), map),
        )
    };

    if let Some(error) = saved_error.into_inner().unwrap() {
        // Keep the error in a local until output destructors finish so unwinding drops it.
        drop(list);
        return Err(error);
    }

    // This works like `extend`, but `Vec::append` is more efficient.
    let mut collection = Vec::with_capacity(list.iter().map(Vec::len).sum());
    for mut other in list {
        collection.append(&mut other);
    }
    Ok(collection)
}

/// Maps every item with `map` and a state that `init` creates for each piece, and collects the
/// outputs in the order of their items.
///
/// This is rayon's `items.into_par_iter().map_init(init, map).collect::<Vec<_>>()`.
///
/// # Panics
///
/// Panics if the calling thread is not a worker of a thread pool. A panic of `init` or `map` is
/// resumed once every other piece has finished, after every output and every item `map` did not
/// take has been dropped.
pub(crate) fn map_init_collect_vec<I: Send, S: Send, T: Send>(
    items: Vec<I>,
    init: &(impl Fn() -> S + Sync),
    map: &(impl Fn(&mut S, I) -> T + Sync),
) -> Vec<T> {
    let mut vec = Vec::new();
    let len = items.len();
    collect_with_consumer(&mut vec, len, |consumer| {
        bridge(items, MapInitConsumer::new(consumer, init, map))
    });
    vec
}

/// Folds the items of each piece into `identity()` with `fold` and a state that `init` creates
/// for the piece, and reduces the pieces' accumulators with `reduce` in the order of their items.
///
/// Each piece reduces its accumulator into another `identity()` before the pieces are reduced.
///
/// This is rayon's `items.into_par_iter().fold(|| (init(), identity()), ..).map(|(_, acc)|
/// acc).reduce(identity, reduce)`, where the fold applies `fold` to the accumulator and the
/// state.
///
/// # Panics
///
/// Panics if the calling thread is not a worker of a thread pool. A panic of a closure is resumed
/// once every other piece has finished, after every accumulator and every item `fold` did not
/// take has been dropped.
pub(crate) fn fold_init<I: Send, S: Send, R: Send>(
    items: Vec<I>,
    init: &(impl Fn() -> S + Sync),
    identity: &(impl Fn() -> R + Sync),
    fold: &(impl Fn(R, &mut S, I) -> R + Sync),
    reduce: &(impl Fn(R, R) -> R + Sync),
) -> R {
    let fold_identity = || (init(), identity());
    let fold_op = |(mut init_val, acc): (S, R), item: I| {
        let new_acc = fold(acc, &mut init_val, item);
        (init_val, new_acc)
    };
    let map_op = |(_, acc): (S, R)| acc;
    let consumer = FoldConsumer {
        base: MapConsumer::new(
            ReduceConsumer {
                identity,
                reduce_op: reduce,
            },
            &map_op,
        ),
        fold_op: &fold_op,
        identity: &fold_identity,
    };
    bridge(items, consumer)
}

/// Folds the items of each piece into `identity()` with `fold` until it returns an error, and
/// reduces the pieces' accumulators with `reduce` in the order of their items, or returns an
/// error `fold` returned.
///
/// Each piece reduces its accumulator into another `identity()` before the pieces are reduced.
/// A piece stops at its first error. Once a failed piece has finished, the pieces in progress
/// stop after their current item, pieces not yet started are skipped, and the items no piece
/// folded are dropped. If several pieces fail, which of their errors is returned is not
/// specified.
///
/// This is rayon's `items.into_par_iter().try_fold(identity, fold).try_reduce(identity, |a, b|
/// Ok(reduce(a, b)))`.
///
/// # Panics
///
/// Panics if the calling thread is not a worker of a thread pool. A panic of a closure is resumed
/// once every other piece has finished, after every accumulator and every item `fold` did not
/// take has been dropped.
pub(crate) fn try_fold<I: Send, R: Send, E: Send>(
    items: Vec<I>,
    identity: &(impl Fn() -> R + Sync),
    fold: &(impl Fn(R, I) -> Result<R, E> + Sync),
    reduce: &(impl Fn(R, R) -> R + Sync),
) -> Result<R, E> {
    let reduce_op = |a: R, b: R| -> Result<R, E> { Ok(reduce(a, b)) };
    let full = AtomicBool::new(false);
    let consumer = TryFoldConsumer {
        base: TryReduceConsumer {
            identity,
            reduce_op: &reduce_op,
            full: &full,
        },
        identity,
        fold_op: fold,
    };
    bridge(items, consumer)
}

/// A consumer is effectively a generalized "fold" operation, and in fact each consumer will
/// eventually be converted into a [`Folder`]. What makes a consumer special is that, like a
/// producer, it can be **split** into multiple consumers using the `split_at` method. When a
/// consumer is split, it produces two consumers, as well as a **reducer**. The two consumers can
/// be fed items independently, and when they are done the reducer is used to combine their two
/// results into one.
trait Consumer<Item>: Send + Sized {
    /// The type of folder that this consumer can be converted into.
    type Folder: Folder<Item, Result = Self::Result>;

    /// The type of reducer that is produced if this consumer is split.
    type Reducer: Reducer<Self::Result>;

    /// The type of result that this consumer will ultimately produce.
    type Result: Send;

    /// Divide the consumer into two consumers, one processing items `0..index` and one
    /// processing items from `index..`. Also produces a reducer that can be used to reduce the
    /// results at the end.
    fn split_at(self, index: usize) -> (Self, Self, Self::Reducer);

    /// Convert the consumer into a folder that can consume items sequentially, eventually
    /// producing a final result.
    fn into_folder(self) -> Self::Folder;

    /// Hint whether this `Consumer` would like to stop processing further items, e.g. if a
    /// search has been completed.
    fn full(&self) -> bool;
}

/// The `Folder` trait encapsulates the standard fold operation. It can be fed many items using
/// the `consume` method. At the end, once all items have been consumed, it can then be converted
/// (using `complete`) into a final value.
trait Folder<Item>: Sized {
    /// The type of result that will ultimately be produced by the folder.
    type Result;

    /// Consume next item and return new sequential state.
    fn consume(self, item: Item) -> Self;

    /// Consume items from the iterator until full, and return new sequential state.
    ///
    /// This method is **optional**. The default simply iterates over `iter`, invoking `consume`
    /// and checking after each iteration whether `full` returns false.
    ///
    /// The main reason to override it is if you can provide a more specialized, efficient
    /// implementation.
    fn consume_iter<I>(mut self, iter: I) -> Self
    where
        I: IntoIterator<Item = Item>,
    {
        for item in iter {
            self = self.consume(item);
            if self.full() {
                break;
            }
        }
        self
    }

    /// Finish consuming items, produce final result.
    fn complete(self) -> Self::Result;

    /// Hint whether this `Folder` would like to stop processing further items, e.g. if a search
    /// has been completed.
    fn full(&self) -> bool;
}

/// The reducer is the final step of a `Consumer`. After a consumer has been split into two parts,
/// and each of those parts has been fully processed, we are left with two results. The reducer is
/// then used to combine those two results into one.
trait Reducer<Result> {
    /// Reduce two final results into one. This is executed after a split.
    fn reduce(self, left: Result, right: Result) -> Result;
}

/// A splitter controls the policy for splitting into smaller work items.
///
/// Thief-splitting is an adaptive policy that starts by splitting into enough jobs for every
/// worker thread, and then resets itself whenever a job is actually stolen into a different
/// thread.
#[derive(Clone, Copy)]
struct Splitter {
    /// The `splits` tell us approximately how many remaining times we'd like to split this job.
    /// We always just divide it by two though, so the effective number of pieces will be
    /// `next_power_of_two()`.
    splits: usize,
}

impl Splitter {
    #[inline]
    fn new() -> Self {
        Self {
            splits: current_num_threads(),
        }
    }

    #[inline]
    fn try_split(&mut self, stolen: bool) -> bool {
        let Self { splits } = *self;

        if stolen {
            // This job was stolen!  Reset the number of desired splits to the
            // thread count, if that's more than we had remaining anyway.
            self.splits = Ord::max(current_num_threads(), self.splits / 2);
            true
        } else if splits > 0 {
            // We have splits remaining, make it so.
            self.splits /= 2;
            true
        } else {
            // Not stolen, and no more splits -- we're done!
            false
        }
    }
}

/// The length splitter is built on thief-splitting, but additionally takes into account the
/// remaining length of the iterator.
#[derive(Clone, Copy)]
struct LengthSplitter {
    inner: Splitter,

    /// The smallest we're willing to divide into.
    min: usize,
}

impl LengthSplitter {
    /// Creates a new splitter based on lengths.
    ///
    /// The `min` is a hard lower bound.  We'll never split below that, but of course an iterator
    /// might start out smaller already.
    ///
    /// The `max` is an upper bound on the working size, used to determine the minimum number of
    /// times we need to split to get under that limit. The adaptive algorithm may very well split
    /// even further, but never smaller than the `min`.
    #[inline]
    fn new(min: usize, max: usize, len: usize) -> Self {
        let mut splitter = Self {
            inner: Splitter::new(),
            min: Ord::max(min, 1),
        };

        // Divide the given length by the max working length to get the minimum
        // number of splits we need to get under that max.  This rounds down,
        // but the splitter actually gives `next_power_of_two()` pieces anyway.
        // e.g. len 12345 / max 100 = 123 min_splits -> 128 pieces.
        let min_splits = len / Ord::max(max, 1);

        // Only update the value if it's not splitting enough already.
        if min_splits > splitter.inner.splits {
            splitter.inner.splits = min_splits;
        }

        splitter
    }

    #[inline]
    fn try_split(&mut self, len: usize, stolen: bool) -> bool {
        // If splitting wouldn't make us too small, try the inner splitter.
        len / 2 >= self.min && self.inner.try_split(stolen)
    }
}

/// Drains every item of `vec` into a producer and passes it to `callback`. The producer moves
/// or drops each item, and the vector then only frees its buffer.
fn with_producer<T: Send, R>(
    mut vec: Vec<T>,
    callback: impl FnOnce(DrainProducer<'_, T>) -> R,
) -> R {
    let len = vec.len();

    // SAFETY: The vector forgets its `len` initialized items before the producer takes them over,
    // so the producer is their only owner, and the vector, whose length stays zero, never reads
    // them again.
    unsafe {
        // Make the vector forget about the drained items.
        vec.set_len(0);

        // Create the producer as the exclusive "owner" of the slice.
        let producer = DrainProducer::from_vec(&mut vec, len);

        // The producer will move or drop each item from the drained range.
        callback(producer)
    }
}

/// Drains every item of `vec` into `consumer`, splitting and creating parallel tasks as needed.
fn bridge<T: Send, C: Consumer<T>>(vec: Vec<T>, consumer: C) -> C::Result {
    let len = vec.len();
    with_producer(vec, |producer| {
        bridge_producer_consumer(len, producer, consumer)
    })
}

/// This helper function is used to "connect" a producer and a consumer. This function will draw
/// items from `producer` and feed them to `consumer`, splitting and creating parallel tasks when
/// needed.
fn bridge_producer_consumer<T: Send, C: Consumer<T>>(
    len: usize,
    producer: DrainProducer<'_, T>,
    consumer: C,
) -> C::Result {
    // A drain splits down to single items and has no maximum piece length.
    let splitter = LengthSplitter::new(1, usize::MAX, len);
    return helper(len, false, splitter, producer, consumer);

    fn helper<T: Send, C: Consumer<T>>(
        len: usize,
        migrated: bool,
        mut splitter: LengthSplitter,
        producer: DrainProducer<'_, T>,
        consumer: C,
    ) -> C::Result {
        if consumer.full() {
            consumer.into_folder().complete()
        } else if splitter.try_split(len, migrated) {
            let mid = len / 2;
            let (left_producer, right_producer) = producer.split_at(mid);
            let (left_consumer, right_consumer, reducer) = consumer.split_at(mid);
            let (left_result, right_result) = join_context(
                |context| {
                    helper(
                        mid,
                        context.migrated(),
                        splitter,
                        left_producer,
                        left_consumer,
                    )
                },
                |context| {
                    helper(
                        len - mid,
                        context.migrated(),
                        splitter,
                        right_producer,
                        right_consumer,
                    )
                },
            );
            reducer.reduce(left_result, right_result)
        } else {
            producer.fold_with(consumer.into_folder()).complete()
        }
    }
}

/// A producer that moves the items out of a slice, splitting into producers of its halves until
/// it is converted into an iterator. Items it has not produced are dropped with it.
struct DrainProducer<'data, T: Send> {
    slice: &'data mut [T],
}

impl<'data, T: Send> DrainProducer<'data, T> {
    /// Creates a draining producer, which *moves* items from the slice.
    ///
    /// Unsafe because `!Copy` data must not be read after the borrow is released.
    const unsafe fn new(slice: &'data mut [T]) -> Self {
        Self { slice }
    }

    /// Creates a draining producer, which *moves* items from the tail of the vector.
    ///
    /// Unsafe because we're moving from beyond `vec.len()`, so the caller must ensure that data
    /// is initialized and not read after the borrow is released.
    unsafe fn from_vec(vec: &'data mut Vec<T>, len: usize) -> Self {
        let start = vec.len();
        assert!(vec.capacity() - start >= len);

        // SAFETY: The assert keeps the `len` items after `start` within the allocation, and the
        // caller ensures they are initialized and not read after the borrow is released. The
        // pointer is derived from `Vec` directly, not through a `Deref`, so it has provenance
        // over the whole allocation.
        unsafe {
            let ptr = vec.as_mut_ptr().add(start);
            Self::new(slice::from_raw_parts_mut(ptr, len))
        }
    }

    /// Split into two producers, one producing items `0..index` and the other `index..N`.
    /// Index must be less than or equal to `N`.
    fn split_at(mut self, index: usize) -> (Self, Self) {
        // replace the slice so we don't drop it twice
        let slice = mem::take(&mut self.slice);
        let (left, right) = slice.split_at_mut(index);

        // SAFETY: The halves partition the slice this producer owned, so each item still has one
        // producer that moves or drops it.
        unsafe { (Self::new(left), Self::new(right)) }
    }

    /// Iterate the producer, feeding each element to `folder`, and stop when the folder is full
    /// (or all elements have been consumed).
    fn fold_with<F>(self, folder: F) -> F
    where
        F: Folder<T>,
    {
        folder.consume_iter(self)
    }
}

impl<'data, T: 'data + Send> IntoIterator for DrainProducer<'data, T> {
    type Item = T;
    type IntoIter = SliceDrain<'data, T>;

    /// Convert `self` into an iterator. At this point, no more parallel splits are possible.
    fn into_iter(mut self) -> Self::IntoIter {
        // replace the slice so we don't drop it twice
        let slice = mem::take(&mut self.slice);
        SliceDrain {
            iter: slice.iter_mut(),
        }
    }
}

impl<'data, T: 'data + Send> Drop for DrainProducer<'data, T> {
    fn drop(&mut self) {
        // extract the slice so we can use `Drop for [T]`
        let slice_ptr: *mut [T] = mem::take::<&'data mut [T]>(&mut self.slice);

        // SAFETY: The producer owns the items left in its slice, which nothing reads afterwards,
        // and taking the slice leaves the producer empty, so each item drops once.
        unsafe { ptr::drop_in_place::<[T]>(slice_ptr) };
    }
}

/// Like `std::vec::Drain`, without updating a source `Vec`.
struct SliceDrain<'data, T> {
    iter: slice::IterMut<'data, T>,
}

impl<'data, T: 'data> Iterator for SliceDrain<'data, T> {
    type Item = T;

    fn next(&mut self) -> Option<T> {
        // Coerce the pointer early, so we don't keep the
        // reference that's about to be invalidated.
        let ptr: *const T = self.iter.next()?;

        // SAFETY: The drain owns the items of its iterator, and the iterator has moved past this
        // one, so neither it nor the drop of the drain reads it again.
        Some(unsafe { ptr::read(ptr) })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.iter.size_hint()
    }

    fn count(self) -> usize {
        self.iter.len()
    }
}

impl<'data, T: 'data> DoubleEndedIterator for SliceDrain<'data, T> {
    fn next_back(&mut self) -> Option<Self::Item> {
        // Coerce the pointer early, so we don't keep the
        // reference that's about to be invalidated.
        let ptr: *const T = self.iter.next_back()?;

        // SAFETY: The drain owns the items of its iterator, and the iterator has moved past this
        // one, so neither it nor the drop of the drain reads it again.
        Some(unsafe { ptr::read(ptr) })
    }
}

impl<'data, T: 'data> ExactSizeIterator for SliceDrain<'data, T> {
    fn len(&self) -> usize {
        self.iter.len()
    }
}

impl<'data, T: 'data> iter::FusedIterator for SliceDrain<'data, T> {}

impl<'data, T: 'data> Drop for SliceDrain<'data, T> {
    fn drop(&mut self) {
        // extract the iterator so we can use `Drop for [T]`
        let slice_ptr: *mut [T] = mem::replace(&mut self.iter, [].iter_mut()).into_slice();

        // SAFETY: The items the iterator has not yielded are owned by the drain and were never
        // read, and the empty iterator left in place keeps them from dropping twice.
        unsafe { ptr::drop_in_place::<[T]>(slice_ptr) };
    }
}

/// Create a consumer on the slice of memory we are collecting into.
///
/// The consumer needs to be used inside the scope function, and the complete collect result
/// passed back.
///
/// This method will verify the collect result, and panic if the slice was not fully written
/// into. Otherwise, in the successful case, the vector is complete with the collected result.
fn collect_with_consumer<T, F>(vec: &mut Vec<T>, len: usize, scope_fn: F)
where
    T: Send,
    F: FnOnce(CollectConsumer<'_, T>) -> CollectResult<'_, T>,
{
    // Reserve space for `len` more elements in the vector.
    vec.reserve(len);

    // Create the consumer and run the callback for collection.
    let result = scope_fn(CollectConsumer::appender(vec, len));

    // The `CollectResult` represents a contiguous part of the slice, that has
    // been written to. On unwind here, the `CollectResult` will be dropped. If
    // some producers on the way did not produce enough elements, partial
    // `CollectResult`s may have been dropped without being reduced to the final
    // result, and we will see that as the length coming up short.
    //
    // Here, we assert that added length is fully initialized. This is checked
    // by the following assert, which verifies if a complete `CollectResult`
    // was produced. If the length is correct, it is necessarily covering the
    // target slice. Since we know that the consumer cannot have escaped from
    // `scope_fn` (by parametricity, essentially), we know that any stores that
    // will happen, have happened. Unless some code is buggy, that means we
    // should have seen `len` total writes.
    let actual_writes = result.len();
    assert!(
        actual_writes == len,
        "expected {len} total writes, but got {actual_writes}"
    );

    // Release the result's mutable borrow and "proxy ownership"
    // of the elements, before the vector takes it over.
    result.release_ownership();

    let new_len = vec.len() + len;

    // SAFETY: The complete result covered the `len` slots after the vector's length, so they are
    // initialized, and releasing the result handed their ownership to the vector.
    unsafe {
        vec.set_len(new_len);
    }
}

/// Writes the items of its range in order into the spare capacity of a vector.
struct CollectConsumer<'c, T: Send> {
    /// See `CollectResult` for explanation of why this is not a slice
    start: SendPtr<T>,
    len: usize,
    marker: PhantomData<&'c mut T>,
}

impl<'c, T: Send + 'c> CollectConsumer<'c, T> {
    /// Create a collector for `len` items in the unused capacity of the vector.
    fn appender(vec: &'c mut Vec<T>, len: usize) -> Self {
        let start = vec.len();
        assert!(vec.capacity() - start >= len);

        // SAFETY: We already made sure to have the additional space allocated.
        // The pointer is derived from `Vec` directly, not through a `Deref`,
        // so it has provenance over the whole allocation.
        unsafe { Self::new(vec.as_mut_ptr().add(start), len) }
    }

    /// The target memory is considered uninitialized, and will be
    /// overwritten without reading or dropping existing values.
    const unsafe fn new(start: *mut T, len: usize) -> Self {
        Self {
            start: SendPtr(start),
            len,
            marker: PhantomData,
        }
    }
}

/// CollectResult represents an initialized part of the target slice.
///
/// This is a proxy owner of the elements in the slice. When it drops,
/// the elements will be dropped, unless its ownership is released before then.
#[must_use]
struct CollectResult<'c, T> {
    /// This pointer and length has the same representation as a slice,
    /// but retains the provenance of the entire array so that we can merge
    /// these regions together in `CollectReducer`.
    start: SendPtr<T>,
    total_len: usize,
    /// The current initialized length after `start`
    initialized_len: usize,
    /// Lifetime invariance guarantees that the data flows from consumer to result,
    /// especially for the `scope_fn` callback in `collect_with_consumer`.
    invariant_lifetime: PhantomData<&'c mut &'c mut [T]>,
}

// SAFETY: The result owns the initialized elements of its part of the slice, so sending it sends
// those elements, which are `Send`.
unsafe impl<'c, T> Send for CollectResult<'c, T> where T: Send {}

impl<'c, T> CollectResult<'c, T> {
    /// The current length of the collect result
    const fn len(&self) -> usize {
        self.initialized_len
    }

    /// Release ownership of the slice of elements, and return the length
    fn release_ownership(mut self) -> usize {
        let ret = self.initialized_len;
        self.initialized_len = 0;
        ret
    }
}

impl<'c, T> Drop for CollectResult<'c, T> {
    fn drop(&mut self) {
        // SAFETY: Drop the first `self.initialized_len` elements, which have been recorded to be
        // initialized by the folder and are owned by this result until it releases its ownership,
        // which zeroes the length.
        unsafe {
            ptr::drop_in_place(ptr::slice_from_raw_parts_mut(
                self.start.0,
                self.initialized_len,
            ));
        }
    }
}

impl<'c, T: Send + 'c> Consumer<T> for CollectConsumer<'c, T> {
    type Folder = CollectResult<'c, T>;
    type Reducer = CollectReducer;
    type Result = CollectResult<'c, T>;

    fn split_at(self, index: usize) -> (Self, Self, CollectReducer) {
        let CollectConsumer { start, len, .. } = self;

        // Produce new consumers.
        // SAFETY: This assert checks that `index` is a valid offset for `start`
        unsafe {
            assert!(index <= len);
            (
                Self::new(start.0, index),
                Self::new(start.0.add(index), len - index),
                CollectReducer,
            )
        }
    }

    fn into_folder(self) -> Self::Folder {
        // Create a result/folder that consumes values and writes them
        // into the region after start. The initial result has length 0.
        CollectResult {
            start: self.start,
            total_len: self.len,
            initialized_len: 0,
            invariant_lifetime: PhantomData,
        }
    }

    fn full(&self) -> bool {
        false
    }
}

impl<'c, T: Send + 'c> Folder<T> for CollectResult<'c, T> {
    type Result = Self;

    fn consume(mut self, item: T) -> Self {
        assert!(
            self.initialized_len < self.total_len,
            "too many values pushed to consumer"
        );

        // SAFETY: The assert above is a bounds check for this write, and we
        // avoid assignment here so we do not drop an uninitialized T.
        unsafe {
            // Write item and increase the initialized length
            self.start.0.add(self.initialized_len).write(item);
            self.initialized_len += 1;
        }

        self
    }

    fn complete(self) -> Self::Result {
        // We don't explicitly check that the local writes were complete,
        // but `collect_with_consumer` asserts the total result length in the end.
        self
    }

    fn full(&self) -> bool {
        false
    }
}

/// CollectReducer combines adjacent chunks. The result must always
/// be contiguous so that it is one combined slice.
struct CollectReducer;

impl<'c, T> Reducer<CollectResult<'c, T>> for CollectReducer {
    fn reduce(
        self,
        mut left: CollectResult<'c, T>,
        right: CollectResult<'c, T>,
    ) -> CollectResult<'c, T> {
        // Merge if the CollectResults are adjacent and in left to right order.
        // Otherwise, drop the right piece now, and the total length will end up
        // short when the correctness of the collected result is asserted.
        //
        // SAFETY: The initialized elements of `left` lie within its part of the slice, so the
        // offset past them stays within the allocation.
        unsafe {
            let left_end = left.start.0.add(left.initialized_len);
            if left_end == right.start.0 {
                left.total_len += right.total_len;
                left.initialized_len += right.release_ownership();
            }
            left
        }
    }
}

/// Collects the items of each piece into a vector and links the pieces' vectors in order.
struct ListVecConsumer;

struct ListVecFolder<T> {
    vec: Vec<T>,
}

impl<T: Send> Consumer<T> for ListVecConsumer {
    type Folder = ListVecFolder<T>;
    type Reducer = ListReducer;
    type Result = LinkedList<Vec<T>>;

    fn split_at(self, _index: usize) -> (Self, Self, Self::Reducer) {
        (Self, Self, ListReducer)
    }

    fn into_folder(self) -> Self::Folder {
        ListVecFolder { vec: Vec::new() }
    }

    fn full(&self) -> bool {
        false
    }
}

impl<T> Folder<T> for ListVecFolder<T> {
    type Result = LinkedList<Vec<T>>;

    fn consume(mut self, item: T) -> Self {
        self.vec.push(item);
        self
    }

    fn consume_iter<I>(mut self, iter: I) -> Self
    where
        I: IntoIterator<Item = T>,
    {
        self.vec.extend(iter);
        self
    }

    fn complete(self) -> Self::Result {
        let mut list = LinkedList::new();
        if !self.vec.is_empty() {
            list.push_back(self.vec);
        }
        list
    }

    fn full(&self) -> bool {
        false
    }
}

struct ListReducer;

impl<T> Reducer<LinkedList<T>> for ListReducer {
    fn reduce(self, mut left: LinkedList<T>, mut right: LinkedList<T>) -> LinkedList<T> {
        left.append(&mut right);
        left
    }
}

/// Maps each item with `map_op` before passing it on.
struct MapConsumer<'f, C, F> {
    base: C,
    map_op: &'f F,
}

impl<'f, C, F> MapConsumer<'f, C, F> {
    const fn new(base: C, map_op: &'f F) -> Self {
        Self { base, map_op }
    }
}

impl<'f, T, R, C, F> Consumer<T> for MapConsumer<'f, C, F>
where
    C: Consumer<F::Output>,
    F: Fn(T) -> R + Sync,
    R: Send,
{
    type Folder = MapFolder<'f, C::Folder, F>;
    type Reducer = C::Reducer;
    type Result = C::Result;

    fn split_at(self, index: usize) -> (Self, Self, Self::Reducer) {
        let (left, right, reducer) = self.base.split_at(index);
        (
            MapConsumer::new(left, self.map_op),
            MapConsumer::new(right, self.map_op),
            reducer,
        )
    }

    fn into_folder(self) -> Self::Folder {
        MapFolder {
            base: self.base.into_folder(),
            map_op: self.map_op,
        }
    }

    fn full(&self) -> bool {
        self.base.full()
    }
}

struct MapFolder<'f, C, F> {
    base: C,
    map_op: &'f F,
}

impl<'f, T, R, C, F> Folder<T> for MapFolder<'f, C, F>
where
    C: Folder<F::Output>,
    F: Fn(T) -> R,
{
    type Result = C::Result;

    fn consume(self, item: T) -> Self {
        let mapped_item = (self.map_op)(item);
        MapFolder {
            base: self.base.consume(mapped_item),
            map_op: self.map_op,
        }
    }

    fn consume_iter<I>(mut self, iter: I) -> Self
    where
        I: IntoIterator<Item = T>,
    {
        self.base = self.base.consume_iter(iter.into_iter().map(self.map_op));
        self
    }

    fn complete(self) -> C::Result {
        self.base.complete()
    }

    fn full(&self) -> bool {
        self.base.full()
    }
}

/// Maps each item with `map_op` and a state that `init` creates for each folder before passing
/// it on.
struct MapInitConsumer<'f, C, INIT, F> {
    base: C,
    init: &'f INIT,
    map_op: &'f F,
}

impl<'f, C, INIT, F> MapInitConsumer<'f, C, INIT, F> {
    const fn new(base: C, init: &'f INIT, map_op: &'f F) -> Self {
        Self { base, init, map_op }
    }
}

impl<'f, T, INIT, U, R, C, F> Consumer<T> for MapInitConsumer<'f, C, INIT, F>
where
    C: Consumer<R>,
    INIT: Fn() -> U + Sync,
    F: Fn(&mut U, T) -> R + Sync,
    R: Send,
{
    type Folder = MapWithFolder<'f, C::Folder, U, F>;
    type Reducer = C::Reducer;
    type Result = C::Result;

    fn split_at(self, index: usize) -> (Self, Self, Self::Reducer) {
        let (left, right, reducer) = self.base.split_at(index);
        (
            MapInitConsumer::new(left, self.init, self.map_op),
            MapInitConsumer::new(right, self.init, self.map_op),
            reducer,
        )
    }

    fn into_folder(self) -> Self::Folder {
        MapWithFolder {
            base: self.base.into_folder(),
            item: (self.init)(),
            map_op: self.map_op,
        }
    }

    fn full(&self) -> bool {
        self.base.full()
    }
}

struct MapWithFolder<'f, C, U, F> {
    base: C,
    item: U,
    map_op: &'f F,
}

impl<'f, T, U, R, C, F> Folder<T> for MapWithFolder<'f, C, U, F>
where
    C: Folder<R>,
    F: Fn(&mut U, T) -> R,
{
    type Result = C::Result;

    fn consume(mut self, item: T) -> Self {
        let mapped_item = (self.map_op)(&mut self.item, item);
        self.base = self.base.consume(mapped_item);
        self
    }

    fn consume_iter<I>(mut self, iter: I) -> Self
    where
        I: IntoIterator<Item = T>,
    {
        fn with<'f, T, U, R>(
            item: &'f mut U,
            map_op: impl Fn(&mut U, T) -> R + 'f,
        ) -> impl FnMut(T) -> R + 'f {
            move |x| map_op(item, x)
        }

        {
            let mapped_iter = iter.into_iter().map(with(&mut self.item, self.map_op));
            self.base = self.base.consume_iter(mapped_iter);
        }
        self
    }

    fn complete(self) -> C::Result {
        self.base.complete()
    }

    fn full(&self) -> bool {
        self.base.full()
    }
}

/// Turns an `Err` into `None` after saving its error, unless another error was saved first.
fn ok<T, E>(saved: &Mutex<Option<E>>) -> impl Fn(Result<T, E>) -> Option<T> + '_ {
    move |item| match item {
        Ok(item) => Some(item),
        Err(error) => {
            // We don't need a blocking `lock()`, as anybody
            // else holding the lock will also be writing
            // `Some(error)`, and then ours is irrelevant.
            if let Ok(mut guard) = saved.try_lock()
                && guard.is_none()
            {
                *guard = Some(error);
            }
            None
        }
    }
}

/// Passes on the items of `Some` and stops every piece at the first `None`.
struct WhileSomeConsumer<'f, C> {
    base: C,
    full: &'f AtomicBool,
}

impl<'f, T, C> Consumer<Option<T>> for WhileSomeConsumer<'f, C>
where
    C: Consumer<T>,
    T: Send,
{
    type Folder = WhileSomeFolder<'f, C::Folder>;
    type Reducer = C::Reducer;
    type Result = C::Result;

    fn split_at(self, index: usize) -> (Self, Self, Self::Reducer) {
        let (left, right, reducer) = self.base.split_at(index);
        (
            WhileSomeConsumer { base: left, ..self },
            WhileSomeConsumer {
                base: right,
                ..self
            },
            reducer,
        )
    }

    fn into_folder(self) -> Self::Folder {
        WhileSomeFolder {
            base: self.base.into_folder(),
            full: self.full,
        }
    }

    fn full(&self) -> bool {
        self.full.load(Ordering::Relaxed) || self.base.full()
    }
}

struct WhileSomeFolder<'f, C> {
    base: C,
    full: &'f AtomicBool,
}

impl<'f, T, C> Folder<Option<T>> for WhileSomeFolder<'f, C>
where
    C: Folder<T>,
{
    type Result = C::Result;

    fn consume(mut self, item: Option<T>) -> Self {
        match item {
            Some(item) => self.base = self.base.consume(item),
            None => self.full.store(true, Ordering::Relaxed),
        }
        self
    }

    fn consume_iter<I>(mut self, iter: I) -> Self
    where
        I: IntoIterator<Item = Option<T>>,
    {
        fn some<T>(full: &AtomicBool) -> impl Fn(&Option<T>) -> bool + '_ {
            move |x| match *x {
                Some(_) => !full.load(Ordering::Relaxed),
                None => {
                    full.store(true, Ordering::Relaxed);
                    false
                }
            }
        }

        self.base = self.base.consume_iter(
            iter.into_iter()
                .take_while(some(self.full))
                .map(Option::unwrap),
        );
        self
    }

    fn complete(self) -> C::Result {
        self.base.complete()
    }

    fn full(&self) -> bool {
        self.full.load(Ordering::Relaxed) || self.base.full()
    }
}

/// Folds the items of each folder into `identity()` with `fold_op`, and passes on the
/// accumulator when the folder completes.
struct FoldConsumer<'c, C, ID, F> {
    base: C,
    fold_op: &'c F,
    identity: &'c ID,
}

impl<'r, U, T, C, ID, F> Consumer<T> for FoldConsumer<'r, C, ID, F>
where
    C: Consumer<U>,
    F: Fn(U, T) -> U + Sync,
    ID: Fn() -> U + Sync,
    U: Send,
{
    type Folder = FoldFolder<'r, C::Folder, U, F>;
    type Reducer = C::Reducer;
    type Result = C::Result;

    fn split_at(self, index: usize) -> (Self, Self, Self::Reducer) {
        let (left, right, reducer) = self.base.split_at(index);
        (
            FoldConsumer { base: left, ..self },
            FoldConsumer {
                base: right,
                ..self
            },
            reducer,
        )
    }

    fn into_folder(self) -> Self::Folder {
        FoldFolder {
            base: self.base.into_folder(),
            item: (self.identity)(),
            fold_op: self.fold_op,
        }
    }

    fn full(&self) -> bool {
        self.base.full()
    }
}

struct FoldFolder<'r, C, ID, F> {
    base: C,
    fold_op: &'r F,
    item: ID,
}

impl<'r, C, ID, F, T> Folder<T> for FoldFolder<'r, C, ID, F>
where
    C: Folder<ID>,
    F: Fn(ID, T) -> ID + Sync,
{
    type Result = C::Result;

    fn consume(self, item: T) -> Self {
        let item = (self.fold_op)(self.item, item);
        FoldFolder {
            base: self.base,
            fold_op: self.fold_op,
            item,
        }
    }

    fn consume_iter<I>(self, iter: I) -> Self
    where
        I: IntoIterator<Item = T>,
    {
        fn not_full<C, ID, T>(base: &C) -> impl Fn(&T) -> bool + '_
        where
            C: Folder<ID>,
        {
            move |_| !base.full()
        }

        let base = self.base;
        let item = iter
            .into_iter()
            // stop iterating if another thread has finished
            .take_while(not_full(&base))
            .fold(self.item, self.fold_op);

        FoldFolder {
            base,
            item,
            fold_op: self.fold_op,
        }
    }

    fn complete(self) -> C::Result {
        self.base.consume(self.item).complete()
    }

    fn full(&self) -> bool {
        self.base.full()
    }
}

/// Reduces the items of each folder into `identity()` with `reduce_op`, and reduces the results
/// of split consumers with `reduce_op`.
struct ReduceConsumer<'r, R, ID> {
    identity: &'r ID,
    reduce_op: &'r R,
}

impl<'r, R, ID> Copy for ReduceConsumer<'r, R, ID> {}

impl<'r, R, ID> Clone for ReduceConsumer<'r, R, ID> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<'r, R, ID, T> Consumer<T> for ReduceConsumer<'r, R, ID>
where
    R: Fn(T, T) -> T + Sync,
    ID: Fn() -> T + Sync,
    T: Send,
{
    type Folder = ReduceFolder<'r, R, T>;
    type Reducer = Self;
    type Result = T;

    fn split_at(self, _index: usize) -> (Self, Self, Self) {
        (self, self, self)
    }

    fn into_folder(self) -> Self::Folder {
        ReduceFolder {
            reduce_op: self.reduce_op,
            item: (self.identity)(),
        }
    }

    fn full(&self) -> bool {
        false
    }
}

impl<'r, R, ID, T> Reducer<T> for ReduceConsumer<'r, R, ID>
where
    R: Fn(T, T) -> T + Sync,
{
    fn reduce(self, left: T, right: T) -> T {
        (self.reduce_op)(left, right)
    }
}

struct ReduceFolder<'r, R, T> {
    reduce_op: &'r R,
    item: T,
}

impl<'r, R, T> Folder<T> for ReduceFolder<'r, R, T>
where
    R: Fn(T, T) -> T,
{
    type Result = T;

    fn consume(self, item: T) -> Self {
        ReduceFolder {
            reduce_op: self.reduce_op,
            item: (self.reduce_op)(self.item, item),
        }
    }

    fn consume_iter<I>(self, iter: I) -> Self
    where
        I: IntoIterator<Item = T>,
    {
        ReduceFolder {
            reduce_op: self.reduce_op,
            item: iter.into_iter().fold(self.item, self.reduce_op),
        }
    }

    fn complete(self) -> T {
        self.item
    }

    fn full(&self) -> bool {
        false
    }
}

/// Folds the items of each folder into `identity()` with `fold_op` until it returns an error,
/// and passes on the accumulator or the error when the folder completes.
struct TryFoldConsumer<'c, C, ID, F> {
    base: C,
    identity: &'c ID,
    fold_op: &'c F,
}

impl<'r, R, E, T, C, ID, F> Consumer<T> for TryFoldConsumer<'r, C, ID, F>
where
    C: Consumer<Result<R, E>>,
    F: Fn(R, T) -> Result<R, E> + Sync,
    ID: Fn() -> R + Sync,
    R: Send,
    E: Send,
{
    type Folder = TryFoldFolder<'r, C::Folder, R, E, F>;
    type Reducer = C::Reducer;
    type Result = C::Result;

    fn split_at(self, index: usize) -> (Self, Self, Self::Reducer) {
        let (left, right, reducer) = self.base.split_at(index);
        (
            TryFoldConsumer { base: left, ..self },
            TryFoldConsumer {
                base: right,
                ..self
            },
            reducer,
        )
    }

    fn into_folder(self) -> Self::Folder {
        TryFoldFolder {
            base: self.base.into_folder(),
            control: Ok((self.identity)()),
            fold_op: self.fold_op,
        }
    }

    fn full(&self) -> bool {
        self.base.full()
    }
}

struct TryFoldFolder<'r, C, R, E, F> {
    base: C,
    fold_op: &'r F,
    control: Result<R, E>,
}

impl<'r, C, R, E, F, T> Folder<T> for TryFoldFolder<'r, C, R, E, F>
where
    C: Folder<Result<R, E>>,
    F: Fn(R, T) -> Result<R, E> + Sync,
{
    type Result = C::Result;

    fn consume(mut self, item: T) -> Self {
        let fold_op = self.fold_op;
        if let Ok(acc) = self.control {
            self.control = fold_op(acc, item);
        }
        self
    }

    fn complete(self) -> C::Result {
        self.base.consume(self.control).complete()
    }

    fn full(&self) -> bool {
        match self.control {
            Err(_) => true,
            _ => self.base.full(),
        }
    }
}

/// Reduces the items of each folder into `identity()` with `reduce_op`, and the results of split
/// consumers with `reduce_op`, until an error. An error marks every consumer split from the same
/// one full and is passed on in place of any result, the left one if both halves failed.
struct TryReduceConsumer<'r, R, ID> {
    identity: &'r ID,
    reduce_op: &'r R,
    full: &'r AtomicBool,
}

impl<'r, R, ID> Copy for TryReduceConsumer<'r, R, ID> {}

impl<'r, R, ID> Clone for TryReduceConsumer<'r, R, ID> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<'r, R, ID, T, E> Consumer<Result<T, E>> for TryReduceConsumer<'r, R, ID>
where
    R: Fn(T, T) -> Result<T, E> + Sync,
    ID: Fn() -> T + Sync,
    T: Send,
    E: Send,
{
    type Folder = TryReduceFolder<'r, R, T, E>;
    type Reducer = Self;
    type Result = Result<T, E>;

    fn split_at(self, _index: usize) -> (Self, Self, Self) {
        (self, self, self)
    }

    fn into_folder(self) -> Self::Folder {
        TryReduceFolder {
            reduce_op: self.reduce_op,
            control: Ok((self.identity)()),
            full: self.full,
        }
    }

    fn full(&self) -> bool {
        self.full.load(Ordering::Relaxed)
    }
}

impl<'r, R, ID, T, E> Reducer<Result<T, E>> for TryReduceConsumer<'r, R, ID>
where
    R: Fn(T, T) -> Result<T, E> + Sync,
{
    fn reduce(self, left: Result<T, E>, right: Result<T, E>) -> Result<T, E> {
        match (left, right) {
            (Ok(left), Ok(right)) => (self.reduce_op)(left, right),
            (Err(r), _) | (_, Err(r)) => Err(r),
        }
    }
}

struct TryReduceFolder<'r, R, T, E> {
    reduce_op: &'r R,
    control: Result<T, E>,
    full: &'r AtomicBool,
}

impl<'r, R, T, E> Folder<Result<T, E>> for TryReduceFolder<'r, R, T, E>
where
    R: Fn(T, T) -> Result<T, E>,
{
    type Result = Result<T, E>;

    fn consume(mut self, item: Result<T, E>) -> Self {
        let reduce_op = self.reduce_op;
        self.control = match (self.control, item) {
            (Ok(left), Ok(right)) => reduce_op(left, right),
            (control @ Err(_), _) | (_, control @ Err(_)) => control,
        };
        if self.control.is_err() {
            self.full.store(true, Ordering::Relaxed);
        }
        self
    }

    fn complete(self) -> Result<T, E> {
        self.control
    }

    fn full(&self) -> bool {
        match self.control {
            Err(_) => true,
            _ => self.full.load(Ordering::Relaxed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rayon::{ThreadPool, ThreadPoolBuilder, current_thread_index, join};
    use commonware_utils::{sync::Mutex, test_rng};
    use rand::{Rng as _, RngExt as _};
    use std::{
        fmt,
        panic::{self, AssertUnwindSafe},
        sync::atomic::AtomicUsize,
        thread::{self, Result as ThreadResult},
        time::{Duration, Instant},
    };

    const LENGTHS: [usize; 6] = [0, 1, 2, 7, 1000, 100_000];

    fn pool(threads: usize) -> ThreadPool {
        ThreadPoolBuilder::new()
            .num_threads(threads)
            .build()
            .unwrap()
    }

    /// Runs `op` on a worker of a new pool of `threads` threads.
    fn in_pool<R: Send>(threads: usize, op: impl FnOnce() -> R + Send) -> R {
        pool(threads).install(op)
    }

    /// Waits until `condition` holds, failing after a bound so that a schedule that never gets
    /// there fails rather than hangs.
    fn wait_until(condition: impl Fn() -> bool) {
        let start = Instant::now();
        while !condition() {
            assert!(
                start.elapsed() < Duration::from_secs(10),
                "the other worker never got there"
            );
            thread::sleep(Duration::from_millis(1));
        }
    }

    /// Appends the items of `b` to `a`, a reduction that keeps the order of its items.
    fn append<T>(mut a: Vec<T>, b: Vec<T>) -> Vec<T> {
        a.extend(b);
        a
    }

    /// Counts, for each index of a test's items, the calls on the item, the drops of the item,
    /// and the outputs made from the item and their drops.
    struct Ledger {
        calls: Vec<AtomicUsize>,
        inputs: Vec<AtomicUsize>,
        created: Vec<AtomicUsize>,
        outputs: Vec<AtomicUsize>,
    }

    /// An item that counts its drop in a ledger.
    struct Input<'a> {
        index: usize,
        ledger: &'a Ledger,
    }

    impl Drop for Input<'_> {
        fn drop(&mut self) {
            self.ledger.inputs[self.index].fetch_add(1, Ordering::SeqCst);
        }
    }

    /// An output that counts its drop in a ledger.
    struct Output<'a> {
        index: usize,
        ledger: &'a Ledger,
    }

    impl Drop for Output<'_> {
        fn drop(&mut self) {
            self.ledger.outputs[self.index].fetch_add(1, Ordering::SeqCst);
        }
    }

    impl Ledger {
        fn new(len: usize) -> Self {
            let counters = || (0..len).map(|_| AtomicUsize::new(0)).collect();
            Self {
                calls: counters(),
                inputs: counters(),
                created: counters(),
                outputs: counters(),
            }
        }

        fn inputs(&self) -> Vec<Input<'_>> {
            (0..self.calls.len())
                .map(|index| Input {
                    index,
                    ledger: self,
                })
                .collect()
        }

        /// Records a call on `input` and returns its index.
        fn call(&self, input: &Input<'_>) -> usize {
            self.calls[input.index].fetch_add(1, Ordering::SeqCst);
            input.index
        }

        fn output(&self, index: usize) -> Output<'_> {
            self.created[index].fetch_add(1, Ordering::SeqCst);
            Output {
                index,
                ledger: self,
            }
        }

        /// Returns the indices of the items that were called on.
        fn called(&self) -> Vec<usize> {
            (0..self.calls.len())
                .filter(|&index| self.calls[index].load(Ordering::SeqCst) > 0)
                .collect()
        }

        /// Asserts that every item was called on at most once and dropped exactly once, and that
        /// every output made was dropped exactly once.
        fn assert_dropped_once(&self) {
            for index in 0..self.calls.len() {
                let calls = self.calls[index].load(Ordering::SeqCst);
                assert!(calls <= 1, "item {index} was called on {calls} times");
                let drops = self.inputs[index].load(Ordering::SeqCst);
                assert_eq!(drops, 1, "item {index} was dropped {drops} times");
                let created = self.created[index].load(Ordering::SeqCst);
                assert!(created <= calls, "item {index} made {created} outputs");
                let drops = self.outputs[index].load(Ordering::SeqCst);
                assert_eq!(drops, created, "output {index} was dropped {drops} times");
            }
        }
    }

    /// Maps keep the order of their items at every length and pool size.
    #[test]
    fn maps_keep_the_order_of_their_items() {
        let mut rng = test_rng();
        for threads in [1, 2, 4] {
            let pool = pool(threads);
            for len in LENGTHS {
                // Map random numbers to strings, so outputs own their memory
                let items: Vec<u64> = (0..len).map(|_| rng.next_u64()).collect();
                let expected: Vec<String> = items.iter().map(u64::to_string).collect();

                // Each operation returns the sequential result
                let mapped = pool.install(|| map_collect_vec(items.clone(), &|x| x.to_string()));
                assert_eq!(mapped, expected);
                let mapped = pool.install(|| {
                    map_init_collect_vec(items.clone(), &|| 0usize, &|seen, x| {
                        *seen += 1;
                        x.to_string()
                    })
                });
                assert_eq!(mapped, expected);
                let mapped = pool.install(|| {
                    try_map_collect_vec(items.clone(), &|x| Ok::<_, ()>(x.to_string()))
                });
                assert_eq!(mapped, Ok(expected));
            }
        }
    }

    /// Folds reduce their pieces in the order of their items, so a reduction that is associative
    /// but not commutative returns the sequential result.
    #[test]
    fn folds_reduce_in_the_order_of_their_items() {
        let mut rng = test_rng();
        let concat = |mut a: String, b: String| {
            a.push_str(&b);
            a
        };
        for threads in [1, 2, 4] {
            let pool = pool(threads);
            for len in LENGTHS {
                // Concatenate random words of one to three letters
                let items: Vec<String> = (0..len)
                    .map(|_| {
                        (0..rng.random_range(1..4))
                            .map(|_| char::from(b'a' + rng.random_range(0..26u8)))
                            .collect()
                    })
                    .collect();
                let expected = items.concat();

                // Each operation returns the sequential concatenation
                let folded = pool.install(|| {
                    fold_init(
                        items.clone(),
                        &|| 0usize,
                        &String::new,
                        &|mut acc, seen, item| {
                            *seen += 1;
                            acc.push_str(&item);
                            acc
                        },
                        &concat,
                    )
                });
                assert_eq!(folded, expected);
                let folded = pool.install(|| {
                    try_fold(
                        items.clone(),
                        &String::new,
                        &|mut acc, item| {
                            acc.push_str(&item);
                            Ok::<_, ()>(acc)
                        },
                        &concat,
                    )
                });
                assert_eq!(folded, Ok(expected));
            }
        }
    }

    /// On one thread the bridge splits once, each piece reduces its accumulator into an identity,
    /// and the pieces reduce left to right, so a reduction that records its grouping returns
    /// `((left)(right))`. A piece of fewer than two items is not split.
    #[test]
    fn reductions_follow_the_tree_of_splits() {
        let pool = pool(1);
        let group = |a: String, b: String| format!("({a}{b})");
        for len in [0, 1, 2, 7, 1000] {
            let items: Vec<String> = (0..len).map(|i| format!("{i},")).collect();
            let mid = len / 2;
            let (expected, pieces) = if len < 2 {
                (format!("({})", items.concat()), 1)
            } else {
                let (left, right) = items.split_at(mid);
                (format!("(({})({}))", left.concat(), right.concat()), 2)
            };

            // The fold creates one state per piece
            let states = AtomicUsize::new(0);
            let folded = pool.install(|| {
                fold_init(
                    items.clone(),
                    &|| states.fetch_add(1, Ordering::SeqCst),
                    &String::new,
                    &|mut acc, _, item| {
                        acc.push_str(&item);
                        acc
                    },
                    &group,
                )
            });
            assert_eq!(folded, expected);
            assert_eq!(states.load(Ordering::SeqCst), pieces);

            // The fallible fold groups its pieces the same way
            let folded = pool.install(|| {
                try_fold(
                    items.clone(),
                    &String::new,
                    &|mut acc, item| {
                        acc.push_str(&item);
                        Ok::<_, ()>(acc)
                    },
                    &group,
                )
            });
            assert_eq!(folded, Ok(expected));
        }
    }

    /// The halves a worker keeps halve their allowance of splits, while a half another worker
    /// steals splits again from the thread count.
    ///
    /// On two threads, the first worker splits the items into halves and its half into quarters,
    /// which it maps as two pieces. The second worker is held until the first finished a piece,
    /// then steals the second half, and the first worker holds its second piece until the second
    /// worker mapped that half, so neither worker steals from the other while it maps.
    #[test]
    fn a_stolen_half_splits_again() {
        const LEN: usize = 1024;

        // A piece records its worker and length when it finishes
        struct Piece<'a> {
            worker: usize,
            ordinal: usize,
            len: usize,
            finished: &'a [AtomicUsize; 2],
            pieces: &'a Mutex<Vec<(usize, usize)>>,
        }
        impl Drop for Piece<'_> {
            fn drop(&mut self) {
                self.pieces.lock().push((self.worker, self.len));
                self.finished[self.worker].fetch_add(1, Ordering::SeqCst);
            }
        }

        // Count the pieces each worker started and finished, and the items it mapped
        let started = [AtomicUsize::new(0), AtomicUsize::new(0)];
        let finished = [AtomicUsize::new(0), AtomicUsize::new(0)];
        let mapped = [AtomicUsize::new(0), AtomicUsize::new(0)];
        let pieces = Mutex::new(Vec::new());

        // Map on the first worker while its join holds the second
        let (first, outputs) = pool(2).install(|| {
            let first = current_thread_index().unwrap();
            let second = 1 - first;
            let (outputs, ()) = join(
                || {
                    map_init_collect_vec(
                        (0..LEN).collect(),
                        &|| {
                            let worker = current_thread_index().unwrap();
                            Piece {
                                worker,
                                ordinal: started[worker].fetch_add(1, Ordering::SeqCst),
                                len: 0,
                                finished: &finished,
                                pieces: &pieces,
                            }
                        },
                        &|piece, item| {
                            if piece.worker == first && piece.ordinal == 1 && piece.len == 0 {
                                wait_until(|| mapped[second].load(Ordering::SeqCst) == LEN / 2);
                            }
                            piece.len += 1;
                            mapped[piece.worker].fetch_add(1, Ordering::SeqCst);
                            item
                        },
                    )
                },
                || wait_until(|| finished[first].load(Ordering::SeqCst) >= 1),
            );
            (first, outputs)
        });

        // The outputs keep their order, the first worker mapped two quarters, and the second
        // split its half into eight pieces
        assert_eq!(outputs, (0..LEN).collect::<Vec<_>>());
        let pieces = pieces.into_inner();
        let lens = |worker| {
            pieces
                .iter()
                .filter(|&&(w, _)| w == worker)
                .map(|&(_, len)| len)
                .collect::<Vec<_>>()
        };
        assert_eq!(lens(first), [LEN / 4; 2]);
        assert_eq!(lens(1 - first), [LEN / 16; 8]);
    }

    /// On one thread, an error stops the first half at the failing item and skips the second
    /// half. On more threads, the error of one of several failing items is returned. Every item
    /// and every output is dropped exactly once.
    #[test]
    fn try_map_stops_at_an_error_and_drops_every_item_once() {
        const LEN: usize = 1000;
        for (threads, errors) in [(1, &[10][..]), (2, &[10, 500, 999]), (4, &[10, 500, 999])] {
            // Map every item to an output, or fail at the error indices
            let ledger = Ledger::new(LEN);
            let result = in_pool(threads, || {
                try_map_collect_vec(ledger.inputs(), &|input| {
                    let index = ledger.call(&input);
                    if errors.contains(&index) {
                        Err(index)
                    } else {
                        Ok(ledger.output(index))
                    }
                })
            });

            // The error is returned and every item and output dropped once
            let error = result.err().expect("an item failed");
            assert!(errors.contains(&error));
            if threads == 1 {
                assert_eq!(ledger.called(), (0..=10).collect::<Vec<_>>());
            }
            ledger.assert_dropped_once();
        }

        // Without an error, the outputs come back in order
        let ledger = Ledger::new(LEN);
        let outputs = in_pool(4, || {
            try_map_collect_vec(ledger.inputs(), &|input| {
                Ok::<_, ()>(ledger.output(ledger.call(&input)))
            })
        })
        .unwrap();
        assert!(outputs.iter().map(|output| output.index).eq(0..LEN));
        drop(outputs);
        ledger.assert_dropped_once();
    }

    /// A destructor panic releases the remaining outputs and the saved error exactly once.
    #[test]
    fn try_map_drops_every_item_when_an_output_drop_panics() {
        struct PanickingOutput<'a> {
            output: Output<'a>,
            panic_at: usize,
        }

        impl Drop for PanickingOutput<'_> {
            fn drop(&mut self) {
                assert_ne!(
                    self.output.index, self.panic_at,
                    "output index must differ from the panic index"
                );
            }
        }

        const LEN: usize = 16;
        for panic_at in [0, LEN / 2, LEN - 2] {
            let ledger = Ledger::new(LEN);
            let result = panic::catch_unwind(AssertUnwindSafe(|| {
                // A single worker fills both halves before the last item fails.
                in_pool(1, || {
                    let _ = try_map_collect_vec(ledger.inputs(), &|input| {
                        let index = ledger.call(&input);
                        if index == LEN - 1 {
                            Err(input)
                        } else {
                            Ok(PanickingOutput {
                                output: ledger.output(index),
                                panic_at,
                            })
                        }
                    });
                });
            }));

            assert_is_panic_with_message(&result, "output index must differ from the panic index");
            assert_eq!(ledger.called(), (0..LEN).collect::<Vec<_>>());
            ledger.assert_dropped_once();
        }
    }

    /// On one thread, an error stops the first half at the failing item and skips the second
    /// half. On more threads, the error of one of several failing items is returned. Every item,
    /// including the items the accumulators hold, is dropped exactly once.
    #[test]
    fn try_fold_stops_at_an_error_and_drops_every_item_once() {
        const LEN: usize = 1000;
        for (threads, errors) in [(1, &[10][..]), (2, &[10, 500, 999]), (4, &[10, 500, 999])] {
            // Collect every item into the accumulators, or fail at the error indices
            let ledger = Ledger::new(LEN);
            let result = in_pool(threads, || {
                try_fold(
                    ledger.inputs(),
                    &Vec::new,
                    &|mut acc, input| {
                        let index = ledger.call(&input);
                        if errors.contains(&index) {
                            return Err(index);
                        }
                        acc.push(input);
                        Ok(acc)
                    },
                    &append,
                )
            });

            // The error is returned and every item dropped once
            let error = result.err().expect("an item failed");
            assert!(errors.contains(&error));
            if threads == 1 {
                assert_eq!(ledger.called(), (0..=10).collect::<Vec<_>>());
            }
            ledger.assert_dropped_once();
        }

        // Without an error, the items come back in order
        let ledger = Ledger::new(LEN);
        let items = in_pool(4, || {
            try_fold(
                ledger.inputs(),
                &Vec::new,
                &|mut acc, input| {
                    ledger.call(&input);
                    acc.push(input);
                    Ok::<_, ()>(acc)
                },
                &append,
            )
        })
        .unwrap();
        assert!(items.iter().map(|input| input.index).eq(0..LEN));
        drop(items);
        ledger.assert_dropped_once();
    }

    /// A panic of a map on one item propagates to the caller of `install` once every other piece
    /// finished, and every item and every output is dropped exactly once. On one thread, the rest
    /// of the panicking half is skipped and the other half is mapped.
    #[test]
    fn a_panicking_map_drops_every_item_and_output_once() {
        const LEN: usize = 1000;
        type Map = for<'a> fn(&'a Ledger, Vec<Input<'a>>, usize);
        let maps: [Map; 3] = [
            |ledger, inputs, panic_at| {
                map_collect_vec(inputs, &|input| {
                    let index = ledger.call(&input);
                    assert_ne!(index, panic_at, "map panicked");
                    ledger.output(index)
                });
            },
            |ledger, inputs, panic_at| {
                map_init_collect_vec(inputs, &|| (), &|_, input| {
                    let index = ledger.call(&input);
                    assert_ne!(index, panic_at, "map panicked");
                    ledger.output(index)
                });
            },
            |ledger, inputs, panic_at| {
                let _ = try_map_collect_vec(inputs, &|input| {
                    let index = ledger.call(&input);
                    assert_ne!(index, panic_at, "map panicked");
                    Ok::<_, ()>(ledger.output(index))
                });
            },
        ];
        for map in maps {
            for threads in [1, 2, 4] {
                for panic_at in [0, 10, LEN / 2, LEN - 1] {
                    // Map on a pool and catch the panic its caller resumes
                    let ledger = Ledger::new(LEN);
                    let result = panic::catch_unwind(AssertUnwindSafe(|| {
                        in_pool(threads, || map(&ledger, ledger.inputs(), panic_at));
                    }));
                    assert_is_panic_with_message(&result, "map panicked");

                    // On one thread the other half was still mapped, and every item and output
                    // was dropped once
                    if threads == 1 && panic_at < LEN / 2 {
                        let expected: Vec<_> = (0..=panic_at).chain(LEN / 2..LEN).collect();
                        assert_eq!(ledger.called(), expected);
                    }
                    ledger.assert_dropped_once();
                }
            }
        }
    }

    /// A panic of a fold propagates to the caller of `install`, and every item, including the
    /// items the accumulators hold, is dropped exactly once.
    #[test]
    fn a_panicking_fold_drops_every_item_once() {
        const LEN: usize = 1000;
        for threads in [1, 2, 4] {
            for panic_at in [0, 10, LEN / 2, LEN - 1] {
                // Collect every item into the accumulators until one panics
                let ledger = Ledger::new(LEN);
                let result = panic::catch_unwind(AssertUnwindSafe(|| {
                    in_pool(threads, || {
                        fold_init(
                            ledger.inputs(),
                            &|| (),
                            &Vec::new,
                            &|mut acc, _, input| {
                                assert_ne!(ledger.call(&input), panic_at, "fold panicked");
                                acc.push(input);
                                acc
                            },
                            &append,
                        )
                    });
                }));
                assert_is_panic_with_message(&result, "fold panicked");
                ledger.assert_dropped_once();

                // The fallible fold drops its items the same way
                let ledger = Ledger::new(LEN);
                let result = panic::catch_unwind(AssertUnwindSafe(|| {
                    let _ = in_pool(threads, || {
                        try_fold(
                            ledger.inputs(),
                            &Vec::new,
                            &|mut acc, input| {
                                assert_ne!(ledger.call(&input), panic_at, "fold panicked");
                                acc.push(input);
                                Ok::<_, ()>(acc)
                            },
                            &append,
                        )
                    });
                }));
                assert_is_panic_with_message(&result, "fold panicked");
                ledger.assert_dropped_once();
            }
        }
    }

    /// Without a pool to split over, every operation refuses a caller outside every pool, and
    /// drops its items.
    #[test]
    fn operations_require_a_worker() {
        let operations: [fn(&Ledger); 5] = [
            |ledger| {
                map_collect_vec(ledger.inputs(), &|input| ledger.call(&input));
            },
            |ledger| {
                let _ =
                    try_map_collect_vec(ledger.inputs(), &|input| Ok::<_, ()>(ledger.call(&input)));
            },
            |ledger| {
                map_init_collect_vec(ledger.inputs(), &|| (), &|_, input| ledger.call(&input));
            },
            |ledger| {
                fold_init(
                    ledger.inputs(),
                    &|| (),
                    &|| 0,
                    &|acc, _, input| acc + ledger.call(&input),
                    &|a, b| a + b,
                );
            },
            |ledger| {
                let _ = try_fold(
                    ledger.inputs(),
                    &|| 0,
                    &|acc, input| Ok::<_, ()>(acc + ledger.call(&input)),
                    &|a, b| a + b,
                );
            },
        ];
        for operation in operations {
            // Each operation panics before calling on an item, and drops every item
            let ledger = Ledger::new(8);
            let result = panic::catch_unwind(AssertUnwindSafe(|| operation(&ledger)));
            assert_is_panic_with_message(
                &result,
                "the calling thread must be a worker of a thread pool",
            );
            assert!(ledger.called().is_empty());
            ledger.assert_dropped_once();
        }
    }

    #[test]
    fn execute() {
        let a: Vec<i32> = (0..1024).collect();
        let b = in_pool(4, || map_collect_vec(a, &|i| i + 1));
        let c: Vec<i32> = (0..1024).map(|i| i + 1).collect();
        assert_eq!(b, c);
    }

    #[test]
    fn check_move() {
        let a = vec![vec![1, 2, 3]];
        let ptr = a[0].as_ptr();

        let b = in_pool(4, || map_collect_vec(a, &|v| v));

        // a simple move means the inner vec will be completely unchanged
        assert_eq!(ptr, b[0].as_ptr());
    }

    #[test]
    fn check_drops() {
        #[derive(Clone)]
        struct DropCounter<'a>(&'a AtomicUsize);
        impl Drop for DropCounter<'_> {
            fn drop(&mut self) {
                self.0.fetch_add(1, Ordering::Relaxed);
            }
        }

        let c = AtomicUsize::new(0);
        let a = vec![DropCounter(&c); 10];

        let b = in_pool(4, || map_collect_vec(a.clone(), &|x| x));
        assert_eq!(c.load(Ordering::Relaxed), 0);

        // A producer drops the items it did not produce
        with_producer(b, |_| ());
        assert_eq!(c.load(Ordering::Relaxed), 10);

        // So do its halves and their iterators
        with_producer(a, |producer| {
            let (a, _) = producer.split_at(5);
            a.into_iter().next();
        });
        assert_eq!(c.load(Ordering::Relaxed), 20);
    }

    /// Stress-test indexes for `DrainProducer::split_at`.
    #[commonware_macros::test_group("miri")]
    #[test]
    fn drain_producer_split_at() {
        fn check_len<I: ExactSizeIterator>(iter: &I, len: usize) {
            assert_eq!(iter.size_hint(), (len, Some(len)));
            assert_eq!(iter.len(), len);
        }

        let v: Vec<_> = (0..10).collect();
        let end = v.len() + 1;
        for i in 0..end {
            for j in i..end {
                for k in j..end {
                    for reverse in [false, true] {
                        let result = with_producer(v.clone(), |producer| {
                            // Splitting the outer indexes first gets us an arbitrary mid section,
                            // which we then split further to get full test coverage.
                            let (left, d) = producer.split_at(k);
                            let (a, mid) = left.split_at(i);
                            let (b, c) = mid.split_at(j - i);

                            let a = a.into_iter();
                            let b = b.into_iter();
                            let c = c.into_iter();
                            let d = d.into_iter();

                            check_len(&a, i);
                            check_len(&b, j - i);
                            check_len(&c, k - j);

                            let chain = a.chain(b).chain(c).chain(d);
                            if reverse {
                                chain.rev().collect::<Vec<_>>()
                            } else {
                                chain.collect()
                            }
                        });
                        if reverse {
                            assert!(result.iter().eq(v.iter().rev()));
                        } else {
                            assert_eq!(result, v);
                        }
                    }
                }
            }
        }
    }

    /// A producer, its halves, and their iterators drop every item they did not produce.
    #[commonware_macros::test_group("miri")]
    #[test]
    fn drain_producer_drops_unproduced_items() {
        let items = || (0..10).map(|i| i.to_string()).collect::<Vec<_>>();

        // Dropping the producer drops every item
        with_producer(items(), |_| ());

        // Dropping a half and a partly consumed iterator drops the items they hold
        let produced = with_producer(items(), |producer| {
            let (left, right) = producer.split_at(4);
            let (_, mid) = right.split_at(3);
            let mut iter = mid.into_iter();
            let first = iter.next();
            let last = iter.next_back();
            drop(left);
            (first, last)
        });
        assert_eq!(produced, (Some("7".to_string()), Some("9".to_string())));
    }

    #[test]
    fn par_iter_collect_result() {
        in_pool(4, || {
            let a: Result<Vec<_>, ()> = (0_i32..2048).map(Ok).collect();
            let b: Result<Vec<_>, ()> = try_map_collect_vec((0_i32..2048).collect(), &Ok);
            assert_eq!(a, b);

            let c: Result<Vec<_>, _> = try_map_collect_vec((0_i32..2048).collect(), &|x| {
                if x == 1234 { Err(x) } else { Ok(x) }
            });
            assert_eq!(c, Err(1234));

            let d: Result<Vec<_>, _> = try_map_collect_vec((0_i32..2048).collect(), &|x| {
                if x % 100 == 99 { Err(x) } else { Ok(x) }
            });
            assert_eq!(d.map_err(|x| x % 100), Err(99));
        });
    }

    #[test]
    fn collect_drop_on_unwind() {
        struct Recorddrop<'a>(i64, &'a Mutex<Vec<i64>>);

        impl Drop for Recorddrop<'_> {
            fn drop(&mut self) {
                self.1.lock().push(self.0);
            }
        }

        let test_collect_panic = |will_panic: bool| {
            let test_vec_len = 1024;
            let panic_point = 740;

            let mut inserts = Mutex::new(Vec::new());
            let mut drops = Mutex::new(Vec::new());

            let a = (0..test_vec_len).collect::<Vec<_>>();
            let b = (0..test_vec_len).collect::<Vec<_>>();

            let _result = panic::catch_unwind(AssertUnwindSafe(|| {
                let pairs = a.iter().copied().zip(b.iter().copied()).collect();
                let result = in_pool(4, || {
                    map_collect_vec(pairs, &|(a, b)| {
                        if a > panic_point && will_panic {
                            panic!("unwinding for test");
                        }
                        let elt = a + b;
                        inserts.lock().push(elt);
                        Recorddrop(elt, &drops)
                    })
                });

                // If we reach this point, this must pass
                assert_eq!(a.len(), result.len());
            }));

            let inserts = inserts.get_mut();
            let drops = drops.get_mut();

            assert_eq!(inserts.len(), drops.len(), "Incorrect number of drops");
            // sort to normalize order
            inserts.sort();
            drops.sort();
            assert_eq!(inserts, drops, "Incorrect elements were dropped");
        };

        for &should_panic in &[true, false] {
            test_collect_panic(should_panic);
        }
    }

    #[test]
    fn collect_drop_on_unwind_zst() {
        static INSERTS: AtomicUsize = AtomicUsize::new(0);
        static DROPS: AtomicUsize = AtomicUsize::new(0);

        struct RecorddropZst;

        impl Drop for RecorddropZst {
            fn drop(&mut self) {
                DROPS.fetch_add(1, Ordering::SeqCst);
            }
        }

        let test_collect_panic = |will_panic: bool| {
            INSERTS.store(0, Ordering::SeqCst);
            DROPS.store(0, Ordering::SeqCst);

            let test_vec_len = 1024;
            let panic_point = 740;

            let a = (0..test_vec_len).collect::<Vec<_>>();

            let _result = panic::catch_unwind(AssertUnwindSafe(|| {
                let result = in_pool(4, || {
                    map_collect_vec(a.clone(), &|a| {
                        if a > panic_point && will_panic {
                            panic!("unwinding for test");
                        }
                        INSERTS.fetch_add(1, Ordering::SeqCst);
                        RecorddropZst
                    })
                });

                // If we reach this point, this must pass
                assert_eq!(a.len(), result.len());
            }));

            let inserts = INSERTS.load(Ordering::SeqCst);
            let drops = DROPS.load(Ordering::SeqCst);

            assert_eq!(inserts, drops, "Incorrect number of drops");
            assert!(will_panic || drops == test_vec_len)
        };

        for &should_panic in &[true, false] {
            test_collect_panic(should_panic);
        }
    }

    /// Promises to produce 2 items, but then produces 3.  Does not do any
    /// splits at all.
    #[commonware_macros::test_group("miri")]
    #[test]
    #[should_panic(expected = "too many values")]
    fn produce_too_many_items() {
        let mut v = vec![];
        collect_with_consumer(&mut v, 2, |consumer| {
            let _folder = consumer.into_folder().consume(22).consume(23).consume(24);
            unreachable!("folder does not complete")
        });
    }

    /// Produces fewer items than promised. Does not do any
    /// splits at all.
    #[commonware_macros::test_group("miri")]
    #[test]
    #[should_panic(expected = "expected 5 total writes, but got 2")]
    fn produce_fewer_items() {
        let mut v = vec![];
        collect_with_consumer(&mut v, 5, |consumer| {
            let mut folder = consumer.into_folder();
            folder = folder.consume(22);
            folder = folder.consume(23);
            folder.complete()
        });
    }

    // Complete is not called by the consumer. Hence, the collection vector is not fully initialized.
    #[commonware_macros::test_group("miri")]
    #[test]
    #[should_panic(expected = "expected 4 total writes, but got 2")]
    fn left_produces_items_with_no_complete() {
        let mut v = vec![];
        collect_with_consumer(&mut v, 4, |consumer| {
            let (left_consumer, right_consumer, _) = consumer.split_at(2);
            let _left_folder = left_consumer.into_folder().consume(0).consume(1);
            let mut right_folder = right_consumer.into_folder();
            right_folder = right_folder.consume(2).consume(3);
            right_folder.complete()
        });
    }

    // Complete is not called by the right consumer. Hence, the
    // collection vector is not fully initialized.
    #[commonware_macros::test_group("miri")]
    #[test]
    #[should_panic(expected = "expected 4 total writes, but got 2")]
    fn right_produces_items_with_no_complete() {
        let mut v = vec![];
        collect_with_consumer(&mut v, 4, |consumer| {
            let (left_consumer, right_consumer, _) = consumer.split_at(2);
            let mut left_folder = left_consumer.into_folder();
            let _right_folder = right_consumer.into_folder().consume(2).consume(3);
            left_folder = left_folder.consume(0).consume(1);
            left_folder.complete()
        });
    }

    // Complete is not called by the consumer. Hence, the collection vector is not fully initialized.
    #[commonware_macros::test_group("miri")]
    #[test]
    fn produces_items_with_no_complete() {
        let counter = DropCounter::default();
        let mut v = vec![];
        let panic_result = panic::catch_unwind(AssertUnwindSafe(|| {
            collect_with_consumer(&mut v, 2, |consumer| {
                let _folder = consumer
                    .into_folder()
                    .consume(counter.element())
                    .consume(counter.element());
                panic!("folder does not complete");
            });
        }));
        assert!(v.is_empty());
        assert_is_panic_with_message(&panic_result, "folder does not complete");
        counter.assert_drop_count();
    }

    // The left consumer produces too many items while the right
    // consumer produces correct number.
    #[commonware_macros::test_group("miri")]
    #[test]
    #[should_panic(expected = "too many values")]
    fn left_produces_too_many_items() {
        let mut v = vec![];
        collect_with_consumer(&mut v, 4, |consumer| {
            let (left_consumer, right_consumer, _) = consumer.split_at(2);
            let _left_folder = left_consumer.into_folder().consume(0).consume(1).consume(2);
            let _ = right_consumer
                .into_folder()
                .consume(2)
                .consume(3)
                .complete();
            unreachable!("folder does not complete");
        });
    }

    // The right consumer produces too many items while the left
    // consumer produces correct number.
    #[commonware_macros::test_group("miri")]
    #[test]
    #[should_panic(expected = "too many values")]
    fn right_produces_too_many_items() {
        let mut v = vec![];
        collect_with_consumer(&mut v, 4, |consumer| {
            let (left_consumer, right_consumer, _) = consumer.split_at(2);
            let left_folder = left_consumer.into_folder().consume(0).consume(1);
            let _right_folder = right_consumer
                .into_folder()
                .consume(2)
                .consume(3)
                .consume(4);
            let _ = left_folder.complete();
            unreachable!("folder does not complete");
        });
    }

    // The left consumer produces fewer items while the right
    // consumer produces correct number.
    #[commonware_macros::test_group("miri")]
    #[test]
    #[should_panic(expected = "expected 4 total writes, but got 1")]
    fn left_produces_fewer_items() {
        let mut v = vec![];
        collect_with_consumer(&mut v, 4, |consumer| {
            let (left_consumer, right_consumer, reducer) = consumer.split_at(2);
            let mut left_folder = left_consumer.into_folder();
            let mut right_folder = right_consumer.into_folder();
            left_folder = left_folder.consume(0);
            right_folder = right_folder.consume(2).consume(3);
            let left_result = left_folder.complete();
            let right_result = right_folder.complete();
            reducer.reduce(left_result, right_result)
        });
    }

    // The left and right consumer produce the correct number but
    // only left result is returned
    #[commonware_macros::test_group("miri")]
    #[test]
    #[should_panic(expected = "expected 4 total writes, but got 2")]
    fn only_left_result() {
        let mut v = vec![];
        collect_with_consumer(&mut v, 4, |consumer| {
            let (left_consumer, right_consumer, _) = consumer.split_at(2);
            let mut left_folder = left_consumer.into_folder();
            let mut right_folder = right_consumer.into_folder();
            left_folder = left_folder.consume(0).consume(1);
            right_folder = right_folder.consume(2).consume(3);
            let left_result = left_folder.complete();
            let _ = right_folder.complete();
            left_result
        });
    }

    // The left and right consumer produce the correct number but
    // only right result is returned
    #[commonware_macros::test_group("miri")]
    #[test]
    #[should_panic(expected = "expected 4 total writes, but got 2")]
    fn only_right_result() {
        let mut v = vec![];
        collect_with_consumer(&mut v, 4, |consumer| {
            let (left_consumer, right_consumer, _) = consumer.split_at(2);
            let mut left_folder = left_consumer.into_folder();
            let mut right_folder = right_consumer.into_folder();
            left_folder = left_folder.consume(0).consume(1);
            right_folder = right_folder.consume(2).consume(3);
            let _ = left_folder.complete();
            right_folder.complete()
        });
    }

    // The left and right consumer produce the correct number but reduce
    // in the wrong order.
    #[commonware_macros::test_group("miri")]
    #[test]
    #[should_panic(expected = "expected 4 total writes, but got 2")]
    fn reducer_does_not_preserve_order() {
        let mut v = vec![];
        collect_with_consumer(&mut v, 4, |consumer| {
            let (left_consumer, right_consumer, reducer) = consumer.split_at(2);
            let mut left_folder = left_consumer.into_folder();
            let mut right_folder = right_consumer.into_folder();
            left_folder = left_folder.consume(0).consume(1);
            right_folder = right_folder.consume(2).consume(3);
            let left_result = left_folder.complete();
            let right_result = right_folder.complete();
            reducer.reduce(right_result, left_result)
        });
    }

    // The right consumer produces fewer items while the left
    // consumer produces correct number.
    #[commonware_macros::test_group("miri")]
    #[test]
    #[should_panic(expected = "expected 4 total writes, but got 3")]
    fn right_produces_fewer_items() {
        let mut v = vec![];
        collect_with_consumer(&mut v, 4, |consumer| {
            let (left_consumer, right_consumer, reducer) = consumer.split_at(2);
            let mut left_folder = left_consumer.into_folder();
            let mut right_folder = right_consumer.into_folder();
            left_folder = left_folder.consume(0).consume(1);
            right_folder = right_folder.consume(2);
            let left_result = left_folder.complete();
            let right_result = right_folder.complete();
            reducer.reduce(left_result, right_result)
        });
    }

    // The left consumer panics and the right stops short, like `panic_fuse()`.
    // We should get the left panic without finishing `collect_with_consumer`.
    #[test]
    #[should_panic(expected = "left consumer panic")]
    fn left_panics() {
        in_pool(4, || {
            let mut v = vec![];
            collect_with_consumer(&mut v, 4, |consumer| {
                let (left_consumer, right_consumer, reducer) = consumer.split_at(2);
                let (left_result, right_result) = join(
                    || {
                        let _left_folder = left_consumer.into_folder().consume(0);
                        panic!("left consumer panic");
                    },
                    || {
                        let mut right_folder = right_consumer.into_folder();
                        right_folder = right_folder.consume(2);
                        right_folder.complete() // early return
                    },
                );
                reducer.reduce(left_result, right_result)
            });
            unreachable!();
        });
    }

    // The right consumer panics and the left stops short, like `panic_fuse()`.
    // We should get the right panic without finishing `collect_with_consumer`.
    #[test]
    #[should_panic(expected = "right consumer panic")]
    fn right_panics() {
        in_pool(4, || {
            let mut v = vec![];
            collect_with_consumer(&mut v, 4, |consumer| {
                let (left_consumer, right_consumer, reducer) = consumer.split_at(2);
                let (left_result, right_result) = join(
                    || {
                        let mut left_folder = left_consumer.into_folder();
                        left_folder = left_folder.consume(0);
                        left_folder.complete() // early return
                    },
                    || {
                        let _right_folder = right_consumer.into_folder().consume(2);
                        panic!("right consumer panic");
                    },
                );
                reducer.reduce(left_result, right_result)
            });
            unreachable!();
        });
    }

    // The left consumer produces fewer items while the right
    // consumer produces correct number. Check that created elements are dropped.
    #[commonware_macros::test_group("miri")]
    #[test]
    fn left_produces_fewer_items_drops() {
        let counter = DropCounter::default();
        let mut v = vec![];
        let panic_result = panic::catch_unwind(AssertUnwindSafe(|| {
            collect_with_consumer(&mut v, 4, |consumer| {
                let (left_consumer, right_consumer, reducer) = consumer.split_at(2);
                let mut left_folder = left_consumer.into_folder();
                let mut right_folder = right_consumer.into_folder();
                left_folder = left_folder.consume(counter.element());
                right_folder = right_folder
                    .consume(counter.element())
                    .consume(counter.element());
                let left_result = left_folder.complete();
                let right_result = right_folder.complete();
                reducer.reduce(left_result, right_result)
            });
        }));
        assert!(v.is_empty());
        assert_is_panic_with_message(&panic_result, "expected 4 total writes, but got 1");
        counter.assert_drop_count();
    }

    /// This counter can create elements, and then count and verify
    /// the number of which have actually been dropped again.
    #[derive(Default)]
    struct DropCounter {
        created: AtomicUsize,
        dropped: AtomicUsize,
    }

    struct Element<'a>(&'a AtomicUsize);

    impl DropCounter {
        fn created(&self) -> usize {
            self.created.load(Ordering::SeqCst)
        }

        fn dropped(&self) -> usize {
            self.dropped.load(Ordering::SeqCst)
        }

        fn element(&self) -> Element<'_> {
            self.created.fetch_add(1, Ordering::SeqCst);
            Element(&self.dropped)
        }

        fn assert_drop_count(&self) {
            assert_eq!(
                self.created(),
                self.dropped(),
                "Expected {} dropped elements, but found {}",
                self.created(),
                self.dropped()
            );
        }
    }

    impl Drop for Element<'_> {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// Assert that the result from catch_unwind is a panic that contains expected message
    fn assert_is_panic_with_message<T>(result: &ThreadResult<T>, expected: &str)
    where
        T: fmt::Debug,
    {
        match result {
            Ok(value) => {
                panic!("assertion failure: Expected panic, got successful {value:?}");
            }
            Err(error) => {
                let message_str = error.downcast_ref::<&'static str>().cloned();
                let message_string = error.downcast_ref::<String>().map(String::as_str);
                if let Some(message) = message_str.or(message_string) {
                    if !message.contains(expected) {
                        panic!(
                            "assertion failure: Expected {expected:?}, but found panic with {message:?}"
                        );
                    }
                // assertion passes
                } else {
                    panic!(
                        "assertion failure: Expected {expected:?}, but found panic with unknown value"
                    );
                }
            }
        }
    }
}
