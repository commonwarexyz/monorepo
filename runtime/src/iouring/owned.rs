//! Every live ordinary task of a runner, retained so teardown can drop its
//! future. Root futures, including the tasks one-off workers run as their
//! roots, belong to their workers instead.
//!
//! [`Owned`] is a sharded intrusive list, as tokio's `OwnedTasks`. Each shard
//! is a mutex over a doubly linked list threaded through the task cells, whose
//! [`Links`] sit in a trailer after the future. Any thread inserts or removes a
//! task in constant time with only the task in hand, and the set allocates
//! nothing per task.
//!
//! A task's shard is the top bits of its cell address times a Fibonacci
//! hashing constant. Cells are cache-line aligned and the allocator places
//! them at regular strides, so the address bits alone, even shifted, would
//! reach only a few shards.
//!
//! The set holds one reference to each linked task, which removal or draining
//! hands back. Closing refuses further insertion and draining then hands out
//! every task left, so an open set retains every task it accepted until its
//! removal. Every task carries the identity of the set that retains it,
//! checked on insertion and removal, so a task routed to another runtime's set
//! panics instead of corrupting that set's lists.

use super::task::{Header, Task};
use crossbeam_utils::CachePadded;
use std::{cell::UnsafeCell, num::NonZeroU64, ptr::NonNull, sync::atomic::AtomicU64, thread};

cfg_if::cfg_if! {
    if #[cfg(feature = "loom")] {
        use loom::sync::{Mutex, MutexGuard, atomic::{AtomicBool, Ordering}};
    } else {
        use commonware_utils::sync::{Mutex, MutexGuard};
        use std::sync::atomic::{AtomicBool, Ordering};
    }
}

/// Fibonacci hashing multiplier, 2^64 divided by the golden ratio.
const MULTIPLIER: u64 = 0x9E37_79B9_7F4A_7C15;

/// Shards per worker, as in tokio.
const SHARDS_PER_WORKER: usize = 4;

/// Most shards, as in tokio.
const MAX_SHARDS: usize = 1 << 16;

/// A task's links in its shard's list, touched only under that shard's lock.
#[derive(Default)]
pub struct Links {
    /// Previous task, `None` at the head and while unlinked.
    prev: UnsafeCell<Option<NonNull<Header>>>,
    /// Next task, `None` at the tail and while unlinked.
    next: UnsafeCell<Option<NonNull<Header>>>,
}

/// One shard's list.
struct List {
    /// First task, `None` when the list is empty.
    head: Option<NonNull<Header>>,
}

// SAFETY: the list holds pointers to tasks, which are `Send`, and the shard's
// mutex serializes every access to it and to its tasks' links.
unsafe impl Send for List {}

impl List {
    /// Whether `node` is in this list. Only the head has no predecessor.
    ///
    /// # Safety
    ///
    /// `node` must point to a live task with the allocation's provenance whose
    /// shard is this one.
    unsafe fn contains(&self, node: NonNull<Header>) -> bool {
        // SAFETY: per the contract, and holding the list means holding the
        // shard's lock, which guards the links.
        let prev = unsafe { *Header::links(node).as_ref().prev.get() };
        prev.is_some() || self.head == Some(node)
    }

    /// Link `node` at the front.
    ///
    /// # Safety
    ///
    /// `node` must point to a live, unlinked task with the allocation's
    /// provenance whose shard is this one.
    unsafe fn push_front(&mut self, node: NonNull<Header>) {
        // SAFETY: per the contract. The old head is a linked task of this
        // shard, kept alive by the list's reference, and the shard's lock
        // guards both tasks' links.
        unsafe {
            let links = Header::links(node).as_ref();
            *links.prev.get() = None;
            *links.next.get() = self.head;
            if let Some(head) = self.head {
                *Header::links(head).as_ref().prev.get() = Some(node);
            }
        }
        self.head = Some(node);
    }

    /// Unlink `node`, returning whether it was linked.
    ///
    /// # Safety
    ///
    /// `node` must point to a live task with the allocation's provenance whose
    /// shard is this one.
    unsafe fn remove(&mut self, node: NonNull<Header>) -> bool {
        // SAFETY: per the contract.
        if !unsafe { self.contains(node) } {
            return false;
        }

        // SAFETY: per the contract. The neighbors are linked tasks of this
        // shard, kept alive by the list's references, and the shard's lock
        // guards every task's links.
        unsafe {
            let links = Header::links(node).as_ref();
            let prev = *links.prev.get();
            let next = *links.next.get();
            match prev {
                Some(prev) => *Header::links(prev).as_ref().next.get() = next,
                None => self.head = next,
            }
            if let Some(next) = next {
                *Header::links(next).as_ref().prev.get() = prev;
            }
            *links.prev.get() = None;
            *links.next.get() = None;
        }
        true
    }

    /// Unlink and return the front task.
    fn pop_front(&mut self) -> Option<NonNull<Header>> {
        let head = self.head?;

        // SAFETY: the head is a linked task of this shard, kept alive by the
        // list's reference.
        let removed = unsafe { self.remove(head) };
        assert!(removed, "list head was not linked");
        Some(head)
    }
}

/// Every live ordinary task of one runner, as a sharded intrusive list.
pub struct Owned {
    /// Lists by shard, each on its own cache line.
    shards: Box<[CachePadded<Mutex<List>>]>,
    /// Right shift that keeps the hash's top `log2(shards)` bits.
    shift: u32,
    /// Whether insertion is refused. Checked under the shard lock.
    closed: AtomicBool,
    /// Identity every task of this set carries.
    id: NonZeroU64,
}

impl Owned {
    /// A set sized for `workers` workers, with four shards per worker rounded
    /// up to a power of two, as tokio sizes its own.
    pub fn new(workers: usize) -> Self {
        // Clamped first, so rounding up cannot overflow.
        let workers = workers.min(MAX_SHARDS / SHARDS_PER_WORKER);
        Self::with_shards(workers.next_power_of_two() * SHARDS_PER_WORKER)
    }

    /// A set with `count` shards, a power of two.
    fn with_shards(count: usize) -> Self {
        assert!(
            count.is_power_of_two(),
            "shard count must be a power of two"
        );

        // Starting at one keeps every identity nonzero, as tokio's are.
        // Wrapping would take 2^64 sets.
        static NEXT_ID: AtomicU64 = AtomicU64::new(1);
        let id = NonZeroU64::new(NEXT_ID.fetch_add(1, Ordering::Relaxed))
            .expect("owned-task set identities exhausted");

        Self {
            shards: (0..count)
                .map(|_| CachePadded::new(Mutex::new(List { head: None })))
                .collect(),
            shift: u64::BITS - count.trailing_zeros(),
            closed: AtomicBool::new(false),
            id,
        }
    }

    /// Identity of this set, which tasks retained by it carry.
    pub const fn id(&self) -> NonZeroU64 {
        self.id
    }

    /// Shard of the task behind `node`.
    fn index(&self, node: NonNull<Header>) -> usize {
        let hash = (node.as_ptr().addr() as u64).wrapping_mul(MULTIPLIER);

        // One shard shifts by 64, which keeps no bits.
        hash.checked_shr(self.shift).unwrap_or(0) as usize
    }

    /// Lock one shard's list.
    fn lock(&self, index: usize) -> MutexGuard<'_, List> {
        cfg_if::cfg_if! {
            if #[cfg(feature = "loom")] {
                let list = self.shards[index].lock().unwrap();
            } else {
                let list = self.shards[index].lock();
            }
        }
        list
    }

    /// Retain `task`, counting a reference for the set. Returns false,
    /// retaining nothing, once the set is closed.
    pub fn insert(&self, task: &Task) -> bool {
        assert_eq!(task.owner(), self.id, "task belongs to another set");
        let node = task.as_ptr();
        let mut list = self.lock(self.index(node));

        // Checked under the lock, so a close that already drained this shard
        // refuses the task instead of leaving it behind.
        if self.closed.load(Ordering::Acquire) {
            return false;
        }

        // SAFETY: the caller's reference keeps the cell alive. The owner check
        // means no other set links the task, and its address names this shard.
        assert!(!unsafe { list.contains(node) }, "task inserted twice");

        // SAFETY: as above, and the task is unlinked.
        unsafe { list.push_front(node) };

        // The link carries this reference until removal or closure.
        let _ = Task::into_raw(task.clone());
        true
    }

    /// Release the set's reference to `task`. Returns `None` for a task a
    /// drain already handed out, and panics for a task an open set does not
    /// hold.
    pub fn remove(&self, task: &Task) -> Option<Task> {
        assert_eq!(task.owner(), self.id, "task belongs to another set");
        let node = task.as_ptr();
        let mut list = self.lock(self.index(node));

        // SAFETY: the caller's reference keeps the cell alive. The owner check
        // means no other set links the task, and its address names this shard.
        if !unsafe { list.remove(node) } {
            // Only a drain unlinks tasks besides removal, and it runs after
            // closing. Under this shard's lock, that close is visible.
            assert!(
                self.closed.load(Ordering::Acquire),
                "task missing from an open set"
            );
            return None;
        }

        // SAFETY: a linked task carried the set's reference.
        Some(unsafe { Task::from_raw(node) })
    }

    /// Refuse further insertion. Tasks already linked stay until a drain.
    pub fn close(&self) {
        self.closed.store(true, Ordering::Release);
    }

    /// Hand out every retained task, one shard lock per task, starting at
    /// shard `start` so workers draining at once spread over the shards. The
    /// caller clears each task before taking the next, with no lock held.
    ///
    /// The set must be closed. An insertion that locks a shard after the drain
    /// has reached it then observes the close and is refused, so no task is
    /// left behind.
    pub fn drain(&self, start: usize) -> Drain<'_> {
        assert!(
            self.closed.load(Ordering::Acquire),
            "set drained before closing"
        );
        let count = self.shards.len();
        Drain {
            owned: self,
            index: start % count,
            remaining: count,
        }
    }

    /// Close and drain the set, as teardown does.
    #[cfg(test)]
    pub fn teardown(&self) -> Vec<Task> {
        self.close();
        self.drain(0).collect()
    }

    /// Tasks linked in each shard.
    #[cfg(test)]
    pub fn lens(&self) -> Vec<usize> {
        (0..self.shards.len())
            .map(|index| {
                let list = self.lock(index);
                let mut len = 0;
                let mut node = list.head;
                while let Some(current) = node {
                    len += 1;
                    // SAFETY: linked tasks are alive, and the lock is held.
                    node = unsafe { *Header::links(current).as_ref().next.get() };
                }
                len
            })
            .collect()
    }

    /// Tasks linked in the set.
    #[cfg(test)]
    pub fn live(&self) -> usize {
        self.lens().into_iter().sum()
    }
}

/// Tasks handed out by [`Owned::drain`], one shard at a time.
pub struct Drain<'a> {
    /// The closed set being drained.
    owned: &'a Owned,
    /// Shard being drained.
    index: usize,
    /// Shards not yet found empty, including the current one.
    remaining: usize,
}

impl Iterator for Drain<'_> {
    type Item = Task;

    fn next(&mut self) -> Option<Task> {
        while self.remaining > 0 {
            // The guard drops here, so the caller clears the task unlocked.
            let node = self.owned.lock(self.index).pop_front();
            if let Some(node) = node {
                // SAFETY: a linked task carried the set's reference.
                return Some(unsafe { Task::from_raw(node) });
            }
            self.index = (self.index + 1) % self.owned.shards.len();
            self.remaining -= 1;
        }
        None
    }
}

impl Drop for Owned {
    fn drop(&mut self) {
        // A task still linked would leak with its future. The check is skipped
        // while unwinding, where a second panic would abort.
        if thread::panicking() {
            return;
        }
        for index in 0..self.shards.len() {
            assert!(
                self.lock(index).head.is_none(),
                "set dropped with live tasks"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{iouring::task::tests::refs, utils::extract_panic_message};
    use std::{
        future::pending,
        panic::{AssertUnwindSafe, catch_unwind},
        sync::{Arc, Barrier, Weak},
        thread,
        time::Duration,
    };

    /// A pending task retained by `owned`, with no worker.
    fn task(owned: &Owned) -> Task {
        Task::new(pending::<()>(), owned, Weak::new())
    }

    /// Drop a test task, clearing its future first.
    fn finish(task: Task) {
        task.clear();
        drop(task);
    }

    #[test]
    fn test_insert_then_remove_returns_the_reference_once() {
        let owned = Owned::new(4);
        let t = task(&owned);
        assert!(owned.insert(&t));
        assert_eq!(refs(&t), 2);

        let removed = owned.remove(&t).expect("linked task is removed");
        assert_eq!(removed.as_ptr(), t.as_ptr());
        drop(removed);
        assert_eq!(refs(&t), 1);
        assert_eq!(owned.live(), 0);

        // An open set holds every task it accepted until its removal, so a
        // second removal is a routing bug. Once closed, it finds nothing.
        let panic = catch_unwind(AssertUnwindSafe(|| drop(owned.remove(&t)))).unwrap_err();
        assert_eq!(
            extract_panic_message(&*panic),
            "task missing from an open set"
        );
        assert!(owned.teardown().is_empty());
        assert!(owned.remove(&t).is_none());
        finish(t);
    }

    #[test]
    fn test_remove_head_middle_and_tail_of_one_shard() {
        // One shard, so every task shares a list.
        let owned = Owned::with_shards(1);
        let tasks: Vec<Task> = (0..5).map(|_| task(&owned)).collect();
        for t in &tasks {
            assert!(owned.insert(t));
        }

        // The front is tasks[4]. Remove the middle, then the head, then the
        // tail.
        for index in [2, 4, 0] {
            assert!(owned.remove(&tasks[index]).is_some());
        }
        assert_eq!(owned.lens(), [2]);

        let rest: Vec<_> = owned.teardown().iter().map(Task::as_ptr).collect();
        assert_eq!(rest, [tasks[3].as_ptr(), tasks[1].as_ptr()]);
        for t in tasks {
            assert_eq!(refs(&t), 1);
            finish(t);
        }
    }

    #[test]
    fn test_close_refuses_insertion_and_drain_hands_out_everything() {
        let owned = Owned::new(4);
        let tasks: Vec<Task> = (0..100).map(|_| task(&owned)).collect();
        for t in &tasks {
            assert!(owned.insert(t));
        }

        // Closing keeps the linked tasks for the drain.
        owned.close();
        let late = task(&owned);
        assert!(!owned.insert(&late), "a closed set refuses insertion");
        assert_eq!(owned.live(), 100);
        assert_eq!(owned.drain(3).count(), 100);

        for t in tasks.iter().chain([&late]) {
            assert!(owned.remove(t).is_none(), "nothing left to remove");
            assert_eq!(refs(t), 1);
        }
        for t in tasks {
            finish(t);
        }
        finish(late);
    }

    #[test]
    fn test_drain_holds_no_lock_between_tasks() {
        // One shard, so every insertion below locks the shard being drained.
        let owned = Owned::with_shards(1);
        let tasks: Vec<Task> = (0..3).map(|_| task(&owned)).collect();
        for t in &tasks {
            assert!(owned.insert(t));
        }
        owned.close();

        // A destructor that spawns while teardown clears its task is refused
        // instead of deadlocking on the shard lock.
        let late = task(&owned);
        let mut drained = 0;
        for t in owned.drain(0) {
            assert!(!owned.insert(&late));
            drop(t);
            drained += 1;
        }
        assert_eq!(drained, 3);
        for t in tasks.into_iter().chain([late]) {
            finish(t);
        }
    }

    #[test]
    #[should_panic(expected = "task belongs to another set")]
    fn test_task_of_another_set_is_rejected() {
        let owner = Owned::new(1);
        let other = Owned::new(1);
        let t = task(&owner);
        t.clear();
        other.insert(&t);
    }

    #[test]
    fn test_second_insertion_is_rejected() {
        let owned = Owned::new(1);
        let t = task(&owned);
        assert!(owned.insert(&t));
        let panic = catch_unwind(AssertUnwindSafe(|| owned.insert(&t))).unwrap_err();
        assert_eq!(extract_panic_message(&*panic), "task inserted twice");

        // The first insertion's reference is still the only one retained.
        assert_eq!(refs(&t), 2);
        drop(owned.teardown());
        finish(t);
    }

    #[test]
    fn test_dropping_a_set_with_live_tasks_panics() {
        let owned = Owned::new(1);
        let t = task(&owned);
        assert!(owned.insert(&t));
        let panic = catch_unwind(AssertUnwindSafe(|| drop(owned))).unwrap_err();
        assert_eq!(
            extract_panic_message(&*panic),
            "set dropped with live tasks"
        );

        // SAFETY: the dropped set held one reference, which it leaked.
        drop(unsafe { Task::from_raw(t.as_ptr()) });
        finish(t);
    }

    #[test]
    fn test_hashed_shards_spread_cells() {
        let owned = Owned::new(16);
        cfg_if::cfg_if! {
            if #[cfg(miri)] {
                // Miri is slow, so fewer tasks per shard with a looser bound.
                let (count, slack) = (1024, 0.5);
            } else {
                let (count, slack) = (64 * 1024, 0.25);
            }
        }
        let tasks: Vec<Task> = (0..count).map(|_| task(&owned)).collect();
        for t in &tasks {
            assert!(owned.insert(t));
        }

        let lens = owned.lens();
        let mean = count as f64 / lens.len() as f64;
        let max = *lens.iter().max().unwrap() as f64;
        let min = *lens.iter().min().unwrap() as f64;
        assert!(
            max < mean * (1.0 + slack) && min > mean * (1.0 - slack),
            "uneven shards: {lens:?}"
        );
        drop(owned.teardown());
        for t in tasks {
            finish(t);
        }
    }

    /// Threads insert and remove while the set closes and drains. Every task
    /// is handed back exactly once, by its removal or by the drain, and every
    /// reference the set took is released.
    #[test]
    fn test_concurrent_insert_remove_and_close_return_each_task_once() {
        cfg_if::cfg_if! {
            if #[cfg(miri)] {
                // Miri is slow, so fewer rounds and tasks.
                let (rounds, per) = (2, 50);
            } else {
                let (rounds, per) = (50, 2000);
            }
        }
        let threads = 4;
        for round in 0..rounds {
            let owned = Arc::new(Owned::new(8));
            let tasks: Arc<Vec<Task>> =
                Arc::new((0..threads * per).map(|_| task(&owned)).collect());
            let barrier = Arc::new(Barrier::new(threads + 1));
            let workers: Vec<_> = (0..threads)
                .map(|t| {
                    let owned = owned.clone();
                    let tasks = tasks.clone();
                    let barrier = barrier.clone();
                    thread::spawn(move || {
                        barrier.wait();
                        let (mut inserted, mut removed) = (0, 0);
                        for i in 0..per {
                            let task = &tasks[t * per + i];
                            if !owned.insert(task) {
                                continue;
                            }
                            inserted += 1;

                            // Remove every other task right away.
                            if i % 2 == 0 && owned.remove(task).is_some() {
                                removed += 1;
                            }
                        }
                        (inserted, removed)
                    })
                })
                .collect();

            // Close part way through the insertions, then drain.
            barrier.wait();
            thread::sleep(Duration::from_micros(50 * (round % 5) as u64));
            owned.close();
            let drained_len = owned.drain(round).count();
            let (inserted, removed) = workers
                .into_iter()
                .map(|w| w.join().unwrap())
                .fold((0, 0), |(i, r), (wi, wr)| (i + wi, r + wr));

            // Anything inserted after the close was refused, so the set now
            // holds nothing, and every inserted task came back once.
            assert_eq!(owned.live(), 0);
            assert_eq!(drained_len + removed, inserted, "round {round}");
            for task in tasks.iter() {
                assert_eq!(refs(task), 1, "round {round}: a reference leaked");
            }
            for task in Arc::try_unwrap(tasks).ok().unwrap() {
                finish(task);
            }
        }
    }
}

#[cfg(all(test, feature = "loom"))]
mod loom_tests {
    use super::*;
    use crate::iouring::task::tests::refs;
    use loom::{sync::Arc, thread};
    use std::{future::pending, sync::Weak};

    /// Insertion, removal, and closure with its drain race on neighbors in
    /// one shard. Each inserted task comes back exactly once, by its removal
    /// or by the drain, and a task refused after the close is not retained.
    #[test]
    fn test_insert_remove_and_close_race_in_one_shard() {
        loom::model(|| {
            let owned = Arc::new(Owned::with_shards(1));
            let tasks: Arc<[Task; 3]> =
                Arc::new([(); 3].map(|_| Task::new(pending::<()>(), &owned, Weak::new())));
            assert!(owned.insert(&tasks[0]));
            assert!(owned.insert(&tasks[1]));

            // Unlink the middle neighbor while another thread links a third
            // task at the front and the main thread closes and drains the set.
            let remover = thread::spawn({
                let owned = owned.clone();
                let tasks = tasks.clone();
                move || owned.remove(&tasks[0]).is_some()
            });
            let inserter = thread::spawn({
                let owned = owned.clone();
                let tasks = tasks.clone();
                move || owned.insert(&tasks[2])
            });
            owned.close();
            let drained: Vec<_> = owned.drain(0).map(|t| t.as_ptr()).collect();
            let removed = remover.join().unwrap();
            let inserted = inserter.join().unwrap();

            // Every inserted task is handed back once, and nothing remains.
            let returned = |t: &Task| drained.contains(&t.as_ptr());
            assert_ne!(removed, returned(&tasks[0]));
            assert!(returned(&tasks[1]));
            assert_eq!(inserted, returned(&tasks[2]));
            assert_eq!(owned.live(), 0);
            for t in tasks.iter() {
                assert_eq!(refs(t), 1);
                t.clear();
            }
        });
    }
}
