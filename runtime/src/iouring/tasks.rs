//! Every live ordinary task of a runner, retained so teardown can drop its
//! future. Root futures, including the tasks one-off workers run as their
//! roots, belong to their workers instead.
//!
//! [`Tasks`] is a sharded intrusive list, as tokio's `OwnedTasks`. Each shard
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
//! [`Tasks::register`] allocates each task for its set and retains it before
//! the first token reaches a worker, so no token exists before the set retains
//! its task. The set holds one reference to each linked task, which removal or
//! draining hands back. Only removal and a drain unlink a task, and a drain
//! requires a closed set, so an open set retains every task it accepted until
//! its removal. Every task carries the identity of the set that retains it,
//! checked on insertion and removal, so a task routed to another runtime's set
//! panics instead of corrupting that set's lists.

use super::{
    mailbox::Mailbox,
    task::{Header, Task},
};
use commonware_utils::GOLDEN_RATIO;
use crossbeam_utils::CachePadded;
use std::{
    cell::UnsafeCell,
    future::Future,
    num::NonZeroU64,
    ptr::NonNull,
    sync::{Weak, atomic::AtomicU64},
    thread,
};

cfg_if::cfg_if! {
    if #[cfg(feature = "loom")] {
        use loom::sync::{Mutex, MutexGuard, atomic::{AtomicBool, Ordering}};
    } else {
        use commonware_utils::sync::{Mutex, MutexGuard};
        use std::sync::atomic::{AtomicBool, Ordering};
    }
}

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

        // SAFETY: per the contract, and `node` is linked here.
        unsafe { self.unlink(node) };
        true
    }

    /// Unlink `node`.
    ///
    /// # Safety
    ///
    /// `node` must point to a live task with the allocation's provenance that
    /// is linked in this list.
    unsafe fn unlink(&mut self, node: NonNull<Header>) {
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
    }

    /// Unlink and return the front task.
    fn pop_front(&mut self) -> Option<NonNull<Header>> {
        let head = self.head?;

        // SAFETY: the head is a linked task of this shard, kept alive by the
        // list's reference.
        unsafe { self.unlink(head) };
        Some(head)
    }
}

/// Every live ordinary task of one runner, as a sharded intrusive list.
pub struct Tasks {
    /// Lists by shard, each on its own cache line.
    shards: Box<[CachePadded<Mutex<List>>]>,
    /// Right shift that keeps the hash's top `log2(shards)` bits.
    shift: u32,
    /// Whether insertion is refused. Checked under the shard lock.
    closed: AtomicBool,
    /// Identity every task of this set carries.
    id: NonZeroU64,
}

impl Tasks {
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
            .expect("task set identities exhausted");

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
        let hash = (node.as_ptr().addr() as u64).wrapping_mul(GOLDEN_RATIO);

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

    /// Whether the set refuses insertion.
    ///
    /// This does not reserve a place. Registration checks again after the
    /// task's factory runs.
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    /// Allocate a task for this set, owned by the worker behind `mailbox`,
    /// retain it, then deliver its first poll's token to that worker directly
    /// or through its mailbox.
    ///
    /// Returns the new task if the set has closed. The caller clears its
    /// future outside worker borrows.
    pub fn register<F>(&self, future: F, mailbox: Weak<Mailbox>) -> Result<(), Task>
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let task = Task::new(future, self, mailbox);

        // The factory runs after the spawn's open check, so the set checks
        // closure again. Insertion precedes delivery, so a token the mailbox
        // refuses belongs to a task teardown clears.
        if !self.insert(&task) {
            return Err(task);
        }

        #[cfg(test)]
        tests::after_insert();

        task.schedule();
        Ok(())
    }

    /// Retain `task`, counting a reference for the set. Returns false,
    /// retaining nothing, once the set is closed.
    pub fn insert(&self, task: &Task) -> bool {
        assert_eq!(task.owner(), self.id, "task belongs to another runtime");
        let node = task.as_ptr();
        let mut list = self.lock(self.index(node));

        // Checked under the lock, so a close that already drained this shard
        // refuses the task instead of leaving it behind.
        if self.is_closed() {
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
    /// closed set does not hold, and panics for a task an open set does not
    /// hold.
    pub fn remove(&self, task: &Task) -> Option<Task> {
        assert_eq!(task.owner(), self.id, "task belongs to another runtime");
        let node = task.as_ptr();
        let mut list = self.lock(self.index(node));

        // SAFETY: the caller's reference keeps the cell alive. The owner check
        // means no other set links the task, and its address names this shard.
        if !unsafe { list.remove(node) } {
            // Only a drain unlinks tasks besides removal, and it runs after
            // closing. Under this shard's lock, that close is visible.
            assert!(self.is_closed(), "task missing from an open set");
            return None;
        }

        // SAFETY: a linked task carried the set's reference.
        Some(unsafe { Task::from_raw(node) })
    }

    /// Refuse further insertion. Linked tasks stay until their removal or a
    /// drain.
    pub fn close(&self) {
        self.closed.store(true, Ordering::Release);
    }

    /// Hand out every retained task, one shard lock per task. The caller
    /// clears each task before taking the next, with no lock held.
    ///
    /// The set must be closed. An insertion that locks a shard after the drain
    /// has reached it then observes the close and is refused, so no task is
    /// left behind.
    pub fn drain(&self) -> Drain<'_> {
        assert!(self.is_closed(), "set drained before closing");
        Drain {
            tasks: self,
            index: 0,
        }
    }

    /// Close and drain the set, as teardown does.
    #[cfg(test)]
    pub fn teardown(&self) -> Vec<Task> {
        self.close();
        self.drain().collect()
    }

    /// Lock one shard's list if no other guard holds it.
    #[cfg(test)]
    fn try_lock(&self, index: usize) -> Option<MutexGuard<'_, List>> {
        cfg_if::cfg_if! {
            if #[cfg(feature = "loom")] {
                self.shards[index].try_lock().ok()
            } else {
                self.shards[index].try_lock()
            }
        }
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

/// Tasks handed out by [`Tasks::drain`], one shard at a time.
pub struct Drain<'a> {
    /// The closed set being drained.
    tasks: &'a Tasks,
    /// Shard being drained.
    index: usize,
}

impl Iterator for Drain<'_> {
    type Item = Task;

    fn next(&mut self) -> Option<Task> {
        while self.index < self.tasks.shards.len() {
            // The guard drops here, so the caller clears the task unlocked.
            let node = self.tasks.lock(self.index).pop_front();
            if let Some(node) = node {
                // SAFETY: a linked task carried the set's reference.
                return Some(unsafe { Task::from_raw(node) });
            }
            self.index += 1;
        }
        None
    }
}

impl Drop for Tasks {
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
pub mod tests {
    use super::*;
    use crate::{iouring::task::tests::refs, utils::extract_panic_message};
    use std::{
        cell::RefCell,
        future::pending,
        panic::{AssertUnwindSafe, catch_unwind},
        sync::{Arc, Barrier, Weak},
        thread,
    };

    thread_local! {
        /// Callback run once by this thread's next registration, after the set
        /// retains the task and before its first token is delivered.
        pub static AFTER_INSERT: RefCell<Option<Box<dyn FnOnce()>>> = const { RefCell::new(None) };
    }

    /// Run the callback a test installed for the window between retention and
    /// first-token delivery.
    pub fn after_insert() {
        // A spawn from a TLS destructor can run after this key is destroyed.
        if let Some(callback) = AFTER_INSERT.try_with(RefCell::take).ok().flatten() {
            callback();
        }
    }

    /// A pending task for `set` to retain, with no worker.
    fn task(set: &Tasks) -> Task {
        Task::new(pending::<()>(), set, Weak::new())
    }

    /// Drop a test task, clearing its future first.
    fn finish(task: Task) {
        task.clear();
        drop(task);
    }

    /// Insertion counts the set's reference, and removal hands it back once.
    #[test]
    fn test_insert_then_remove_returns_the_reference_once() {
        let set = Tasks::new(4);
        let t = task(&set);
        assert!(set.insert(&t));
        assert_eq!(refs(&t), 2);

        let removed = set.remove(&t).expect("linked task is removed");
        assert_eq!(removed.as_ptr(), t.as_ptr());
        drop(removed);
        assert_eq!(refs(&t), 1);
        assert_eq!(set.live(), 0);

        // An open set holds every task it accepted until its removal, so a
        // second removal is a routing bug. Once closed, it finds nothing.
        let panic = catch_unwind(AssertUnwindSafe(|| drop(set.remove(&t)))).unwrap_err();
        assert_eq!(
            extract_panic_message(&*panic),
            "task missing from an open set"
        );
        assert!(set.teardown().is_empty());
        assert!(set.remove(&t).is_none());
        finish(t);
    }

    /// Removal relinks the neighbors of a head, middle, or tail task.
    #[test]
    fn test_remove_head_middle_and_tail_of_one_shard() {
        // One shard, so every task shares a list.
        let set = Tasks::with_shards(1);
        let tasks: Vec<Task> = (0..5).map(|_| task(&set)).collect();
        for t in &tasks {
            assert!(set.insert(t));
        }

        // The front is tasks[4]. Remove the middle, then the head, then the
        // tail.
        for index in [2, 4, 0] {
            assert!(set.remove(&tasks[index]).is_some());
        }
        assert_eq!(set.lens(), [2]);

        let rest: Vec<_> = set.teardown().iter().map(Task::as_ptr).collect();
        assert_eq!(rest, [tasks[3].as_ptr(), tasks[1].as_ptr()]);
        for t in tasks {
            assert_eq!(refs(&t), 1);
            finish(t);
        }
    }

    /// A closed set refuses insertion, and its drain hands out every linked
    /// task across the shards.
    #[test]
    fn test_close_refuses_insertion_and_drain_hands_out_everything() {
        let set = Tasks::new(4);
        let tasks: Vec<Task> = (0..100).map(|_| task(&set)).collect();
        for t in &tasks {
            assert!(set.insert(t));
        }

        // Closing keeps the linked tasks for the drain.
        set.close();
        let late = task(&set);
        assert!(!set.insert(&late), "a closed set refuses insertion");
        assert_eq!(set.live(), 100);
        assert_eq!(set.drain().count(), 100);

        for t in tasks.iter().chain([&late]) {
            assert!(set.remove(t).is_none(), "nothing left to remove");
            assert_eq!(refs(t), 1);
        }
        for t in tasks {
            finish(t);
        }
        finish(late);
    }

    /// A drain releases the shard lock before it hands out each task.
    #[test]
    fn test_drain_holds_no_lock_between_tasks() {
        // One shard, so every insertion below locks the shard being drained.
        let set = Tasks::with_shards(1);
        let tasks: Vec<Task> = (0..3).map(|_| task(&set)).collect();
        for t in &tasks {
            assert!(set.insert(t));
        }
        set.close();

        // The shard is free while the caller holds a drained task, so a
        // destructor that spawns while teardown clears its task is refused
        // instead of deadlocking on the shard lock.
        let late = task(&set);
        let mut drained = 0;
        for t in set.drain() {
            assert!(set.try_lock(0).is_some(), "drain held the shard lock");
            assert!(!set.insert(&late));
            drop(t);
            drained += 1;
        }
        assert_eq!(drained, 3);
        for t in tasks.into_iter().chain([late]) {
            finish(t);
        }
    }

    /// Another set refuses to insert or remove a task, so its lists stay
    /// intact.
    #[test]
    fn test_task_of_another_set_is_rejected() {
        let owner = Tasks::new(1);
        let other = Tasks::new(1);
        let t = task(&owner);
        t.clear();

        // Insertion into another set panics before it links anything.
        let panic = catch_unwind(AssertUnwindSafe(|| other.insert(&t))).unwrap_err();
        assert!(extract_panic_message(&*panic).contains("task belongs to another runtime"));

        // Removal from another set panics before it unlinks anything, and the
        // owner still holds the task.
        assert!(owner.insert(&t));
        let panic = catch_unwind(AssertUnwindSafe(|| drop(other.remove(&t)))).unwrap_err();
        assert!(extract_panic_message(&*panic).contains("task belongs to another runtime"));
        assert_eq!(owner.teardown().len(), 1);
        assert_eq!(refs(&t), 1);
    }

    /// Draining requires a closed set.
    #[test]
    #[should_panic(expected = "set drained before closing")]
    fn test_drain_of_an_open_set_is_rejected() {
        let _ = Tasks::new(1).drain();
    }

    /// A task already linked is not linked again.
    #[test]
    fn test_second_insertion_is_rejected() {
        let set = Tasks::new(1);
        let t = task(&set);
        assert!(set.insert(&t));
        let panic = catch_unwind(AssertUnwindSafe(|| set.insert(&t))).unwrap_err();
        assert_eq!(extract_panic_message(&*panic), "task inserted twice");

        // The first insertion's reference is still the only one retained.
        assert_eq!(refs(&t), 2);
        drop(set.teardown());
        finish(t);
    }

    /// Dropping a set that still links a task panics, unless the thread is
    /// already unwinding, where a second panic would abort.
    #[test]
    fn test_dropping_a_set_with_live_tasks_panics() {
        let set = Tasks::new(1);
        let t = task(&set);
        assert!(set.insert(&t));
        let panic = catch_unwind(AssertUnwindSafe(|| drop(set))).unwrap_err();
        assert_eq!(
            extract_panic_message(&*panic),
            "set dropped with live tasks"
        );

        // SAFETY: the dropped set held one reference, which it leaked.
        drop(unsafe { Task::from_raw(t.as_ptr()) });

        // A set dropped while unwinding skips the check, so the original
        // panic survives.
        let set = Tasks::new(1);
        let u = task(&set);
        assert!(set.insert(&u));
        let panic = catch_unwind(AssertUnwindSafe(|| {
            let _set = set;
            panic!("original panic");
        }))
        .unwrap_err();
        assert_eq!(extract_panic_message(&*panic), "original panic");

        // SAFETY: as above.
        drop(unsafe { Task::from_raw(u.as_ptr()) });
        finish(t);
        finish(u);
    }

    /// Addresses at regular strides, as an allocator places cells, spread
    /// evenly over the shards. The addresses are synthetic, so the result
    /// does not depend on the allocator and is the same on every run.
    #[test]
    fn test_hash_spreads_strided_addresses() {
        let set = Tasks::new(16);
        let shards = set.shards.len();
        let per_shard = 256;
        for stride in [64, 128, 144, 192, 256, 384, 512, 4096] {
            let mut lens = vec![0_usize; shards];
            for i in 0..shards * per_shard {
                // Never dereferenced, so the pointer needs no provenance.
                let addr = 0x7f00_0000_0000 + i * stride;
                let node = NonNull::new(std::ptr::without_provenance_mut(addr)).unwrap();
                lens[set.index(node)] += 1;
            }
            assert!(
                lens.iter()
                    .all(|&len| len.abs_diff(per_shard) <= per_shard / 8),
                "uneven shards at stride {stride}: {lens:?}"
            );
        }
    }

    /// Cells from the real allocator spread evenly over the shards. Miri
    /// places allocations at random addresses instead of the allocator's
    /// strides, so this runs natively only.
    #[cfg(not(miri))]
    #[test]
    fn test_hashed_shards_spread_cells() {
        let set = Tasks::new(16);
        let count = 64 * 1024;
        let tasks: Vec<Task> = (0..count).map(|_| task(&set)).collect();
        for t in &tasks {
            assert!(set.insert(t));
        }

        let lens = set.lens();
        let mean = count as f64 / lens.len() as f64;
        let max = *lens.iter().max().unwrap() as f64;
        let min = *lens.iter().min().unwrap() as f64;
        assert!(
            max < mean * 1.25 && min > mean * 0.75,
            "uneven shards: {lens:?}"
        );
        drop(set.teardown());
        for t in tasks {
            finish(t);
        }
    }

    /// Threads insert and remove tasks in shared shards at once, then the set
    /// closes and drains. Every task is handed back exactly once, by its
    /// removal or by the drain, and every reference the set took is released.
    #[test]
    fn test_concurrent_insert_and_remove_return_each_task_once() {
        cfg_if::cfg_if! {
            if #[cfg(miri)] {
                // Miri is slow, so fewer tasks.
                let per = 50;
            } else {
                let per = 2000;
            }
        }
        let threads = 4;
        let set = Arc::new(Tasks::new(1));
        let tasks: Arc<Vec<Task>> = Arc::new((0..threads * per).map(|_| task(&set)).collect());

        // Each thread inserts its tasks and removes every other one right
        // away, writing links in the shards the other threads write.
        let barrier = Arc::new(Barrier::new(threads));
        let workers: Vec<_> = (0..threads)
            .map(|t| {
                let set = set.clone();
                let tasks = tasks.clone();
                let barrier = barrier.clone();
                thread::spawn(move || {
                    barrier.wait();
                    for (i, task) in tasks[t * per..(t + 1) * per].iter().enumerate() {
                        assert!(set.insert(task));
                        if i % 2 == 0 {
                            assert!(set.remove(task).is_some());
                        }
                    }
                })
            })
            .collect();
        for worker in workers {
            worker.join().unwrap();
        }

        // The drain hands back exactly the tasks no thread removed, and the
        // set keeps no reference.
        assert_eq!(set.live(), threads * per / 2);
        assert_eq!(set.teardown().len(), threads * per / 2);
        for task in Arc::try_unwrap(tasks).ok().unwrap() {
            assert_eq!(refs(&task), 1);
            finish(task);
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
            let set = Arc::new(Tasks::with_shards(1));
            let tasks: Arc<[Task; 3]> =
                Arc::new([(); 3].map(|_| Task::new(pending::<()>(), &set, Weak::new())));
            assert!(set.insert(&tasks[0]));
            assert!(set.insert(&tasks[1]));

            // Unlink the tail while another thread links a third task at the
            // front and the main thread closes and drains the set.
            let remover = thread::spawn({
                let set = set.clone();
                let tasks = tasks.clone();
                move || set.remove(&tasks[0]).is_some()
            });
            let inserter = thread::spawn({
                let set = set.clone();
                let tasks = tasks.clone();
                move || set.insert(&tasks[2])
            });
            set.close();
            let drained: Vec<_> = set.drain().map(|t| t.as_ptr()).collect();
            let removed = remover.join().unwrap();
            let inserted = inserter.join().unwrap();

            // Every inserted task is handed back once, and nothing remains.
            let returned = |t: &Task| drained.contains(&t.as_ptr());
            assert_ne!(removed, returned(&tasks[0]));
            assert!(returned(&tasks[1]));
            assert_eq!(inserted, returned(&tasks[2]));
            assert_eq!(set.live(), 0);
            for t in tasks.iter() {
                assert_eq!(refs(t), 1);
                t.clear();
            }
        });
    }
}
