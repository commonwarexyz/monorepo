use super::Aborter;
use commonware_utils::sync::Mutex;
use std::{
    mem,
    sync::{Arc, Weak},
};

/// Minimum length a node's child list reaches before [`Children::push`]
/// compacts it, so short lists batch their cleanup.
const COMPACTION_THRESHOLD: usize = 32;

/// A node in the supervision tree.
///
/// Each context holds its own node, and creating a child context creates a child
/// node. The context owns its node until a spawn hands the node to the task. A
/// node closes when its owner lets go: when the last [`Arc`] to it is dropped, or
/// when the task that occupies it ends. Closing a node aborts its task and every
/// node below it.
///
/// Parents only hold weak links to their children. Every open node is kept alive
/// by its owner, so a closing ancestor can always reach it.
pub(crate) struct Tree {
    inner: Mutex<TreeInner>,
}

/// Weak child pointers, compacted as the list grows.
struct Children {
    links: Vec<Weak<Tree>>,
    /// List length at which the next push first drops dead links.
    compact_at: usize,
}

impl Children {
    const fn new() -> Self {
        Self {
            links: Vec::new(),
            compact_at: COMPACTION_THRESHOLD,
        }
    }

    /// Appends a weak link to `child`. Once the list reaches `compact_at`, dead
    /// links are dropped first and the next compaction waits until the list has
    /// doubled again, so compaction costs amortized constant time per push.
    fn push(&mut self, child: &Arc<Tree>) {
        if self.links.len() >= self.compact_at {
            self.links.retain(|weak| weak.strong_count() > 0);
            self.compact_at = COMPACTION_THRESHOLD.max(self.links.len() * 2);
        }
        self.links.push(Arc::downgrade(child));
    }
}

/// The task, children and state of a node.
struct TreeInner {
    children: Children,
    task: Option<Aborter>,
    aborted: bool,
}

/// What a node held when it closed: its task and the links to its children.
type Closed = (Option<Aborter>, Vec<Weak<Tree>>);

impl TreeInner {
    const fn new(aborted: bool) -> Self {
        Self {
            children: Children::new(),
            task: None,
            aborted,
        }
    }

    fn register(&mut self, aborter: Aborter) -> Result<(), Aborter> {
        if self.aborted {
            return Err(aborter);
        }

        assert!(self.task.is_none(), "task already registered");
        self.task = Some(aborter);
        Ok(())
    }

    /// Marks the node aborted and takes what it held, unless it already closed.
    fn close(&mut self) -> Option<Closed> {
        if self.aborted {
            return None;
        }

        self.aborted = true;
        let task = self.task.take();
        let children = mem::take(&mut self.children.links);
        Some((task, children))
    }
}

impl Tree {
    /// Returns a new root node.
    pub(crate) fn root() -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(TreeInner::new(false)),
        })
    }

    /// Creates a new child node under `parent`, and returns whether it was born
    /// aborted because `parent` already closed.
    pub(crate) fn child(parent: &Arc<Self>) -> (Arc<Self>, bool) {
        let mut parent_inner = parent.inner.lock();
        let aborted = parent_inner.aborted;
        let child = Arc::new(Self {
            inner: Mutex::new(TreeInner::new(aborted)),
        });
        if !aborted {
            parent_inner.children.push(&child);
        }
        drop(parent_inner);

        (child, aborted)
    }

    /// Records an [Aborter] on the node.
    pub(crate) fn register(&self, aborter: Aborter) {
        let result = {
            let mut inner = self.inner.lock();
            inner.register(aborter)
        };

        // If the node closed before a task was registered, abort the task.
        if let Err(aborter) = result {
            aborter.abort();
        }
    }

    /// Aborts the task and all descendants rooted at this node.
    pub(crate) fn abort(&self) {
        let closed = self.inner.lock().close();
        Self::abort_closed(closed);
    }

    /// Aborts what a closed node held, then the rest of its subtree.
    fn abort_closed(closed: Option<Closed>) {
        let Some((task, children)) = closed else {
            return;
        };

        // Most nodes that close have no live children, so abort a lone task
        // without allocating.
        let mut pending: Vec<Arc<Self>> =
            children.into_iter().filter_map(|c| c.upgrade()).collect();
        if pending.is_empty() {
            if let Some(aborter) = task {
                aborter.abort();
            }
            return;
        }

        // Suspend every task in the subtree before aborting any of them. A
        // suspended task stops polling its future without ending, so a task in
        // the subtree can only observe another one's abort by this walk (a closed
        // channel, a handle resolving to closed) in a poll it started before it
        // was suspended. Tasks still see closed for other reasons, such as a
        // spawn under a node this walk already closed, or a descendant closing
        // concurrently and aborting what it reaches itself.
        // The walk is iterative so deep chains do not exhaust the thread stack.
        // Each node's list was drained when it closed, so every live descendant
        // is visited once.
        let mut suspended = Vec::new();
        if let Some(aborter) = task {
            aborter.suspend();
            suspended.push(aborter);
        }
        while let Some(node) = pending.pop() {
            let Some((task, children)) = node.inner.lock().close() else {
                continue;
            };
            if let Some(aborter) = task {
                aborter.suspend();
                suspended.push(aborter);
            }
            pending.extend(children.into_iter().filter_map(|child| child.upgrade()));
        }

        // Abort every suspended task even if a wake unwinds partway.
        let mut remaining = AbortRemaining(suspended.into_iter());
        for aborter in remaining.0.by_ref() {
            aborter.abort();
        }
    }
}

/// Aborts the tasks it still holds when dropped, so a wake that unwinds while a
/// closing subtree is aborted does not leave the rest suspended.
struct AbortRemaining(std::vec::IntoIter<Aborter>);

impl Drop for AbortRemaining {
    fn drop(&mut self) {
        for aborter in self.0.by_ref() {
            aborter.abort();
        }
    }
}

impl Drop for Tree {
    fn drop(&mut self) {
        // The owner let go of the node, which closes it.
        let closed = self.inner.get_mut().close();
        Self::abort_closed(closed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        telemetry::metrics::raw::Gauge,
        utils::{
            MetricHandle,
            abort::{AbortHandle, Abortable, Aborted},
        },
    };
    use futures::future::pending;

    fn aborter() -> (Aborter, Abortable<futures::future::Pending<()>>) {
        let gauge = Gauge::default();
        let metric = MetricHandle::new(gauge);
        let (handle, registration) = AbortHandle::new_pair();
        let aborter = Aborter::new(handle, metric);
        (aborter, Abortable::new(pending::<()>(), registration))
    }

    #[test]
    fn abort_cascades_to_children() {
        let root = Tree::root();
        let (parent, aborted) = Tree::child(&root);
        assert!(!aborted, "parent node unexpectedly aborted");

        // Register the parent task
        let (parent_aborter, parent_future) = aborter();
        parent.register(parent_aborter);

        // Create a child node
        let (child, aborted) = Tree::child(&parent);
        assert!(!aborted, "child node unexpectedly aborted");

        // Register the child task
        let (child_aborter, child_future) = aborter();
        child.register(child_aborter);

        // Abort the parent task
        parent.abort();

        // The parent and child tasks should abort
        assert!(parent_future.is_aborted(), "parent was not aborted");
        assert!(child_future.is_aborted(), "child was not aborted");
    }

    #[test]
    fn dropping_a_node_closes_its_subtree() {
        let root = Tree::root();
        let (parent, _) = Tree::child(&root);
        let (child, _) = Tree::child(&parent);
        let (aborter, future) = aborter();
        child.register(aborter);

        // Dropping the last handle to the parent closes it while the child is
        // still held, so the child's task is aborted and later children of the
        // child are born aborted.
        drop(parent);
        assert!(future.is_aborted(), "child task was not aborted");
        assert!(Tree::child(&child).1, "grandchild was not born aborted");
    }

    #[test]
    fn suspended_tasks_do_not_end_before_the_walk_suspends_every_task() {
        use futures::{FutureExt as _, future::ready, task::noop_waker};
        use std::{
            task::Poll,
            thread,
            time::{Duration, Instant},
        };

        // A component's run task, a node the test holds locked to pause the
        // walk, and work that would end as soon as it is polled. The walk
        // visits the newest child first.
        let scope = Tree::root();
        let (run, _) = Tree::child(&scope);
        let (gate, _) = Tree::child(&scope);
        let (work, _) = Tree::child(&scope);
        let task = |node: &Arc<Tree>| {
            let (handle, registration) = AbortHandle::new_pair();
            node.register(Aborter::new(
                handle.clone(),
                MetricHandle::new(Gauge::default()),
            ));
            (handle, Abortable::new(ready(()), registration))
        };
        let (run_handle, _run_task) = task(&run);
        let (work_handle, mut work_task) = task(&work);

        // Close the scope on another thread and pause the walk at the gate,
        // after it suspended the work.
        let paused = gate.inner.lock();
        let closer = thread::spawn(move || drop(scope));
        let start = Instant::now();
        while !work_handle.is_suspended() {
            assert!(start.elapsed() < Duration::from_secs(10), "walk stalled");
            thread::yield_now();
        }

        // The work does not end while the run task still runs.
        let waker = noop_waker();
        let mut cx = std::task::Context::from_waker(&waker);
        assert!(work_task.poll_unpin(&mut cx).is_pending());
        assert!(!run_handle.is_suspended() && !run_handle.is_aborted());

        // Once the walk suspended every task, it aborts them all.
        drop(paused);
        closer.join().unwrap();
        assert!(run_handle.is_aborted());
        assert_eq!(work_task.poll_unpin(&mut cx), Poll::Ready(Err(Aborted)));
        drop((run, gate, work));
    }

    #[test]
    fn a_wake_that_unwinds_leaves_no_task_suspended() {
        use futures::{
            FutureExt as _,
            task::{ArcWake, waker},
        };
        use std::panic::{AssertUnwindSafe, catch_unwind};

        struct Unwinds;

        impl ArcWake for Unwinds {
            fn wake_by_ref(_: &Arc<Self>) {
                panic!("wake unwound");
            }
        }

        // The walk aborts the newest child first, and waking its task unwinds.
        let scope = Tree::root();
        let (first, _) = Tree::child(&scope);
        let (second, _) = Tree::child(&scope);
        let (first_aborter, first_task) = aborter();
        first.register(first_aborter);
        let (second_aborter, mut second_task) = aborter();
        second.register(second_aborter);
        let waker = waker(Arc::new(Unwinds));
        let mut cx = std::task::Context::from_waker(&waker);
        assert!(second_task.poll_unpin(&mut cx).is_pending());

        assert!(catch_unwind(AssertUnwindSafe(|| drop(scope))).is_err());
        assert!(first_task.is_aborted(), "first task stayed suspended");
        drop((first, second));
    }

    #[test]
    fn idle_child_survives_descendant_abort() {
        let root = Tree::root();
        let (parent, aborted) = Tree::child(&root);
        assert!(!aborted, "parent node unexpectedly aborted");

        // Create a child node
        let (child1, aborted) = Tree::child(&parent);
        assert!(!aborted, "child1 node unexpectedly aborted");

        // Create a child node (sibling)
        let (child2, aborted) = Tree::child(&parent);
        assert!(!aborted, "child2 node unexpectedly aborted");

        // Register the child task
        let (child1_aborter, child1_future) = aborter();
        child1.register(child1_aborter);

        // Register the child task (sibling)
        let (child2_aborter, child2_future) = aborter();
        child2.register(child2_aborter);

        // Abort the child task (sibling)
        child2.abort();

        // The child task (sibling) should abort.
        assert!(child2_future.is_aborted(), "child2 was not aborted");

        // The child task should remain pending.
        assert!(
            !child1_future.is_aborted(),
            "child1 was aborted by descendant task"
        );
    }

    #[test]
    fn abort_deep_chain_without_stack_growth() {
        let depth = 50_000;
        let root = Tree::root();
        let mut nodes = Vec::with_capacity(depth);
        let mut futures = Vec::with_capacity(depth);

        // Build a single-chain supervision tree deep enough to overflow a
        // recursive abort implementation on typical stacks. Every node is kept
        // open by its handle in `nodes`.
        let mut current = root.clone();
        for _ in 0..depth {
            let (child, aborted) = Tree::child(&current);
            assert!(!aborted, "child node unexpectedly aborted");

            let (child_aborter, child_future) = aborter();
            child.register(child_aborter);
            futures.push(child_future);
            nodes.push(child.clone());
            current = child;
        }

        // Abort from the root and verify every registered descendant is still
        // reached by the iterative traversal.
        root.abort();

        for future in futures {
            assert!(future.is_aborted(), "descendant was not aborted");
        }

        // Dropping the chain from the top closes nodes that are already closed.
        drop(nodes);
    }

    #[test]
    fn child_list_compacts_dead_links_as_it_grows() {
        let root = Tree::root();

        // Fill the list to the threshold with children that are dropped at once.
        for _ in 0..COMPACTION_THRESHOLD {
            let (child, aborted) = Tree::child(&root);
            assert!(!aborted, "child node unexpectedly aborted");
            drop(child);
        }
        assert_eq!(root.inner.lock().children.links.len(), COMPACTION_THRESHOLD);

        // The next child compacts the dead links before it is appended.
        let (live, _) = Tree::child(&root);
        assert_eq!(root.inner.lock().children.links.len(), 1);

        // When every link is live, compaction keeps them all and the next one
        // waits until the list has doubled.
        let mut children: Vec<_> = (0..COMPACTION_THRESHOLD)
            .map(|_| Tree::child(&root).0)
            .collect();
        {
            let inner = root.inner.lock();
            assert_eq!(inner.children.links.len(), COMPACTION_THRESHOLD + 1);
            assert_eq!(inner.children.compact_at, COMPACTION_THRESHOLD * 2);
        }

        // Dead links accumulate until then, and the push that reaches it drops
        // every one of them.
        children.clear();
        while root.inner.lock().children.links.len() < COMPACTION_THRESHOLD * 2 {
            drop(Tree::child(&root).0);
        }
        let (last, _) = Tree::child(&root);
        assert_eq!(root.inner.lock().children.links.len(), 2);

        drop((live, last));
    }

    #[test]
    fn abort_wide_sibling_fanout_after_compaction() {
        let root = Tree::root();
        let (parent, aborted) = Tree::child(&root);
        assert!(!aborted, "parent node unexpectedly aborted");

        let mut live = Vec::new();
        let total = COMPACTION_THRESHOLD * 2;
        // Mix live and dropped siblings so the parent compacts dead links before
        // an abort cascade runs through the remaining subtree.
        for idx in 0..total {
            let (child, aborted) = Tree::child(&parent);
            assert!(!aborted, "child node unexpectedly aborted");

            let (aborter, future) = aborter();
            child.register(aborter);
            if idx % 3 == 0 {
                live.push((child, future));
            }
        }

        parent.abort();

        for (child, future) in live {
            assert!(future.is_aborted(), "live child was not aborted");
            drop(child);
        }
    }
}
