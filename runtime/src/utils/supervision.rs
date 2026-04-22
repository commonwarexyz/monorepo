use super::Aborter;
use commonware_utils::sync::Mutex;
use std::{
    mem,
    sync::{Arc, Weak},
};

/// Delay reaping dropped children until enough stale weak pointers accumulate to
/// amortize the cleanup cost for clone-heavy parents.
const STALE_CHILD_THRESHOLD: usize = 32;

/// Tracks the relationship between runtime contexts.
///
/// Each [`Tree`] node corresponds to a single context instance. Cloning a context
/// registers a new child node beneath the current node. When the task spawned from
/// a context finishes or is aborted, the runtime drains the node and aborts all descendant
/// tasks (leaving siblings intact).
pub(crate) struct Tree {
    // Keep the strong parent link outside `inner`.
    //
    // This link models ownership of the ancestry chain rather than mutable
    // supervision state. `drop_ancestry` walks that ownership chain using only
    // `Arc<Tree>` handles, so it must be able to sever each parent link without
    // taking the `inner` lock first.
    parent: Mutex<Option<Arc<Self>>>,
    inner: Mutex<TreeInner>,
}

/// Weak child pointers with a deferred-compaction counter.
#[derive(Default)]
struct Children {
    links: Vec<Weak<Tree>>,
    stale: usize,
}

impl Children {
    /// Appends a weak reference to `child`, compacting stale entries first if
    /// the stale count has reached [`STALE_CHILD_THRESHOLD`].
    fn push(&mut self, child: &Arc<Tree>) {
        if self.stale >= STALE_CHILD_THRESHOLD {
            self.links.retain(|weak| weak.strong_count() > 0);
            self.stale = 0;
        }
        self.links.push(Arc::downgrade(child));
    }

    /// Records that one weak child pointer is known-dead.
    const fn mark_stale(&mut self) {
        self.stale = self.stale.saturating_add(1);
    }

    /// Takes all weak child pointers, resetting the list and stale count.
    fn drain(&mut self) -> Vec<Weak<Tree>> {
        mem::take(self).links
    }
}

struct TreeInner {
    children: Children,
    task: Option<Aborter>,
    aborted: bool,
}

impl TreeInner {
    const fn new(aborted: bool) -> Self {
        Self {
            children: Children {
                links: Vec::new(),
                stale: 0,
            },
            task: None,
            aborted,
        }
    }

    fn child(&mut self, child: &Arc<Tree>) {
        self.children.push(child);
    }

    fn register(&mut self, aborter: Aborter) -> Result<(), Aborter> {
        if self.aborted {
            return Err(aborter);
        }

        assert!(self.task.is_none(), "task already registered");
        self.task = Some(aborter);
        Ok(())
    }

    fn abort(&mut self) -> Option<(Option<Aborter>, Vec<Weak<Tree>>)> {
        if self.aborted {
            return None;
        }

        self.aborted = true;
        let task = self.task.take();
        let children = self.children.drain();
        Some((task, children))
    }
}

impl Tree {
    /// Returns a new root node without a parent.
    pub(crate) fn root() -> Arc<Self> {
        Arc::new(Self {
            parent: Mutex::new(None),
            inner: Mutex::new(TreeInner::new(false)),
        })
    }

    /// Creates a new child node registered under the provided parent.
    pub(crate) fn child(parent: &Arc<Self>) -> (Arc<Self>, bool) {
        let mut parent_inner = parent.inner.lock();
        let aborted = parent_inner.aborted;
        let child = Arc::new(Self {
            // Hold a strong reference to the parent to keep an ancestry of
            // unspawned contexts alive. Without this, the parent could drop
            // immediately, leaving only weak pointers that cannot be upgraded
            // during abort cascades.
            parent: Mutex::new((!aborted).then(|| parent.clone())),
            inner: Mutex::new(TreeInner::new(aborted)),
        });
        if !aborted {
            parent_inner.child(&child);
        }
        drop(parent_inner);

        (child, aborted)
    }

    /// Records an [Aborter] on the node.
    pub(crate) fn register(self: &Arc<Self>, aborter: Aborter) {
        let result = {
            let mut inner = self.inner.lock();
            inner.register(aborter)
        };

        // If context was aborted before a task was registered, abort the task.
        if let Err(aborter) = result {
            aborter.abort();
        }
    }

    /// Aborts the task and all descendants rooted at this node.
    pub(crate) fn abort(self: &Arc<Self>) {
        // Walk the supervision tree iteratively so deep clone/spawn chains do
        // not exhaust the thread stack while propagating aborts.
        let mut pending = vec![Arc::clone(self)];
        while let Some(node) = pending.pop() {
            // Keep the parent link until `Drop` so stale-child accounting
            // stays centralized in one place.
            let result = {
                let mut inner = node.inner.lock();
                inner.abort()
            };
            let Some((task, children)) = result else {
                continue;
            };

            // Abort the task before descending so observers see the parent
            // transition before any surviving children are visited.
            if let Some(aborter) = task {
                aborter.abort();
            }

            // `abort()` drained this node's child list, so each upgraded child
            // is visited at most once even if the subtree is shared by weak
            // pointers elsewhere.
            pending.extend(children.into_iter().filter_map(|child| child.upgrade()));
        }
    }

    /// Drops a strong ancestry chain iteratively to avoid recursive `Arc`
    /// teardown.
    fn drop_ancestry(parent: Arc<Self>) {
        let mut pending = vec![parent];
        while let Some(node) = pending.pop() {
            // Only continue walking upward when this loop owns the final strong
            // reference to `node`. Child links are weak, so `strong_count == 1`
            // means no live descendant or external handle still depends on it.
            if Arc::strong_count(&node) == 1 {
                if let Some(parent) = node.parent.lock().take() {
                    // Move the parent `Arc` out of `node` before dropping
                    // `node`. This leaves `node.parent = None`, so `drop(node)`
                    // cannot recurse into the parent. The local `parent`
                    // variable now owns that strong reference until we push it
                    // onto `pending` for the next iteration.
                    //
                    // Because `Drop` will no longer observe this parent edge,
                    // account for the stale weak child entry before releasing
                    // `node`.
                    let mut parent_inner = parent.inner.lock();
                    parent_inner.children.mark_stale();
                    drop(parent_inner);
                    pending.push(parent);
                }
            }
            // If another strong owner still exists, dropping our handle only
            // decrements that count and the remaining ancestry stays reachable
            // through those owners.
            drop(node);
        }
    }
}

impl Drop for Tree {
    fn drop(&mut self) {
        if let Some(parent) = self.parent.get_mut().take() {
            let mut parent_inner = parent.inner.lock();
            parent_inner.children.mark_stale();
            drop(parent_inner);

            // If dropping this node makes its ancestors uniquely owned as well,
            // release that lineage iteratively instead of recursing through
            // nested `Arc` drops.
            Self::drop_ancestry(parent);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{metrics::Gauge, utils::MetricHandle};
    use futures::future::{pending, AbortHandle, Abortable};

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
        let mut current = root.clone();
        let mut futures = Vec::with_capacity(depth);

        // Build a single-chain supervision tree deep enough to overflow a
        // recursive abort implementation on typical stacks.
        for _ in 0..depth {
            let (child, aborted) = Tree::child(&current);
            assert!(!aborted, "child node unexpectedly aborted");

            let (child_aborter, child_future) = aborter();
            child.register(child_aborter);
            futures.push(child_future);
            current = child;
        }

        // Abort from the root and verify every registered descendant is still
        // reached by the iterative traversal.
        root.abort();

        for future in futures {
            assert!(future.is_aborted(), "descendant was not aborted");
        }
    }

    #[test]
    fn drop_deep_clone_chain_without_stack_growth() {
        let depth = 50_000;
        let root = Tree::root();
        let mut current = root.clone();

        // Keep only one strong edge per level so dropping the leaf forces the
        // ancestry chain to tear down immediately.
        for _ in 0..depth {
            let (child, aborted) = Tree::child(&current);
            assert!(!aborted, "child node unexpectedly aborted");
            current = child;
        }

        // This used to recurse through nested `Arc` drops; now the lineage is
        // released iteratively.
        drop(current);
        drop(root);
    }

    #[test]
    fn child_reaping_batches_compaction_for_clone_heavy_parent() {
        let root = Tree::root();
        let mut dropped = Vec::with_capacity(STALE_CHILD_THRESHOLD);

        // Fill the parent's weak child list exactly to the reap threshold.
        for _ in 0..STALE_CHILD_THRESHOLD {
            let (child, aborted) = Tree::child(&root);
            assert!(!aborted, "child node unexpectedly aborted");
            dropped.push(child);
        }

        for child in dropped {
            drop(child);
        }

        {
            // Reaping is deferred until the next child arrives, so the stale
            // weak pointers should still be present here.
            let inner = root.inner.lock();
            assert_eq!(inner.children.links.len(), STALE_CHILD_THRESHOLD);
            assert_eq!(inner.children.stale, STALE_CHILD_THRESHOLD);
        }

        // The next child creation should trigger one batched compaction pass.
        let (child, aborted) = Tree::child(&root);
        assert!(!aborted, "child node unexpectedly aborted");

        {
            let inner = root.inner.lock();
            assert_eq!(
                inner.children.links.len(),
                1,
                "stale children were not reaped"
            );
            assert_eq!(inner.children.stale, 0, "stale child count was not reset");
        }

        drop(child);
        drop(root);
    }

    #[test]
    fn aborted_children_still_count_toward_batched_reaping() {
        let root = Tree::root();
        let mut aborted = Vec::with_capacity(STALE_CHILD_THRESHOLD);

        // Register enough children to fill the weak child list to the reap
        // threshold, then abort and drop them all.
        for _ in 0..STALE_CHILD_THRESHOLD {
            let (child, was_aborted) = Tree::child(&root);
            assert!(!was_aborted, "child node unexpectedly aborted");
            aborted.push(child);
        }

        for child in aborted {
            child.abort();
            drop(child);
        }

        {
            // Aborted children still leave stale weak pointers behind until a
            // future insert performs the batched cleanup.
            let inner = root.inner.lock();
            assert_eq!(inner.children.links.len(), STALE_CHILD_THRESHOLD);
            assert_eq!(inner.children.stale, STALE_CHILD_THRESHOLD);
        }

        // A fresh child should compact both normally dropped and previously
        // aborted entries in the same path.
        let (child, was_aborted) = Tree::child(&root);
        assert!(!was_aborted, "child node unexpectedly aborted");

        {
            let inner = root.inner.lock();
            assert_eq!(
                inner.children.links.len(),
                1,
                "aborted children were not reaped"
            );
            assert_eq!(inner.children.stale, 0, "stale child count was not reset");
        }

        drop(child);
        drop(root);
    }

    #[test]
    fn unique_ancestor_release_counts_stale_child_on_surviving_root() {
        let root = Tree::root();

        // Arrange for each leaf drop to make its parent uniquely owned so
        // `drop_ancestry` must walk one level higher and mark the root stale.
        for _ in 0..STALE_CHILD_THRESHOLD {
            let (parent, aborted) = Tree::child(&root);
            assert!(!aborted, "parent node unexpectedly aborted");

            let (leaf, aborted) = Tree::child(&parent);
            assert!(!aborted, "leaf node unexpectedly aborted");

            // Dropping the explicit parent handle leaves the leaf as the only
            // strong owner of `parent`, so `drop_ancestry` must account for
            // the stale weak pointer on `root`.
            drop(parent);
            drop(leaf);
        }

        {
            // Those stale entries are still deferred until the next child is
            // inserted under the surviving root.
            let inner = root.inner.lock();
            assert_eq!(inner.children.links.len(), STALE_CHILD_THRESHOLD);
            assert_eq!(inner.children.stale, STALE_CHILD_THRESHOLD);
        }

        // Creating one more child should reap the stale root entries produced
        // by iterative ancestor release.
        let (child, aborted) = Tree::child(&root);
        assert!(!aborted, "child node unexpectedly aborted");

        {
            let inner = root.inner.lock();
            assert_eq!(
                inner.children.links.len(),
                1,
                "unique ancestors were not reaped"
            );
            assert_eq!(inner.children.stale, 0, "stale child count was not reset");
        }

        drop(child);
        drop(root);
    }

    #[test]
    fn abort_wide_sibling_fanout_after_batched_reaping() {
        let root = Tree::root();
        let (parent, aborted) = Tree::child(&root);
        assert!(!aborted, "parent node unexpectedly aborted");

        let mut live = Vec::new();
        let mut dropped = Vec::new();
        let total = STALE_CHILD_THRESHOLD * 2;
        // Mix live and dropped siblings so the parent accumulates stale weak
        // pointers before an abort cascade runs through the remaining subtree.
        for idx in 0..total {
            let (child, aborted) = Tree::child(&parent);
            assert!(!aborted, "child node unexpectedly aborted");

            let (aborter, future) = aborter();
            child.register(aborter);
            if idx % 3 == 0 {
                live.push((child, future));
            } else {
                dropped.push(child);
            }
        }

        for child in dropped {
            drop(child);
        }

        // Trigger one more insert so the parent compacts stale entries before
        // we verify abort propagation across the surviving siblings.
        let (trigger, aborted) = Tree::child(&parent);
        assert!(!aborted, "trigger child unexpectedly aborted");
        let (trigger_aborter, trigger_future) = aborter();
        trigger.register(trigger_aborter);

        parent.abort();

        assert!(trigger_future.is_aborted(), "trigger child was not aborted");
        for (child, future) in live {
            assert!(future.is_aborted(), "live child was not aborted");
            drop(child);
        }

        drop(trigger);
        drop(root);
    }
}
