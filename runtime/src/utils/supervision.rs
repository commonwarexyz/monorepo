use super::Aborter;
use commonware_utils::sync::Mutex;
use std::{
    mem,
    sync::{Arc, Weak},
};

/// Delay reaping dropped children until enough stale weak pointers accumulate to
/// amortize the cleanup cost for clone-heavy parents.
const CHILD_REAP_THRESHOLD: usize = 64;

/// Tracks the relationship between runtime contexts.
///
/// Each [`Tree`] node corresponds to a single context instance. Cloning a context
/// registers a new child node beneath the current node. When the task spawned from
/// a context finishes or is aborted, the runtime drains the node and aborts all descendant
/// tasks (leaving siblings intact).
pub(crate) struct Tree {
    parent: Mutex<Option<Arc<Self>>>,
    inner: Mutex<TreeInner>,
}

struct TreeInner {
    children: Vec<Weak<Tree>>,
    stale_children: usize,
    task: Option<Aborter>,
    aborted: bool,
}

impl TreeInner {
    const fn new(aborted: bool) -> Self {
        Self {
            children: Vec::new(),
            stale_children: 0,
            task: None,
            aborted,
        }
    }

    fn child(&mut self, child: &Arc<Tree>) {
        // Avoid scanning the entire child list on every clone. Instead, batch
        // cleanup once enough dropped children have accumulated.
        if self.stale_children >= CHILD_REAP_THRESHOLD {
            self.children.retain(|weak| weak.strong_count() > 0);
            self.stale_children = 0;
        }
        self.children.push(Arc::downgrade(child));
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
        let children = mem::take(&mut self.children);
        Some((task, children))
    }
}

impl Tree {
    /// Drops a strong ancestry chain iteratively to avoid recursive `Arc` teardown.
    fn drop_ancestry(parent: Arc<Self>) {
        let mut pending = vec![parent];
        while let Some(node) = pending.pop() {
            if Arc::strong_count(&node) == 1 {
                if let Some(parent) = node.parent.lock().take() {
                    pending.push(parent);
                }
            }
            drop(node);
        }
    }

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
            let result = {
                node.parent.lock().take();
                let mut inner = node.inner.lock();
                inner.abort()
            };
            let Some((task, children)) = result else {
                continue;
            };

            if let Some(aborter) = task {
                aborter.abort();
            }

            pending.extend(children.into_iter().filter_map(|child| child.upgrade()));
        }
    }
}

impl Drop for Tree {
    fn drop(&mut self) {
        let children = self.inner.get_mut().children.drain(..).collect::<Vec<_>>();
        if !children.is_empty() {
            if let Some(parent) = self.parent.get_mut().as_ref() {
                let mut parent_inner = parent.inner.lock();
                let released = children
                    .into_iter()
                    .filter(|child| child.strong_count() == 0)
                    .count();
                parent_inner.stale_children = parent_inner.stale_children.saturating_add(released);
            }
        }
        if let Some(parent) = self.parent.get_mut().take() {
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
    use crate::utils::MetricHandle;
    use futures::future::{pending, AbortHandle, Abortable};
    use prometheus_client::metrics::gauge::Gauge;

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

        for _ in 0..depth {
            let (child, aborted) = Tree::child(&current);
            assert!(!aborted, "child node unexpectedly aborted");

            let (child_aborter, child_future) = aborter();
            child.register(child_aborter);
            futures.push(child_future);
            current = child;
        }

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

        for _ in 0..depth {
            let (child, aborted) = Tree::child(&current);
            assert!(!aborted, "child node unexpectedly aborted");
            current = child;
        }

        drop(current);
        drop(root);
    }
}
