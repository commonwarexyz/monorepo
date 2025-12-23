use super::Aborter;
use std::{
    mem,
    sync::{Arc, Mutex, Weak},
};

/// Tracks the relationship between runtime contexts.
///
/// Each [`Tree`] node corresponds to a single context instance. Cloning a context
/// registers a new child node beneath the current node. When the task spawned from
/// a context finishes or is aborted, the runtime drains the node and aborts all descendant
/// tasks (leaving siblings intact).
pub(crate) struct Tree {
    inner: Mutex<TreeInner>,
}

struct TreeInner {
    // Hold a strong reference to the parent to keep an ancestry of unspawned contexts alive.
    //
    // Without this, the parent could drop immediately, leaving only weak pointers that
    // cannot be upgraded during abort cascades.
    _parent: Option<Arc<Tree>>,
    children: Vec<Weak<Tree>>,
    task: Option<Aborter>,
    aborted: bool,
}

impl TreeInner {
    const fn new(parent: Option<Arc<Tree>>, aborted: bool) -> Self {
        Self {
            _parent: parent,
            children: Vec::new(),
            task: None,
            aborted,
        }
    }

    fn child(&mut self, child: &Arc<Tree>) {
        // To avoid unbounded growth of children for clone-heavy loops, we reap dropped children here.
        self.children.retain(|weak| weak.strong_count() > 0);
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
    /// Returns a new root node without a parent.
    pub(crate) fn root() -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(TreeInner::new(None, false)),
        })
    }

    /// Creates a new child node registered under the provided parent.
    pub(crate) fn child(parent: &Arc<Self>) -> (Arc<Self>, bool) {
        let mut parent_inner = parent.inner.lock().unwrap();
        let aborted = parent_inner.aborted;
        let child = Arc::new(Self {
            inner: Mutex::new(TreeInner::new(Some(parent.clone()), aborted)),
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
            let mut inner = self.inner.lock().unwrap();
            inner.register(aborter)
        };

        // If context was aborted before a task was registered, abort the task.
        if let Err(aborter) = result {
            aborter.abort();
        }
    }

    /// Aborts the task and all descendants rooted at this node.
    pub(crate) fn abort(self: &Arc<Self>) {
        let result = {
            let mut inner = self.inner.lock().unwrap();
            inner.abort()
        };
        let Some((task, children)) = result else {
            return;
        };

        // Abort the task
        if let Some(aborter) = task {
            aborter.abort();
        }

        // Drain children so the subtree cannot be aborted twice.
        for child in children {
            if let Some(child) = child.upgrade() {
                child.abort();
            }
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
}
