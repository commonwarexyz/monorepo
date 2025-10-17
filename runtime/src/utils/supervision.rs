use super::Aborter;
use std::{
    mem,
    sync::{Arc, Mutex, Weak},
};

/// Tracks the relationship between runtime contexts.
///
/// Each [`Tree`] node corresponds to a single context instance. Cloning a context
/// registers a new child node beneath the current node. When the task spawned from
/// a context finishes or is aborted, the runtime drains the node and aborts all descendant tasks.
///
/// ```text
/// parent (task)
/// |- clone()  -> sibling (idle)
/// `- spawn()  -> child (task)
///     `- clone() -> grandchild (idle)
/// ```
///
/// Aborting the parent walks both branches. When the child task finishes it aborts only its own
/// subtree, so the sibling hanging off the parent remains alive.
pub(crate) struct Tree {
    inner: Mutex<TreeInner>,
}

struct TreeInner {
    // Hold a strong link back to the parent so pure clone chains keep their ancestry alive.
    // Without this, the parent node could drop immediately, leaving only weak pointers that
    // cannot be upgraded during abort cascades.
    _parent: Option<Arc<Tree>>,
    children: Vec<Weak<Tree>>,
    task: Option<Aborter>,
    aborted: bool,
}

impl TreeInner {
    fn new(parent: Option<Arc<Tree>>, aborted: bool) -> Self {
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
        assert!(self.task.is_none(), "task aborter already registered");
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

    /// Records an [Aborter] on the current context.
    pub(crate) fn register(self: &Arc<Self>, aborter: Aborter) {
        let result = {
            let mut inner = self.inner.lock().unwrap();
            inner.register(aborter)
        };

        if let Err(aborter) = result {
            aborter.abort();
        }
    }

    /// Aborts all descendants (tasks and nested contexts) rooted at this node.
    pub(crate) fn abort(self: &Arc<Self>) {
        let result = {
            let mut inner = self.inner.lock().unwrap();
            inner.abort()
        };
        let Some((task, children)) = result else {
            return;
        };

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
    use futures::{
        executor::block_on,
        future::{pending, AbortHandle, Abortable, Aborted},
        FutureExt,
    };
    use prometheus_client::metrics::gauge::Gauge;

    fn aborter() -> (Aborter, Abortable<futures::future::Pending<()>>) {
        let (handle, registration) = AbortHandle::new_pair();
        let gauge = Gauge::default();
        let metric = MetricHandle::new(gauge);
        let aborter = Aborter::new(handle, metric);
        (aborter, Abortable::new(pending::<()>(), registration))
    }

    #[test]
    fn abort_cascades_to_children() {
        let root = Tree::root();
        let (parent, aborted) = Tree::child(&root);
        assert!(!aborted, "parent node unexpectedly aborted");

        let (parent_aborter, parent_future) = aborter();
        parent.register(parent_aborter);

        let (child, aborted) = Tree::child(&parent);
        assert!(!aborted, "child node unexpectedly aborted");

        let (child_aborter, child_future) = aborter();
        child.register(child_aborter);
        parent.abort();

        assert!(matches!(block_on(parent_future), Err(Aborted)));
        assert!(matches!(block_on(child_future), Err(Aborted)));
    }

    #[test]
    fn idle_child_survives_descendant_abort() {
        let root = Tree::root();
        let (parent, aborted) = Tree::child(&root);
        assert!(!aborted, "parent node unexpectedly aborted");

        // Parent creates an idle clone that it intends to use later.
        let (child1, aborted) = Tree::child(&parent);
        assert!(!aborted, "child1 node unexpectedly aborted");

        // Parent spawns a new task; the idle helper remains attached to the parent.
        let (child2, aborted) = Tree::child(&parent);
        assert!(!aborted, "child2 node unexpectedly aborted");

        // Parent starts using the helper after the new task was created.
        let (child1_aborter, child1_future) = aborter();
        child1.register(child1_aborter);

        // Simulate the spawned task finishing, which aborts its subtree.
        let (child2_aborter, child2_future) = aborter();
        child2.register(child2_aborter);
        child2.abort();

        // The spawned task should abort.
        assert!(
            matches!(child2_future.now_or_never(), Some(Err(Aborted))),
            "child2 future did not abort as expected"
        );

        // The helper belongs to the parent and should remain pending.
        assert!(
            child1_future.now_or_never().is_none(),
            "child1 was aborted by descendant task"
        );
    }
}
