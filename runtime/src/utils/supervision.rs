use super::Aborter;
use std::{
    mem,
    sync::{Arc, Mutex, Weak},
};

/// Tracks the supervision relationships between runtime contexts.
///
/// Each [`SupervisionTree`] node corresponds to a single context instance. Cloning a context
/// registers a new child node beneath the current node, while spawning a task registers the
/// spawned context beneath its parent. When a context finishes or is aborted, the runtime drains
/// the node and aborts all descendant tasks.
pub(crate) struct SupervisionTree {
    inner: Mutex<SupervisionTreeInner>,
}

struct SupervisionTreeInner {
    // Retain a strong reference to the parent so clone-only hops (no spawn) keep the ancestry
    // alive. Otherwise the parent node would drop immediately, leaving descendants with only weak
    // pointers that cannot be upgraded during abort cascades.
    _parent: Option<Arc<SupervisionTree>>,
    children: Vec<Weak<SupervisionTree>>,
    task: Option<Aborter>,
    aborted: bool,
}

impl SupervisionTreeInner {
    fn new(parent: Option<Arc<SupervisionTree>>, aborted: bool) -> Self {
        Self {
            _parent: parent,
            children: Vec::new(),
            task: None,
            aborted,
        }
    }

    fn register_child(&mut self, child: &Arc<SupervisionTree>) {
        // To avoid unbounded growth of children for clone-heavy loops, we reap dropped children here.
        self.children.retain(|weak| weak.strong_count() > 0);
        self.children.push(Arc::downgrade(child));
    }

    fn set_task(&mut self, aborter: Aborter) -> Result<(), Aborter> {
        if self.aborted {
            return Err(aborter);
        }
        assert!(self.task.is_none(), "task aborter already registered");
        self.task = Some(aborter);
        Ok(())
    }

    fn capture(&mut self) -> Option<(Option<Aborter>, Vec<Weak<SupervisionTree>>)> {
        if self.aborted {
            return None;
        }

        self.aborted = true;
        let task = self.task.take();
        let children = mem::take(&mut self.children);
        Some((task, children))
    }
}

impl SupervisionTree {
    /// Returns a new root node without a parent.
    pub(crate) fn root() -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(SupervisionTreeInner::new(None, false)),
        })
    }

    /// Creates a new child node registered under the provided parent.
    pub(crate) fn child(parent: &Arc<Self>) -> (Arc<Self>, bool) {
        let mut parent_inner = parent.inner.lock().unwrap();
        let aborted = parent_inner.aborted;
        let child = Arc::new(Self {
            inner: Mutex::new(SupervisionTreeInner::new(Some(parent.clone()), aborted)),
        });

        if !aborted {
            parent_inner.register_child(&child);
        }
        drop(parent_inner);

        (child, aborted)
    }

    /// Creates a new child node for a spawned task.
    pub(crate) fn spawn_child(parent: &Arc<Self>) -> (Arc<Self>, bool) {
        Self::child(parent)
    }

    /// Records a supervised task so it can be aborted alongside the current context.
    pub(crate) fn register_task(self: &Arc<Self>, aborter: Aborter) {
        let result = {
            let mut inner = self.inner.lock().unwrap();
            inner.set_task(aborter)
        };

        if let Err(aborter) = result {
            aborter.abort();
        }
    }

    /// Aborts all descendants (tasks and nested contexts) rooted at this node.
    pub(crate) fn abort_descendants(self: &Arc<Self>) {
        let result = {
            let mut inner = self.inner.lock().unwrap();
            inner.capture()
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
                child.abort_descendants();
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

    fn pending_aborter() -> (Aborter, Abortable<futures::future::Pending<()>>) {
        let (handle, registration) = AbortHandle::new_pair();
        let gauge = Gauge::default();
        let metric = MetricHandle::new(gauge);
        let aborter = Aborter::new(handle, metric);
        (aborter, Abortable::new(pending::<()>(), registration))
    }

    #[test]
    fn abort_cascades_to_children() {
        let root = SupervisionTree::root();
        let (parent, aborted) = SupervisionTree::spawn_child(&root);
        assert!(!aborted, "parent node unexpectedly aborted");

        let (parent_aborter, parent_future) = pending_aborter();
        parent.register_task(parent_aborter);

        let (child, aborted) = SupervisionTree::spawn_child(&parent);
        assert!(!aborted, "child node unexpectedly aborted");

        let (child_aborter, child_future) = pending_aborter();
        child.register_task(child_aborter);

        parent.abort_descendants();

        assert!(matches!(block_on(parent_future), Err(Aborted)));
        assert!(matches!(block_on(child_future), Err(Aborted)));
    }

    #[test]
    fn idle_child_survives_descendant_abort() {
        let root = SupervisionTree::root();
        let (parent, aborted) = SupervisionTree::spawn_child(&root);
        assert!(!aborted, "parent node unexpectedly aborted");

        // Parent creates an idle clone that it intends to use later.
        let (helper, aborted) = SupervisionTree::child(&parent);
        assert!(!aborted, "helper node unexpectedly aborted");

        // Parent spawns a new task; the idle helper remains attached to the parent.
        let (child, aborted) = SupervisionTree::spawn_child(&parent);
        assert!(!aborted, "child node unexpectedly aborted");

        // Parent starts using the helper after the new task was created.
        let (helper_aborter, helper_future) = pending_aborter();
        helper.register_task(helper_aborter);

        // Simulate the spawned task finishing, which aborts its descendants.
        let (child_aborter, child_future) = pending_aborter();
        child.register_task(child_aborter);
        child.abort_descendants();

        // The spawned task should abort.
        assert!(
            matches!(child_future.now_or_never(), Some(Err(Aborted))),
            "child future did not abort as expected"
        );

        // The helper belongs to the parent and should remain pending.
        assert!(
            helper_future.now_or_never().is_none(),
            "helper was aborted by descendant task"
        );
    }
}
