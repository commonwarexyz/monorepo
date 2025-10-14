use super::Aborter;
use std::{
    mem,
    sync::{Arc, Mutex, Weak},
};

/// Interior state guarded by the [`SupervisionTree`] lock.
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

/// Tracks the supervision relationships between runtime contexts.
///
/// Each [`SupervisionTree`] node corresponds to a single context instance. Cloning a context
/// registers a new child node beneath the current node, while spawning a task transfers ownership
/// of that node to the spawned task. When a context finishes or is aborted, the runtime drains the
/// node and aborts all descendant tasks.
pub(crate) struct SupervisionTree {
    inner: Mutex<SupervisionTreeInner>,
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
        let child = Arc::new(Self {
            inner: Mutex::new(SupervisionTreeInner::new(
                Some(parent.clone()),
                parent_inner.aborted,
            )),
        });

        if !parent_inner.aborted {
            parent_inner.register_child(&child);
        }

        (child, parent_inner.aborted)
    }

    /// Records a supervised task so it can be aborted alongside the current context.
    pub(crate) fn register_task(&self, aborter: Aborter) {
        let aborter = {
            let mut inner = self.inner.lock().unwrap();
            match inner.set_task(aborter) {
                Ok(()) => return,
                Err(aborter) => aborter,
            }
        };
        aborter.abort();
    }

    /// Aborts all descendants (tasks and nested contexts) rooted at this node.
    pub(crate) fn abort_descendants(&self) {
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
