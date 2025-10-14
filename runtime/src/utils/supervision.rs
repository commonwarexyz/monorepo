use std::sync::{Arc, Mutex, Weak};

use super::Aborter;

struct SupervisionTreeInner {
    // Retain a strong reference to the parent so clone-only hops (no spawn) keep the ancestry
    // alive. Otherwise the parent node would drop immediately, leaving descendants with only weak
    // pointers that cannot be upgraded during abort cascades.
    _parent: Option<Arc<SupervisionTree>>,
    children: Vec<Weak<SupervisionTree>>,
    task: Option<Aborter>,
    aborted: bool,
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
            inner: Mutex::new(SupervisionTreeInner {
                _parent: None,
                children: Vec::new(),
                task: None,
                aborted: false,
            }),
        })
    }

    /// Creates a new child node registered under the provided parent.
    pub(crate) fn child(parent: &Arc<Self>) -> Arc<Self> {
        let mut parent_inner = parent.inner.lock().unwrap();
        let aborted = parent_inner.aborted;

        let child = Arc::new(Self {
            inner: Mutex::new(SupervisionTreeInner {
                _parent: Some(parent.clone()),
                children: Vec::new(),
                task: None,
                aborted,
            }),
        });

        if !aborted {
            // Clean up any dead children while we have the lock.
            parent_inner.children.retain(|weak| weak.strong_count() > 0);

            // Push new item
            parent_inner.children.push(Arc::downgrade(&child));
        }

        drop(parent_inner);

        child
    }

    /// Records a supervised task so it can be aborted alongside the current context.
    pub(crate) fn register_task(&self, aborter: Aborter) {
        let mut inner = self.inner.lock().unwrap();
        if inner.aborted {
            drop(inner);
            aborter.abort();
            return;
        }

        assert!(inner.task.is_none(), "task aborter already registered");
        inner.task = Some(aborter);
    }

    /// Returns whether this node has already been aborted.
    pub(crate) fn is_aborted(&self) -> bool {
        self.inner.lock().unwrap().aborted
    }

    /// Aborts all descendants (tasks and nested contexts) rooted at this node.
    pub(crate) fn abort_descendants(&self) {
        let (task, children) = {
            let mut inner = self.inner.lock().unwrap();
            if inner.aborted {
                return;
            }
            inner.aborted = true;
            let task = inner.task.take();
            let children = std::mem::take(&mut inner.children);
            (task, children)
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
