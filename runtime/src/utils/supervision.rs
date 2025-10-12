use std::sync::{Arc, Mutex, Weak};

use super::Aborter;

/// Tracks the supervision relationships between runtime contexts.
///
/// Each [`SupervisionTree`] node corresponds to a single context instance. Cloning a context
/// registers a new child node beneath the current node, while spawning a task transfers ownership
/// of that node to the spawned task. When a context finishes or is aborted, the runtime drains the
/// node and aborts all descendant tasks.
pub(crate) struct SupervisionTree {
    // Retain a strong reference to the parent so clone-only hops (no spawn) keep the ancestry
    // alive. Otherwise the parent node would drop immediately, leaving descendants with only weak
    // pointers that cannot be upgraded during abort cascades.
    _parent: Option<Arc<SupervisionTree>>,
    children: Mutex<Vec<Weak<SupervisionTree>>>,
    tasks: Mutex<Vec<Aborter>>,
}

impl SupervisionTree {
    /// Returns a new root node without a parent.
    pub(crate) fn root() -> Arc<Self> {
        Arc::new(Self {
            _parent: None,
            children: Mutex::new(Vec::new()),
            tasks: Mutex::new(Vec::new()),
        })
    }

    /// Creates a new child node registered under the provided parent.
    pub(crate) fn child(parent: &Arc<Self>) -> Arc<Self> {
        let child = Arc::new(Self {
            _parent: Some(parent.clone()),
            children: Mutex::new(Vec::new()),
            tasks: Mutex::new(Vec::new()),
        });
        parent.children.lock().unwrap().push(Arc::downgrade(&child));
        child
    }

    /// Records a supervised task so it can be aborted alongside the current context.
    pub(crate) fn register_task(&self, aborter: Aborter) {
        self.tasks.lock().unwrap().push(aborter);
    }

    /// Aborts all descendants (tasks and nested contexts) rooted at this node.
    pub(crate) fn abort_descendants(&self) {
        // Drain the tasks list first so repeated calls are idempotent.
        let tasks = {
            let mut tasks = self.tasks.lock().unwrap();
            std::mem::take(&mut *tasks)
        };
        for aborter in tasks {
            aborter.abort();
        }

        // Drain children so the subtree cannot be aborted twice.
        let children = {
            let mut children = self.children.lock().unwrap();
            std::mem::take(&mut *children)
        };
        for child in children {
            if let Some(child) = child.upgrade() {
                child.abort_descendants();
            }
        }
    }
}
