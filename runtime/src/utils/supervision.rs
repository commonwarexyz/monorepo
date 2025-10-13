use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex, Weak,
};

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
    index: Mutex<Option<usize>>,
    children: Mutex<Vec<Weak<SupervisionTree>>>,
    task: Mutex<Option<Aborter>>,
    aborted: AtomicBool,
}

impl SupervisionTree {
    /// Returns a new root node without a parent.
    pub(crate) fn root() -> Arc<Self> {
        Arc::new(Self {
            _parent: None,
            index: Mutex::new(None),
            children: Mutex::new(Vec::new()),
            task: Mutex::new(None),
            aborted: AtomicBool::new(false),
        })
    }

    /// Creates a new child node registered under the provided parent.
    pub(crate) fn child(parent: &Arc<Self>) -> Arc<Self> {
        let aborted = parent.aborted.load(Ordering::Acquire);

        let child = Arc::new(Self {
            _parent: Some(parent.clone()),
            index: Mutex::new(None),
            children: Mutex::new(Vec::new()),
            task: Mutex::new(None),
            aborted: AtomicBool::new(aborted),
        });

        if !aborted {
            let mut children = parent.children.lock().unwrap();
            let slot = children.len();
            children.push(Arc::downgrade(&child));
            *child.index.lock().unwrap() = Some(slot);
        }

        child
    }

    /// Records a supervised task so it can be aborted alongside the current context.
    pub(crate) fn register_task(&self, aborter: Aborter) {
        if self.aborted.load(Ordering::Acquire) {
            aborter.abort();
            return;
        }

        let mut task = self.task.lock().unwrap();
        assert!(task.is_none(), "task aborter already registered");
        *task = Some(aborter);
    }

    /// Returns whether this node has already been aborted.
    pub(crate) fn is_aborted(&self) -> bool {
        self.aborted.load(Ordering::Acquire)
    }

    /// Removes a child entry from the local children list, maintaining contiguous indices.
    fn remove_child(&self, index: usize) {
        let mut children = self.children.lock().unwrap();
        if index >= children.len() {
            return;
        }

        let hole = index;
        children.swap_remove(hole);
        while hole < children.len() {
            if let Some(child) = children[hole].upgrade() {
                *child.index.lock().unwrap() = Some(hole);
                break;
            }
            children.swap_remove(hole);
        }
    }

    /// Aborts all descendants (tasks and nested contexts) rooted at this node.
    pub(crate) fn abort_descendants(&self) {
        if self.aborted.swap(true, Ordering::AcqRel) {
            return;
        }

        // Drain the tasks list first so repeated calls are idempotent.
        let task = {
            let mut task = self.task.lock().unwrap();
            task.take()
        };
        if let Some(aborter) = task {
            aborter.abort();
        }

        // Drain children so the subtree cannot be aborted twice.
        let children = {
            let mut children = self.children.lock().unwrap();
            std::mem::take(&mut *children)
        };
        for child in children {
            if let Some(child) = child.upgrade() {
                *child.index.lock().unwrap() = None;
                child.abort_descendants();
            }
        }
    }
}

impl Drop for SupervisionTree {
    fn drop(&mut self) {
        let Some(parent) = self._parent.as_ref() else {
            return;
        };

        let index = {
            let mut index = self.index.lock().unwrap();
            index.take()
        };
        if let Some(index) = index {
            parent.remove_child(index);
        }
    }
}
