use super::Aborter;
use std::{
    mem,
    sync::{Arc, Mutex, Weak},
};

/// Tracks the supervision relationships between runtime contexts.
///
/// Each [`SupervisionTree`] node corresponds to a single context instance. Cloning a context
/// registers a new child node beneath the current node, while spawning a task transfers ownership
/// of that node to the spawned task. When a context finishes or is aborted, the runtime drains the
/// node and aborts all descendant tasks.
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
    active_children: usize,
    aborted: bool,
}

impl SupervisionTreeInner {
    fn new(parent: Option<Arc<SupervisionTree>>, aborted: bool) -> Self {
        Self {
            _parent: parent,
            children: Vec::new(),
            task: None,
            active_children: 0,
            aborted,
        }
    }

    fn is_active(&self) -> bool {
        self.task.is_some() || self.active_children > 0
    }

    fn register_child(&mut self, child: &Arc<SupervisionTree>) -> bool {
        // To avoid unbounded growth of children for clone-heavy loops, we reap dropped children here.
        self.children.retain(|weak| weak.strong_count() > 0);
        let was_active = self.is_active();
        if SupervisionTree::is_active(child) {
            self.active_children += 1;
        }
        self.children.push(Arc::downgrade(child));
        !was_active && self.is_active()
    }

    fn set_task(&mut self, aborter: Aborter) -> Result<bool, Aborter> {
        if self.aborted {
            return Err(aborter);
        }
        let was_active = self.is_active();
        assert!(self.task.is_none(), "task aborter already registered");
        self.task = Some(aborter);
        Ok(!was_active)
    }

    fn capture(&mut self) -> Option<(Option<Aborter>, Vec<Weak<SupervisionTree>>, bool)> {
        if self.aborted {
            return None;
        }

        self.aborted = true;
        let was_active = self.is_active();
        let task = self.task.take();
        self.active_children = 0;
        let children = mem::take(&mut self.children);
        Some((task, children, was_active))
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

        let activated = if !aborted {
            parent_inner.register_child(&child)
        } else {
            false
        };
        drop(parent_inner);

        if activated {
            Self::on_activation(parent);
        }

        (child, aborted)
    }

    /// Creates a new child node for a spawned task and reattaches idle descendants.
    pub(crate) fn spawn_child(parent: &Arc<Self>) -> (Arc<Self>, bool) {
        let mut parent_inner = parent.inner.lock().unwrap();
        let aborted = parent_inner.aborted;
        let child = Arc::new(Self {
            inner: Mutex::new(SupervisionTreeInner::new(Some(parent.clone()), aborted)),
        });

        if aborted {
            return (child, true);
        }

        let mut adopted = Vec::new();
        parent_inner.children.retain(|weak| {
            let Some(existing_child) = weak.upgrade() else {
                return false;
            };
            if Self::is_active(&existing_child) {
                return true;
            }

            {
                let mut existing_inner = existing_child.inner.lock().unwrap();
                existing_inner._parent = Some(Arc::clone(&child));
            }
            adopted.push(Arc::downgrade(&existing_child));
            false
        });

        let activated = parent_inner.register_child(&child);
        drop(parent_inner);

        if activated {
            Self::on_activation(parent);
        }

        if !adopted.is_empty() {
            let mut child_inner = child.inner.lock().unwrap();
            child_inner.children = adopted;
        }

        (child, false)
    }

    fn parent(node: &Arc<Self>) -> Option<Arc<Self>> {
        let inner = node.inner.lock().unwrap();
        inner._parent.as_ref().map(Arc::clone)
    }

    fn is_active(node: &Arc<Self>) -> bool {
        let inner = node.inner.lock().unwrap();
        inner.is_active()
    }

    fn on_activation(node: &Arc<Self>) {
        let mut current = Arc::clone(node);
        while let Some(parent) = Self::parent(&current) {
            let propagate = {
                let mut parent_inner = parent.inner.lock().unwrap();
                let was_active = parent_inner.is_active();
                parent_inner.active_children += 1;
                !was_active && parent_inner.is_active()
            };
            if propagate {
                current = parent;
            } else {
                break;
            }
        }
    }

    fn on_deactivation(node: &Arc<Self>) {
        let mut current = Arc::clone(node);
        while let Some(parent) = Self::parent(&current) {
            let propagate = {
                let mut parent_inner = parent.inner.lock().unwrap();
                let was_active = parent_inner.is_active();
                assert!(
                    parent_inner.active_children > 0,
                    "active child tracking underflow"
                );
                parent_inner.active_children -= 1;
                was_active && !parent_inner.is_active()
            };
            if propagate {
                current = parent;
            } else {
                break;
            }
        }
    }

    /// Records a supervised task so it can be aborted alongside the current context.
    pub(crate) fn register_task(self: &Arc<Self>, aborter: Aborter) {
        match {
            let mut inner = self.inner.lock().unwrap();
            inner.set_task(aborter)
        } {
            Ok(activated) => {
                if activated {
                    Self::on_activation(self);
                }
            }
            Err(aborter) => aborter.abort(),
        }
    }

    /// Aborts all descendants (tasks and nested contexts) rooted at this node.
    pub(crate) fn abort_descendants(self: &Arc<Self>) {
        let result = {
            let mut inner = self.inner.lock().unwrap();
            inner.capture()
        };
        let Some((task, children, was_active)) = result else {
            return;
        };

        if was_active {
            Self::on_deactivation(self);
        }

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
