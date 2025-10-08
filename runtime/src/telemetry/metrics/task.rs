//! Recording metrics related to tasks.

use prometheus_client::encoding::{EncodeLabelSet, EncodeLabelValue};

/// Metric label that indicates the type of task spawned.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct Label {
    /// The name of the task.
    name: String,
    /// The type of task (root, async, or blocking).
    kind: Kind,
    /// Whether the task is supervised by a parent.
    supervision: Supervision,
    /// Whether the task runs on a dedicated thread or the shared runtime.
    mode: Mode,
}

impl Label {
    /// Create a new label for the root task.
    pub fn root() -> Self {
        Self {
            name: String::new(),
            kind: Kind::Root,
            supervision: Supervision::Detached,
            mode: Mode::Shared,
        }
    }

    /// Create a new label for a future task.
    pub fn task(name: String, supervised: bool, dedicated: bool, blocking: bool) -> Self {
        Self {
            name,
            kind: Kind::Task,
            supervision: if supervised {
                Supervision::Supervised
            } else {
                Supervision::Detached
            },
            mode: if dedicated {
                Mode::Dedicated
            } else if blocking {
                Mode::SharedBlocking
            } else {
                Mode::Shared
            },
        }
    }

    /// Get the name of the task.
    pub fn name(&self) -> String {
        self.name.clone()
    }
}

/// Metric label that indicates the type of task spawned.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelValue)]
pub enum Kind {
    /// The root task.
    Root,
    /// An async task.
    Task,
}

/// Metric label describing whether a task is supervised by its parent.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelValue)]
pub enum Supervision {
    /// Task is supervised and will be aborted with its parent.
    Supervised,
    /// Task is detached from parent supervision.
    Detached,
}

/// Metric label describing whether a task runs on a dedicated thread.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelValue)]
pub enum Mode {
    /// Task runs on the shared runtime.
    Shared,
    /// Task runs on a shared runtime but is blocking.
    SharedBlocking,
    /// Task runs on a dedicated thread.
    Dedicated,
}
