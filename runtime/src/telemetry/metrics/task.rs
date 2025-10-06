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
    /// Whether the task runs on a dedicated thread.
    schedule: Schedule,
}

impl Label {
    /// Create a new label for the root task.
    pub fn root() -> Self {
        Self {
            name: String::new(),
            kind: Kind::Root,
            supervision: Supervision::Detached,
            schedule: Schedule::Shared,
        }
    }

    /// Create a new label for a future task.
    pub fn future(name: String, supervised: bool, dedicated: bool) -> Self {
        Self {
            name,
            kind: Kind::Future,
            supervision: if supervised {
                Supervision::Supervised
            } else {
                Supervision::Detached
            },
            schedule: if dedicated {
                Schedule::Dedicated
            } else {
                Schedule::Shared
            },
        }
    }

    /// Create a new label for a blocking task.
    pub fn blocking(name: String, dedicated: bool) -> Self {
        Self {
            name,
            kind: Kind::Blocking,
            supervision: Supervision::Detached,
            schedule: if dedicated {
                Schedule::Dedicated
            } else {
                Schedule::Shared
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
    Future,
    /// A blocking task.
    Blocking,
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
pub enum Schedule {
    /// Task runs on the shared runtime.
    Shared,
    /// Task runs on a dedicated thread.
    Dedicated,
}
