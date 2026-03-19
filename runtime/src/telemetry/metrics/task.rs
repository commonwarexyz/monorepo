//! Recording metrics related to tasks.

use prometheus_client::encoding::{EncodeLabelSet, EncodeLabelValue};

/// Metric label that indicates the type of task spawned.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct Label {
    /// The name of the task.
    name: String,
    /// The type of task (root, async, or blocking).
    kind: Kind,
    /// Whether the task runs on a dedicated thread or the shared runtime.
    execution: Execution,
}

impl Label {
    /// Create a new label for the root task.
    pub const fn root() -> Self {
        Self {
            name: String::new(),
            kind: Kind::Root,
            execution: Execution::Shared,
        }
    }

    /// Create a new label for a future task.
    pub const fn task(name: String, execution: crate::Execution) -> Self {
        Self {
            name,
            kind: Kind::Task,
            execution: match execution {
                crate::Execution::Dedicated => Execution::Dedicated,
                crate::Execution::Shared(blocking) => {
                    if blocking {
                        Execution::SharedBlocking
                    } else {
                        Execution::Shared
                    }
                }
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

/// Metric label describing whether a task runs on a dedicated thread.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelValue)]
pub enum Execution {
    /// Task runs on the shared runtime.
    Shared,
    /// Task runs on a shared runtime but is blocking.
    SharedBlocking,
    /// Task runs on a dedicated thread.
    Dedicated,
}
