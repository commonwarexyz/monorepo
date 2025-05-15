//! Recording metrics related to tasks.

use prometheus_client::encoding::{EncodeLabelSet, EncodeLabelValue};

/// Metric label that indicates the type of task spawned.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct Label {
    /// The name of the task.
    name: String,
    /// The type of task.
    task: Task,
}

impl Label {
    /// Create a new label for the root task.
    pub fn root() -> Self {
        Self {
            name: String::new(),
            task: Task::Root,
        }
    }

    /// Create a new label for a future task.
    pub fn future(name: String) -> Self {
        Self {
            name,
            task: Task::Future,
        }
    }

    /// Create a new label for a blocking task spawned in a shared thread pool.
    pub fn blocking_shared(name: String) -> Self {
        Self {
            name,
            task: Task::BlockingShared,
        }
    }

    /// Create a new label for a blocking task spawned on a dedicated thread.
    pub fn blocking_dedicated(name: String) -> Self {
        Self {
            name,
            task: Task::BlockingDedicated,
        }
    }

    /// Get the name of the task.
    pub fn name(&self) -> String {
        self.name.clone()
    }
}

/// Metric label that indicates the type of task spawned.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelValue)]
pub enum Task {
    /// The root task.
    Root,
    /// An async task.
    Future,
    /// A blocking task spawned in a shared thread pool.
    BlockingShared,
    /// A blocking task spawned on a dedicated thread.
    BlockingDedicated,
}
