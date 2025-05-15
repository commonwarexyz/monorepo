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
    pub fn root() -> Self {
        Self {
            name: String::new(),
            task: Task::Root,
        }
    }

    pub fn future(name: String) -> Self {
        Self {
            name,
            task: Task::Future,
        }
    }

    pub fn blocking_shared(name: String) -> Self {
        Self {
            name,
            task: Task::BlockingShared,
        }
    }

    pub fn blocking_dedicated(name: String) -> Self {
        Self {
            name,
            task: Task::BlockingDedicated,
        }
    }

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
