//! Processed-height introspection for simulation state.

use std::future::Future;

/// Access the latest application-acknowledged processed height.
pub trait ProcessedHeight: Send + Sync {
    /// Returns the latest processed height.
    fn processed_height(&self) -> impl Future<Output = u64> + Send;
}

impl ProcessedHeight for () {
    async fn processed_height(&self) -> u64 {
        0
    }
}
