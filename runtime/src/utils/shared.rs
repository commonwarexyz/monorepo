use commonware_utils::sync::{AsyncMutex, AsyncMutexGuard};
use std::sync::Arc;

/// A cloneable handle to shared mutable state.
///
/// This is useful for adapting components that need multiple handles to a
/// single underlying value. The lock is async so callers may hold a guard
/// across `.await` when the wrapped interface requires mutable access for an
/// async operation.
pub struct Shared<T> {
    inner: Arc<AsyncMutex<T>>,
}

impl<T> Shared<T> {
    /// Wrap `value` in shared mutable state.
    pub fn new(value: T) -> Self {
        Self {
            inner: Arc::new(AsyncMutex::new(value)),
        }
    }

    /// Acquire exclusive access to the wrapped value.
    pub async fn lock(&self) -> AsyncMutexGuard<'_, T> {
        self.inner.lock().await
    }
}

impl<T> Clone for Shared<T> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}
