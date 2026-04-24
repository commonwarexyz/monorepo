use commonware_utils::sync::Mutex;
use std::sync::Arc;

struct GuardHolder<G>(Mutex<G>);

/// A shared lifecycle token for a [`Registered`](super::Registered) metric handle.
///
/// When the last clone of the associated [`Registered`](super::Registered)
/// handle is dropped, this registration is dropped as well. Runtime-managed
/// metrics use that drop to unregister themselves from the runtime registry,
/// while external callers may attach custom cleanup with [`Registration::from`].
#[derive(Clone)]
pub struct Registration {
    _guard: Arc<dyn Send + Sync>,
}

impl Registration {
    /// Create a registration from a guard that should be dropped when the last
    /// associated [`Registered`](super::Registered) handle is dropped.
    pub fn from<G>(guard: G) -> Self
    where
        G: Send + 'static,
    {
        Self {
            _guard: Arc::new(GuardHolder(Mutex::new(guard))),
        }
    }
}
