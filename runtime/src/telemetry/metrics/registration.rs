use commonware_utils::sync::Mutex;
use std::sync::Arc;

struct GuardHolder<G>(Mutex<G>);

/// A shared lifecycle token for a [`Registered`](super::Registered) metric handle.
///
/// When the last clone of the associated [`Registered`](super::Registered)
/// handle is dropped, this registration is dropped as well. Runtime-managed
/// metrics use that drop to unregister themselves from the runtime registry,
/// while external callers may attach custom cleanup with [`Registration::from_guard`].
pub struct Registration {
    _guard: Arc<dyn Send + Sync>,
}

impl Clone for Registration {
    fn clone(&self) -> Self {
        Self {
            _guard: Arc::clone(&self._guard),
        }
    }
}

impl Registration {
    pub(crate) fn from_registration_guard<G>(guard: G) -> Self
    where
        G: Send + Sync + 'static,
    {
        Self {
            _guard: Arc::new(guard),
        }
    }

    /// Create a registration from a guard that should be dropped when the last
    /// associated [`Registered`](super::Registered) handle is dropped.
    pub fn from_guard<G>(guard: G) -> Self
    where
        G: Send + 'static,
    {
        Self::from_registration_guard(GuardHolder(Mutex::new(guard)))
    }
}

impl From<()> for Registration {
    /// Create a registration token that performs no cleanup when dropped.
    fn from(_: ()) -> Self {
        Self::from_registration_guard(())
    }
}
