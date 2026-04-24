use commonware_utils::sync::Mutex;
use std::sync::{Arc, Weak};

pub(crate) type RegistrationHandle = Arc<dyn RegistrationGuard>;
pub(crate) type WeakRegistrationHandle = Weak<dyn RegistrationGuard>;

pub(crate) trait RegistrationGuard: Send + Sync + 'static {
    fn registration_cloned(&self, _registration: &RegistrationHandle) {}

    fn registration_dropped(&self, _registration: &RegistrationHandle) {}
}

impl<G: Send + 'static> RegistrationGuard for GuardHolder<G> {}

struct GuardHolder<G>(Mutex<G>);

/// A shared lifecycle token for a [`Registered`](super::Registered) metric handle.
///
/// When the last clone of the associated [`Registered`](super::Registered)
/// handle is dropped, this registration is dropped as well. Runtime-managed
/// metrics use that drop to unregister themselves from the runtime registry,
/// while external callers may attach any custom drop guard.
pub struct Registration {
    pub(crate) guard: RegistrationHandle,
}

impl Clone for Registration {
    fn clone(&self) -> Self {
        self.guard.registration_cloned(&self.guard);
        Self {
            guard: Arc::clone(&self.guard),
        }
    }
}

impl Registration {
    pub(crate) fn from_handle(handle: RegistrationHandle) -> Self {
        Self { guard: handle }
    }

    pub(crate) fn from_registration_guard<G>(guard: G) -> Self
    where
        G: RegistrationGuard,
    {
        Self {
            guard: Arc::new(guard),
        }
    }

    /// Create a registration that performs no action when dropped.
    pub fn detached() -> Self {
        Self::from_guard(())
    }

    /// Create a registration from a guard that should be dropped when the last
    /// associated [`Registered`](super::Registered) handle is dropped.
    ///
    /// This can be used by external `Metrics` implementations to run custom
    /// teardown or notification logic by providing a guard type that implements
    /// [`Drop`].
    pub fn from_guard<G>(guard: G) -> Self
    where
        G: Send + 'static,
    {
        Self::from_registration_guard(GuardHolder(Mutex::new(guard)))
    }

    pub(crate) fn downgrade(&self) -> WeakRegistrationHandle {
        Arc::downgrade(&self.guard)
    }
}

impl Drop for Registration {
    fn drop(&mut self) {
        self.guard.registration_dropped(&self.guard);
    }
}
