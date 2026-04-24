use commonware_utils::sync::Mutex;
use std::sync::{Arc, Weak};

pub(crate) type RegistrationHandle = Arc<dyn RegistrationGuard>;
pub(crate) type WeakRegistrationHandle = Weak<dyn RegistrationGuard>;

pub(crate) trait RegistrationGuard: Send + Sync + 'static {
    fn registration_dropped(&self) {}
}

impl RegistrationGuard for () {}

impl<G: Send + 'static> RegistrationGuard for GuardHolder<G> {}

struct GuardHolder<G>(Mutex<G>);

/// A shared lifecycle token for a [`Registered`](super::Registered) metric handle.
///
/// When the last clone of the associated [`Registered`](super::Registered)
/// handle is dropped, this registration is dropped as well. Runtime-managed
/// metrics use that drop to unregister themselves from the runtime registry,
/// while external callers may attach custom cleanup with [`Registration::from_guard`].
pub struct Registration {
    inner: Arc<RegistrationInner>,
}

struct RegistrationInner {
    guard: RegistrationHandle,
}

impl Clone for Registration {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl Registration {
    pub(crate) fn from_handle(handle: RegistrationHandle) -> Self {
        Self {
            inner: Arc::new(RegistrationInner { guard: handle }),
        }
    }

    pub(crate) fn from_registration_guard<G>(guard: G) -> Self
    where
        G: RegistrationGuard,
    {
        Self::from_handle(Arc::new(guard))
    }

    pub(crate) fn downgrade(&self) -> WeakRegistrationHandle {
        Arc::downgrade(&self.inner.guard)
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

impl Drop for RegistrationInner {
    fn drop(&mut self) {
        self.guard.registration_dropped();
    }
}
