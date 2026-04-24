use commonware_utils::sync::Mutex;
use std::sync::Arc;

pub(crate) trait RegistrationGuard: Send + Sync {
    fn registration_dropped(&self, registration: &Arc<RegistrationInner>) {
        registration.release();
    }
}

impl<G: Send + 'static> RegistrationGuard for GuardHolder<G> {}

struct GuardHolder<G>(Mutex<G>);

pub(crate) struct RegistrationInner {
    guard: Box<dyn RegistrationGuard>,
    // Counts live Registration claims, not Arc strong references. The registry
    // only holds Weak references, and duplicate registration may briefly
    // upgrade one without claiming it.
    claims: Mutex<usize>,
}

impl RegistrationInner {
    pub(crate) fn new<G>(guard: G) -> Arc<Self>
    where
        G: RegistrationGuard + 'static,
    {
        Arc::new(Self {
            guard: Box::new(guard),
            claims: Mutex::new(1),
        })
    }

    pub(crate) fn claim(inner: Arc<Self>) -> Option<Registration> {
        let mut claims = inner.claims.lock();
        if *claims == 0 {
            return None;
        }
        *claims = claims.checked_add(1).expect("registration claims overflow");
        drop(claims);
        Some(Registration { inner })
    }

    pub(crate) fn release(&self) -> bool {
        let mut claims = self.claims.lock();
        let remaining = claims
            .checked_sub(1)
            .expect("registration claim count underflow");
        *claims = remaining;
        remaining == 0
    }
}

/// A shared lifecycle token for a [`Registered`](super::Registered) metric handle.
///
/// When the last clone of the associated [`Registered`](super::Registered)
/// handle is dropped, this registration is dropped as well. Runtime-managed
/// metrics use that drop to unregister themselves from the runtime registry,
/// while external callers may attach any custom drop guard.
pub struct Registration {
    pub(crate) inner: Arc<RegistrationInner>,
}

impl Clone for Registration {
    fn clone(&self) -> Self {
        RegistrationInner::claim(Arc::clone(&self.inner))
            .expect("live registration claim count missing")
    }
}

impl Registration {
    pub(crate) fn from_inner(inner: Arc<RegistrationInner>) -> Self {
        Self { inner }
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
        Self {
            inner: RegistrationInner::new(GuardHolder(Mutex::new(guard))),
        }
    }

    pub(crate) fn downgrade(&self) -> std::sync::Weak<RegistrationInner> {
        Arc::downgrade(&self.inner)
    }
}

impl Drop for Registration {
    fn drop(&mut self) {
        self.inner.guard.registration_dropped(&self.inner);
    }
}
