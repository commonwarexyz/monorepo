use super::driver::Service;
use crate::{
    mailbox::{UnreliablePolicy, UnreliableReceiver},
    Actor,
};
use commonware_runtime::{Handle, Spawner};

/// Actor service backed by unreliable mailbox lanes.
pub struct Unreliable<E, A>
where
    E: Spawner,
    A: Actor<E>,
    A::Ingress: UnreliablePolicy<Overflow: Send> + Send + 'static,
{
    inner: Service<E, A, UnreliableReceiver<A::Ingress>>,
}

impl<E, A> Unreliable<E, A>
where
    E: Spawner,
    A: Actor<E>,
    A::Ingress: UnreliablePolicy<Overflow: Send> + Send + 'static,
{
    pub(super) const fn new(inner: Service<E, A, UnreliableReceiver<A::Ingress>>) -> Self {
        Self { inner }
    }

    /// Spawn the control loop, passing `args` data to [`Actor::on_startup`].
    pub fn start_with(self, args: A::Args) -> Handle<()> {
        self.inner.start_with(args)
    }
}

impl<E, A> Unreliable<E, A>
where
    E: Spawner,
    A: Actor<E, Args = ()>,
    A::Ingress: UnreliablePolicy<Overflow: Send> + Send + 'static,
{
    /// Spawn the control loop for actors whose [`Actor::Args`] is `()`.
    pub fn start(self) -> Handle<()> {
        self.inner.start()
    }
}
