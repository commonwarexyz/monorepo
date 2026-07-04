use super::driver::Service;
use crate::{
    mailbox::{Policy, Receiver},
    Actor,
};
use commonware_runtime::{Handle, Spawner};

/// Actor service backed by reliable mailbox lanes.
pub struct Reliable<E, A>
where
    E: Spawner,
    A: Actor<E>,
    A::Ingress: Policy<Overflow: Send> + Send + 'static,
{
    inner: Service<E, A, Receiver<A::Ingress>>,
}

impl<E, A> Reliable<E, A>
where
    E: Spawner,
    A: Actor<E>,
    A::Ingress: Policy<Overflow: Send> + Send + 'static,
{
    pub(super) const fn new(inner: Service<E, A, Receiver<A::Ingress>>) -> Self {
        Self { inner }
    }

    /// Spawn the control loop, passing `args` data to [`Actor::on_startup`].
    pub fn start_with(self, args: A::Args) -> Handle<()> {
        self.inner.start_with(args)
    }
}

impl<E, A> Reliable<E, A>
where
    E: Spawner,
    A: Actor<E, Args = ()>,
    A::Ingress: Policy<Overflow: Send> + Send + 'static,
{
    /// Spawn the control loop for actors whose [`Actor::Args`] is `()`.
    pub fn start(self) -> Handle<()> {
        self.inner.start()
    }
}
