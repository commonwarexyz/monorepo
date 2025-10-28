//! Shared control loop primitive for actors.
//!
//! # Overview
//!
//! Coordinates an actor's control loop by wiring its mailbox to the runtime that
//! owns it. The control loop multiplexes incoming [`Envelope`]s with the runtime's
//! shutdown signal so actors can continue draining pending work or exit immediately
//! on shutdown, depending on the configured policy.
//!
//! # Examples
//!
//! See [`crate::actor`] module documentation for a complete example that wires an
//! actor, its control loop, and its mailbox together.

use crate::{
    actor::{ingress::Mailbox, Envelope},
    signal::Signal,
    spawn_cell, ContextCell, Handle, Spawner,
};
use commonware_macros::select;
use futures::{channel::mpsc, StreamExt};
use tracing::debug;

/// Default [`Mailbox`] capacity when none is provided.
const DEFAULT_MAILBOX_CAPACITY: usize = 64;

/// Configures the control loop and [`Mailbox`] used to communicate with an actor.
///
/// The builder bundles an actor instance with mailbox configuration. Calling
/// [`Builder::build`] returns both the mailbox callers use to interact with the actor
/// and the [`Control`] loop that must be spawned onto the runtime.
pub struct Builder<A> {
    actor: A,
    mailbox_capacity: usize,
    drain_on_shutdown: bool,
}

impl<A> Builder<A> {
    /// Create a new builder for `actor`.
    ///
    /// # Examples
    ///
    /// See the module-level example for an end-to-end usage pattern.
    pub fn new(actor: A) -> Self {
        Self {
            actor,
            mailbox_capacity: DEFAULT_MAILBOX_CAPACITY,
            drain_on_shutdown: true,
        }
    }

    /// Override the [`Mailbox`] capacity.
    ///
    /// By default a mailbox buffers up to 64 messages. Use this method to tune
    /// throughput or backpressure behaviour to match the actor's workload.
    pub fn with_mailbox_capacity(mut self, capacity: usize) -> Self {
        self.mailbox_capacity = capacity;
        self
    }

    /// Configure whether the control loop drains outstanding messages once shutdown begins.
    ///
    /// When set to `false`, the control loop exits immediately after the runtime
    /// signals shutdown. When `true`, the loop first closes the mailbox receiver
    /// and processes any remaining buffered envelopes before completing.
    pub fn with_drain_on_shutdown(mut self, drain: bool) -> Self {
        self.drain_on_shutdown = drain;
        self
    }

    /// Finalize construction, returning the mailbox and control loop driver.
    ///
    /// The returned [`Mailbox`] can be cloned and shared with asynchronous tasks.
    /// The [`Control`] must be spawned (for example via [`Control::start`]) so the
    /// actor can process inbound messages.
    ///
    /// Captures the [`Spawner::stopped`] signal so the control loop can exit
    /// gracefully when the runtime begins shutting down.
    pub fn build<E>(self, context: E) -> (Mailbox<A>, Control<E, A>)
    where
        A: Send + 'static,
        E: Spawner,
    {
        let (tx, rx) = mpsc::channel(self.mailbox_capacity);
        let mailbox = Mailbox::new(tx);
        let shutdown = context.stopped();

        let control = Control {
            context: ContextCell::new(context),
            actor: self.actor,
            mailbox: rx,
            drain_on_shutdown: self.drain_on_shutdown,
            shutdown,
        };

        (mailbox, control)
    }
}

/// Drives an actor by receiving envelopes and executing them on the bound runtime.
pub struct Control<E, A> {
    context: ContextCell<E>,
    actor: A,
    mailbox: mpsc::Receiver<Envelope<A>>,
    drain_on_shutdown: bool,
    shutdown: Signal,
}

impl<E, A> Control<E, A>
where
    A: Send + 'static,
    E: Spawner,
{
    /// Spawn the control loop onto the associated runtime.
    ///
    /// Returns a [`Handle`] that resolves once the actor completes shutdown.
    pub fn start(mut self) -> Handle<()> {
        spawn_cell!(self.context, self.enter().await)
    }

    async fn enter(mut self) {
        loop {
            select! {
                _ = &mut self.shutdown => {
                    if self.drain_on_shutdown {
                        debug!("shutdown signal received. draining queued messages and shutting down actor");
                        self.mailbox.close();
                        while let Some(Some(envelope)) = self.mailbox.next().now_or_never() {
                            envelope(&mut self.actor).await;
                        }
                    } else {
                        debug!("shutdown signal received, shutting down actor");
                    }
                    break;
                },
                envelope = self.mailbox.next() => {
                    let Some(envelope) = envelope else {
                        debug!("mailbox closed, shutting down actor");
                        break;
                    };

                    envelope(&mut self.actor).await;
                }
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{actor::ingress::MailboxError, deterministic, handle, message, Metrics, Runner};

    message! {
        Increment { amount: usize };
        Get -> usize
    }

    #[derive(Default, Debug, Clone)]
    struct CounterActor {
        count: usize,
    }

    handle! {
        CounterActor => {
            Increment => |self, data| {
                self.count += data.amount;
            },
            Get => |self, _data| {
                self.count
            }
        }
    }

    #[test]
    fn test_actor() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let actor = CounterActor::default();
            let (mut mailbox, control) = Builder::new(actor).build(context.with_label("counter"));
            control.start();

            // Ensure the actor is initialized and accepting messages.
            let value = mailbox.ask(Get).await.unwrap();
            assert_eq!(value, 0);

            // Tell the actor to increment the value twice
            mailbox.tell(Increment { amount: 5 }).await.unwrap();
            mailbox.tell(Increment { amount: 5 }).await.unwrap();

            // Ask the actor for its value.
            let value = mailbox.ask(Get).await.unwrap();
            assert_eq!(value, 10);

            // Signal the actor to gracefully shutdown
            context.stop(0, None).await.unwrap();

            // Check that the mailbox is closed.
            if let MailboxError::Send(err) = mailbox.ask(Get).await.unwrap_err() {
                assert!(err.is_disconnected());
            } else {
                panic!("Wrong error");
            }
        });
    }
}
