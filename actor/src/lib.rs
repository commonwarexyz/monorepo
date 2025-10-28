#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://commonware.xyz/imgs/rustdoc_logo.svg",
    html_favicon_url = "https://commonware.xyz/favicon.ico"
)]

// Allow proc-macro expansions to reference this crate as `::commonware_actor`
// in in-crate tests, doctests, and downstream crates with one stable path.
#[allow(unused_extern_crates)]
extern crate self as commonware_actor;

use commonware_macros::stability_scope;

stability_scope!(ALPHA {
    use std::{future::Future, ops::ControlFlow};

    pub mod mailbox;
    pub mod service;
    pub mod source;

    #[doc(hidden)]
    pub use commonware_utils::channel::oneshot;
    pub use commonware_actor_macros::ingress;

    /// Re-export of [`commonware_runtime::ContextCell`] for concise actor signatures.
    pub use commonware_runtime::ContextCell as Ctx;

    /// Stateful task driven by the actor control loop.
    ///
    /// # Lifecycle
    ///
    /// In driver mode ([`service::ServiceBuilder`]), hooks run in this order:
    ///
    /// 1. `on_startup` once (receives [`Actor::Init`] data)
    /// 2. per iteration: `preprocess`, one event dispatch via `on_ingress`, `postprocess`
    /// 3. `on_shutdown` once
    ///
    /// Return [`std::ops::ControlFlow::Break`] from `on_ingress` to exit the loop.
    pub trait Actor<E>: Send + 'static {
        /// Ingress message type consumed by this actor.
        type Ingress: Send + 'static;

        /// Initialization data passed to [`Actor::on_startup`].
        ///
        /// Use `()` for actors that do not need external initialization data.
        /// Actors with non-unit `Init` must be started via
        /// [`service::ActorService::start_with`].
        type Init: Send + 'static;

        /// Runs once when the control loop starts.
        ///
        /// `init` carries externally-provided data that the actor needs before
        /// processing messages (e.g., connection handles, peer identity).
        fn on_startup(&mut self, _context: &E, _init: Self::Init) -> impl Future<Output = ()> + Send {
            async {}
        }

        /// Runs once when the control loop stops.
        fn on_shutdown(&mut self, _context: &E) -> impl Future<Output = ()> + Send {
            async {}
        }

        /// Runs at the start of each iteration before event polling.
        fn preprocess(&mut self, _context: &E) -> impl Future<Output = ()> + Send {
            async {}
        }

        /// Handle one ingress message.
        fn on_ingress(
            &mut self,
            context: &E,
            message: Self::Ingress,
        ) -> impl Future<Output = std::ops::ControlFlow<()>> + Send;

        /// Runs at the end of each iteration.
        fn postprocess(
            &mut self,
            _context: &E,
        ) -> impl Future<Output = ()> + Send {
            async {}
        }
    }

    /// Request-response conversion trait for mailbox APIs.
    ///
    /// A request type converts itself into the actor's ingress enum by embedding a
    /// oneshot response channel into the produced ingress message.
    pub trait Request<I>: Send + 'static {
        /// Response type expected from the actor.
        type Response: Send + 'static;

        /// Convert this request into an ingress value with a response sender.
        fn into_ingress(self, response: oneshot::Sender<Self::Response>) -> I;
    }

    /// Fire-and-forget conversion trait for mailbox APIs.
    ///
    /// Maps wrapper types into ingress without closure boxing.
    pub trait Tell<I>: Send + 'static {
        /// Convert this tell message into an ingress value.
        fn into_ingress(self) -> I;
    }

    /// Converts dispatch arm results into actor control flow.
    pub trait IntoActorFlow {
        /// Convert to [`std::ops::ControlFlow`] for actor loops.
        fn into_actor_flow(self) -> ControlFlow<()>;
    }

    impl IntoActorFlow for () {
        fn into_actor_flow(self) -> ControlFlow<()> {
            std::ops::ControlFlow::Continue(())
        }
    }

    impl IntoActorFlow for ControlFlow<()> {
        fn into_actor_flow(self) -> ControlFlow<()> {
            self
        }
    }
});

/// Helper macro for writing ingress dispatch without repeating [`std::ops::ControlFlow`] glue.
///
/// Each arm expression may return `()` (treated as continue) or [`std::ops::ControlFlow<()>`].
///
/// # Example
///
/// ```rust
/// use commonware_actor::dispatch;
/// use std::ops::ControlFlow;
///
/// enum Ingress {
///     Tick,
///     Stop,
/// }
///
/// let mut ticks = 0usize;
/// let flow = dispatch!(Ingress::Tick, {
///     Ingress::Tick => { ticks += 1; },
///     Ingress::Stop => { ControlFlow::Break(()) },
/// });
/// assert_eq!(ticks, 1);
/// assert_eq!(flow, ControlFlow::Continue(()));
/// ```
#[macro_export]
#[cfg(not(any(
    commonware_stability_BETA,
    commonware_stability_GAMMA,
    commonware_stability_DELTA,
    commonware_stability_EPSILON,
    commonware_stability_RESERVED
)))] // ALPHA
macro_rules! dispatch {
    ($message:expr, { $($pattern:pat $(if $guard:expr)? => $body:expr),+ $(,)? }) => {
        match $message {
            $($pattern $(if $guard)? => $crate::IntoActorFlow::into_actor_flow($body)),+
        }
    };
}

/// Helper macro for constructing static source sets.
///
/// This macro preserves declaration order for source polling:
/// `sources!(a, b, c)` is polled as `a`, then `b`, then `c`.
#[macro_export]
#[cfg(not(any(
    commonware_stability_BETA,
    commonware_stability_GAMMA,
    commonware_stability_DELTA,
    commonware_stability_EPSILON,
    commonware_stability_RESERVED
)))] // ALPHA
macro_rules! sources {
    () => {
        $crate::source::NoSources
    };
    ($single:expr $(,)?) => {
        $single
    };
    ($first:expr, $($rest:expr),+ $(,)?) => {
        ($first, $($rest),+)
    };
}

#[cfg(test)]
mod tests {
    use super::{Request, Tell};
    use crate::ingress;
    use std::ops::ControlFlow;

    ingress! {
        MacroMailbox,

        tell Fire;
        tell Data { value: u64 };
        ask Read -> u64;
        ask Add { lhs: u64, rhs: u64 } -> u64;
    }

    #[test]
    fn ingress_macro_generates_tell_and_ask_wrappers() {
        match Fire.into_ingress() {
            MacroMailboxMessage::Fire => {}
            _ => panic!("expected fire ingress"),
        }

        match (Data { value: 7 }).into_ingress() {
            MacroMailboxMessage::Data { value } => assert_eq!(value, 7),
            _ => panic!("expected data ingress"),
        }

        let (tx, _rx) = crate::oneshot::channel::<u64>();
        match Read.into_ingress(tx) {
            MacroMailboxMessage::Read { response } => {
                drop(response);
            }
            _ => panic!("expected read ingress"),
        }

        let (tx, _rx) = crate::oneshot::channel::<u64>();
        match (Add { lhs: 2, rhs: 5 }).into_ingress(tx) {
            MacroMailboxMessage::Add { lhs, rhs, response } => {
                assert_eq!(lhs, 2);
                assert_eq!(rhs, 5);
                drop(response);
            }
            _ => panic!("expected add ingress"),
        }
    }

    #[test]
    fn dispatch_macro_accepts_continue_and_break_arms() {
        let mut total = 0u64;

        let flow = dispatch!(Fire.into_ingress(), {
            MacroMailboxMessage::Fire => {
                total += 1;
            },
            _ => {
                ControlFlow::Break(())
            }
        });
        assert_eq!(flow, ControlFlow::Continue(()));
        assert_eq!(total, 1);

        let flow = dispatch!((Data { value: 3 }).into_ingress(), {
            MacroMailboxMessage::Data { value } => {
                total += value;
            },
            _ => {
                ControlFlow::Break(())
            }
        });
        assert_eq!(flow, ControlFlow::Continue(()));
        assert_eq!(total, 4);

        let (tx, rx) = crate::oneshot::channel::<u64>();
        let flow = dispatch!(Read.into_ingress(tx), {
            MacroMailboxMessage::Read { response } => {
                let _ = response.send(total);
            },
            _ => {
                ControlFlow::Break(())
            }
        });
        assert_eq!(flow, ControlFlow::Continue(()));
        assert_eq!(futures::executor::block_on(rx).unwrap(), 4);

        let (tx, _rx) = crate::oneshot::channel::<u64>();
        let flow = dispatch!((Add { lhs: 2, rhs: 5 }).into_ingress(tx), {
            MacroMailboxMessage::Add { lhs, rhs, response } => {
                let _ = response.send(lhs + rhs);
                ControlFlow::Break(())
            },
            _ => {
                ControlFlow::Continue(())
            }
        });
        assert_eq!(flow, ControlFlow::Break(()));
    }

    // Verify that unbounded ingress generates sync tell methods and
    // an UnboundedMailbox-based wrapper.
    ingress! {
        unbounded UnboundedMacroMailbox,

        pub tell Ping;
        pub tell Payload { value: u64 };
        pub ask Fetch -> u64;
    }

    #[test]
    fn unbounded_ingress_macro_generates_sync_tell_and_async_ask() {
        // Tell wrappers still implement the same trait.
        match Ping.into_ingress() {
            UnboundedMacroMailboxMessage::Ping => {}
            _ => panic!("expected Ping ingress"),
        }

        match (Payload { value: 7 }).into_ingress() {
            UnboundedMacroMailboxMessage::Payload { value } => assert_eq!(value, 7),
            _ => panic!("expected Payload ingress"),
        }

        // Verify the unbounded mailbox wrapper works with an actual channel.
        let (tx, _rx) = commonware_utils::channel::mpsc::unbounded_channel();
        let mut mailbox = UnboundedMacroMailbox::new(tx);

        // tell is sync (not async) for unbounded mailboxes.
        assert!(mailbox.ping().is_ok());
        assert!(mailbox.payload(42).is_ok());
    }
}
