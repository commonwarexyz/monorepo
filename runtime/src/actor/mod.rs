//! `commonware-runtime` actor primitives.
//!
//! # Overview
//!
//! Defines the messaging primitives used to build actors within the runtime. The
//! abstractions in this module stay runtime-agnostic: task spawning, timers, and I/O
//! are delegated to the surrounding infrastructure so actors can run unchanged in the
//! deterministic executor or any other runtime that implements the required traits.
//! Actors expose behaviour by defining [`Message`] types and mapping them to async
//! [`Handler`] implementations. Callers interact with running actors through the
//! [`ingress::Mailbox`], while the actor itself is driven by the control loop in
//! [`control`].
//!
//! # Examples
//!
//! ```rust
//! use commonware_runtime::{
//!     actor::{control::Builder, Handler, Message, Actor},
//!     deterministic, handle, message, Metrics, Runner,
//!     Spawner, Clock, Network, Storage
//! };
//! use governor::clock::Clock as GClock;
//! use rand::{CryptoRng, Rng};
//!
//! message! {
//!     /// Increment the counter by the given amount.
//!     Increment { amount: usize };
//!     /// Get the current counter value.
//!     Get -> usize
//! }
//!
//! #[derive(Default, Debug)]
//! struct Counter {
//!     number: usize,
//! }
//! impl<E> Actor<E> for Counter where
//!     E: Spawner + Metrics + Rng + CryptoRng + Clock + GClock + Storage + Network
//! {
//! }
//!
//! handle! {
//!     Counter => {
//!         Increment => |self, msg| {
//!             self.number += msg.amount;
//!         },
//!         Get => |self, _msg| {
//!             self.number
//!         }
//!     }
//! }
//!
//! deterministic::Runner::default().start(|context| async move {
//!     let (mut mailbox, control) =
//!         Builder::new(Counter::default()).build(context.with_label("counter"));
//!     control.start();
//!
//!     mailbox.tell(Increment { amount: 5 }).await.unwrap();
//!     assert_eq!(mailbox.ask(Get).await.unwrap(), 5);
//! });
//! ```

use crate::{Clock, Metrics, Network, Spawner, Storage};
use futures::future::BoxFuture;
use governor::clock::Clock as GClock;
use rand::{CryptoRng, Rng};
use std::{future::Future, ops::ControlFlow};

pub mod control;
pub mod ingress;

/// Trait implemented by stateful tasks driven by the actor control loop.
///
/// An actor owns its state and processes [`Message`] values serially so handlers do not need
/// interior mutability. Implement [`Handler`] for each message the actor accepts and wire the
/// actor to a runtime with [`control::Builder`]. Callers interact with the running actor through
/// an [`ingress::Mailbox`], while the control loop guarantees only one handler runs at a time.
///
/// # Lifecycle hooks
///
/// The control loop invokes the hooks below in order:
/// - [`Actor::on_startup`] runs once before the first message is processed. Use it to
///   initialize state, register metrics, or spawn background tasks. The provided context
///   exposes the runtime's timing, randomness, storage, network, and metrics capabilities.
/// - [`Actor::preprocess`] runs before every loop iteration, prior to polling the mailbox
///   or reacting to shutdown. Use it for lightweight periodic work that should occur even
///   without inbound messages. Keep it quick to avoid delaying message handling.
/// - [`Actor::on_shutdown`] runs once after the loop exits because shutdown was signaled or
///   the mailbox closed. Use it to flush buffers or clean up spawned tasks.
///
/// Each hook returns a future so asynchronous setup and teardown can run without blocking
/// the control loop. All hooks default to no-ops.
pub trait Actor<E>: Send + 'static
where
    E: Spawner + Metrics + Rng + CryptoRng + Clock + GClock + Storage + Network,
{
    /// A hook that runs when the actor's control loop starts.
    fn on_startup(&mut self, _context: &E) -> impl Future<Output = ()> + Send {
        async {}
    }

    /// A hook that runs on each iteration of the actor's control loop, prior to message processing.
    ///
    /// This is invoked even when no messages are queued, making it suitable for periodic
    /// housekeeping or cooperative checks. Keep the work minimal to preserve mailbox latency.
    fn preprocess(&mut self, _context: &E) -> impl Future<Output = ()> + Send {
        async {}
    }

    /// A hook that runs when the actor's control loop is shut down.
    ///
    /// Triggered when the runtime signals shutdown or when the mailbox closes. Use this to
    /// release resources owned by the actor or to cancel any auxiliary tasks that were spawned.
    fn on_shutdown(&mut self, _context: &E) -> impl Future<Output = ()> + Send {
        async {}
    }

    /// Polls an auxiliary task or stream alongside the mailbox.
    ///
    /// The control loop drives this future in the same `select!` that handles shutdown and
    /// incoming envelopes, letting an actor react to external signals that do not arrive through
    /// its [`ingress::Mailbox`]. Return `ControlFlow::Continue` to keep the loop running or
    /// `ControlFlow::Break` to request shutdown once the work is complete. The default
    /// implementation never resolves so actors opt in explicitly.
    fn auxiliary(&mut self, _context: &E) -> impl Future<Output = ControlFlow<()>> + Send {
        futures::future::pending()
    }
}

/// A message with an associated response type.
///
/// [`Message`] implementors describe the payload delivered to an actor as well as the
/// type of the response that should be produced. Both the request and response must be
/// `Send + 'static` so they can cross runtime boundaries safely.
///
/// # Examples
///
/// The [`message!`] macro generates strongly typed messages with the appropriate
/// [`Message::Response`] definitions:
///
/// ```
/// use commonware_runtime::message;
///
/// message! {
///     Ping;
///     GetValue -> u64;
///     PutValue { value: u64 }
/// }
/// ```
///
/// [`message!`]: crate::message
pub trait Message: Send + 'static {
    /// The type of response produced when handling this message.
    type Response: Send + 'static;
}

/// Handler for incoming [`Message`]s.
///
/// Actors implement this trait for every [`Message`] they are prepared to consume. The
/// handler may perform asynchronous work and is executed within the actor's run loop.
///
/// # Examples
///
/// Implementations can be written manually or generated with the [`handle!`] macro:
///
/// ```
/// use commonware_runtime::{
///     actor::{Handler, Message},
///     message,
/// };
///
/// message! { Ping }
///
/// struct Greeter;
///
/// impl Handler<Ping> for Greeter {
///     async fn handle(&mut self, _msg: Ping) {
///         // Respond to Ping
///     }
/// }
/// ```
///
/// [`handle!`]: crate::handle
pub trait Handler<M: Message>: Send + 'static {
    /// Handle an incoming message and produce a response.
    fn handle(&mut self, message: M) -> impl Future<Output = M::Response> + Send;
}

/// A boxed closure that delivers a message to an actor and executes the response future.
///
/// The runtime pushes [`Envelope`] instances through the control loop so that messages
/// can be processed serially on the actor.
pub type Envelope<A> = Box<dyn for<'a> FnOnce(&'a mut A) -> BoxFuture<'a, ()> + Send>;

/// Defines a new [`Message`] type with the given fields and response type.
///
/// # Examples
///
/// ```rust
/// use commonware_runtime::message;
///
/// // Define a unit-type message without a response
/// message! { MessageA };
///
/// // Define a unit-type message with a response
/// message! { MessageB -> String };
///
/// // Define a message without a response
/// message! { MessageC { payload: String } };
///
/// // Define a message with a response
/// message! { MessageD { payload: String } -> String };
///
/// // Define multiple messages at once
/// message! {
///    /// A unit-type message without a response
///    MyMessage;
///
///    /// A message with a packet and response
///    AnotherMessage {
///        /// The packet
///        data: u32
///    } -> u32;
///
///    /// A message with only a payload
///    Payload { content: Vec<u8> }
/// };
/// ```
#[macro_export]
macro_rules! message {
    (
        $(#[$meta:meta])*
        $name:ident
        $(; $($tail:tt)*)?
    ) => {
        $(#[$meta])*
        pub struct $name;

        impl $crate::actor::Message for $name {
            type Response = ();
        }

        $(message! { $($tail)* } )?
    };
    (
        $(#[$meta:meta])*
        $name:ident -> $response:ty
        $(; $($tail:tt)*)?
    ) => {
        $(#[$meta])*
        pub struct $name;

        impl $crate::actor::Message for $name {
            type Response = $response;
        }

        $(message! { $($tail)* } )?
    };
    (
        $(#[$meta:meta])*
        $name:ident {
            $($(#[$field_meta:meta])* $field:ident : $ty:ty),* $(,)?
        }
        $(; $($tail:tt)*)?
    ) => {
        $(#[$meta])*
        pub struct $name {
            $(
                $(#[$field_meta])*
                pub $field: $ty
            ),*
        }

        impl $crate::actor::Message for $name {
            type Response = ();
        }

        $(message! { $($tail)* } )?
    };
    (
        $(#[$meta:meta])*
        $name:ident {
            $($(#[$field_meta:meta])* $field:ident : $ty:ty),* $(,)?
        } -> $response:ty
        $(; $($tail:tt)*)?
    ) => {
        $(#[$meta])*
        pub struct $name {
            $(
                $(#[$field_meta])*
                pub $field: $ty
            ),*
        }

        impl $crate::actor::Message for $name {
            type Response = $response;
        }

        $(message! { $($tail)* } )?
    };
}

/// Implement [`Handler`] for one or more message types.
///
/// Each entry maps an actor type and message type to the body that should execute when
/// the message is received. The macro expands to async [`Handler::handle`] impls,
/// allowing multiple message implementations to be declared in a single block.
///
/// # Examples
///
/// ```rust
/// use commonware_runtime::{
///     actor::{Handler, Message},
///     handle, message,
/// };
///
/// message! {
///     Increment { amount: u64 };
///     Get -> u64
/// }
///
/// #[derive(Default, Debug)]
/// struct Counter {
///     number: u64,
/// }
///
/// handle! {
///     Counter => {
///         Increment => |self, msg| {
///             self.number += msg.amount;
///         },
///         Get => |self, _msg| {
///             self.number
///         }
///     }
/// }
/// ```
#[macro_export]
macro_rules! handle {
    (
        $actor:ident => {
            $message_ty:ty => |$sel:ident, $message:ident| {
                $($body:tt)*
            }
            $(, $($tail:tt)*)?
        }$(,)?
    ) => {
        impl $crate::actor::Handler<$message_ty> for $actor {
            async fn handle(&mut $sel, $message: $message_ty) -> <$message_ty as $crate::actor::Message>::Response {
                $($body)*
            }
        }

        $(handle! {
            $actor => {
                $($tail)*
            }
        })?
    }
}
