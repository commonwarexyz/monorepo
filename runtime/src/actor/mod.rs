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
//!     actor::{control::Builder, Handler, Message},
//!     deterministic, handle, message, Metrics, Runner,
//! };
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

use futures::future::BoxFuture;
use std::future::Future;

pub mod control;
pub mod ingress;

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
