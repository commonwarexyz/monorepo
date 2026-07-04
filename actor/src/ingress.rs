//! Typed ingress helpers built on the non-blocking mailbox.
//!
//! [`Mailbox`] and [`UnreliableMailbox`] wrap the corresponding [`mailbox`]
//! senders with a typed request/response API. The [`crate::ingress!`] macro
//! generates message enums and a typed wrapper over these endpoints; the
//! [`Tell`] and [`Ask`] traits support hand-written message types.
//!
//! # Submission Shapes
//!
//! `tell` methods are synchronous and never block. `ask` methods enqueue like
//! `subscribe`, then await the response receiver inline. `subscribe` returns
//! the response receiver immediately so the caller can await it later.
//!
//! # Overflow
//!
//! By default, generated reliable ingress keeps FIFO overflow storage and drops
//! queued requests whose response channel has already closed. The macro's
//! `custom_policy`, `unreliable`, and `unreliable custom_policy` headers let
//! callers provide custom overflow behavior or use an unreliable mailbox that
//! may reject work under backpressure.
//!
//! # Tracing
//!
//! Generated ingress carries debug-level enqueue spans for tracing. `tell`
//! spans are new roots that `follows_from` the caller's current span so actor
//! ping-pong does not grow one unbounded trace. `ask` and `subscribe` spans
//! are children of the caller's span. Use `#[span]`, `#[span(display)]`, or
//! `#[span(debug)]` on message fields in [`crate::ingress!`] declarations to
//! record identifying values. Bare `#[span]` is an alias for
//! `#[span(display)]`.

use crate::{
    mailbox::{self, Policy, UnreliablePolicy},
    Feedback, Unreliable,
};
use commonware_utils::channel::oneshot;
use std::fmt::{self, Formatter};
use thiserror::Error;
use tracing::{debug_span, Span};

/// The actor dropped a request before responding.
///
/// Returned when the mailbox is closed, the queue policy drops the message,
/// or the actor drops the response sender without answering.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[error("request cancelled before a response was received")]
pub struct Cancelled;

/// Conversion trait for request/response messages.
pub trait Ask<I>: Send + 'static {
    /// Response type expected from the actor.
    type Response: Send + 'static;

    /// Convert this request into an ingress message.
    fn into_ingress(self, span: Span, response: oneshot::Sender<Self::Response>) -> I;
}

/// Conversion trait for fire-and-forget messages.
pub trait Tell<I>: Send + 'static {
    /// Convert this message into an ingress value.
    fn into_ingress(self, span: Span) -> I;
}

/// Scheduler route for an ingress message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Envelope<R, W> {
    /// Read-only ingress executed concurrently on a snapshot.
    ReadOnly(R),
    /// Read-write ingress executed serially on the control loop.
    ReadWrite(W),
}

/// Conversion into a scheduler route.
pub trait IntoEnvelope: Send + 'static {
    /// Read-only ingress branch.
    type ReadOnlyMessage: Send + 'static;
    /// Read-write ingress branch.
    type ReadWriteMessage: Send + 'static;

    /// Convert this value into its enqueue span and scheduler route.
    fn into_envelope(
        self,
    ) -> (
        Span,
        Envelope<Self::ReadOnlyMessage, Self::ReadWriteMessage>,
    );
}

/// Create the enqueue span for a fire-and-forget message.
///
/// The span is a new root that `follows_from` the caller's current span:
/// a tell begins a new causal unit of work, so actors that tell each other
/// in a loop link their traces instead of growing one trace without bound.
fn tell_span() -> Span {
    let current = Span::current();
    let span = debug_span!(parent: None::<tracing::span::Id>, "actor.mailbox.tell");
    span.follows_from(current.id());
    span
}

async fn response<T>(receiver: oneshot::Receiver<T>) -> Result<T, Cancelled> {
    receiver.await.map_err(|_| Cancelled)
}

/// Typed reliable mailbox endpoint.
pub struct Mailbox<I: Policy> {
    sender: mailbox::Sender<I>,
}

impl<I: Policy> Clone for Mailbox<I> {
    fn clone(&self) -> Self {
        Self {
            sender: self.sender.clone(),
        }
    }
}

impl<I: Policy> fmt::Debug for Mailbox<I> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Mailbox").finish_non_exhaustive()
    }
}

impl<I: Policy> Mailbox<I> {
    /// Create a typed mailbox from a reliable sender.
    pub const fn new(sender: mailbox::Sender<I>) -> Self {
        Self { sender }
    }

    /// Submit a fully-constructed ingress message.
    ///
    /// Callers are responsible for any span carried inside `message`.
    /// Generated mailboxes use this to enqueue without conversion traits.
    #[must_use = "caller must handle enqueue feedback"]
    pub fn enqueue(&self, message: I) -> Feedback {
        self.sender.enqueue(message)
    }

    /// Send a fire-and-forget message.
    #[must_use = "caller must handle enqueue feedback"]
    pub fn tell<T>(&self, message: T) -> Feedback
    where
        T: Tell<I>,
    {
        self.tell_with_span(message, tell_span())
    }

    /// Send a fire-and-forget message with a caller-provided enqueue span.
    #[must_use = "caller must handle enqueue feedback"]
    pub fn tell_with_span<T>(&self, message: T, span: Span) -> Feedback
    where
        T: Tell<I>,
    {
        self.enqueue(message.into_ingress(span))
    }

    /// Send a request and wait for the response.
    ///
    /// This is [`Mailbox::subscribe`] with the receiver awaited inline.
    /// Returns [`Cancelled`] when the mailbox is closed, the queue policy
    /// drops the message, or the actor drops the response sender.
    pub async fn ask<A>(&self, message: A) -> Result<A::Response, Cancelled>
    where
        A: Ask<I>,
    {
        self.ask_with_span(message, debug_span!("actor.mailbox.ask"))
            .await
    }

    /// Send a request with a caller-provided enqueue span and wait for the response.
    pub async fn ask_with_span<A>(&self, message: A, span: Span) -> Result<A::Response, Cancelled>
    where
        A: Ask<I>,
    {
        self.subscribe_with_span(message, span)
            .await
            .map_err(|_| Cancelled)
    }

    /// Enqueue a request and return the response receiver to be awaited later.
    ///
    /// The receiver resolves to an error when the mailbox is closed, the
    /// queue policy drops the message, or the actor drops the response
    /// sender.
    pub fn subscribe<A>(&self, message: A) -> oneshot::Receiver<A::Response>
    where
        A: Ask<I>,
    {
        self.subscribe_with_span(message, debug_span!("actor.mailbox.subscribe"))
    }

    /// Enqueue a request with a caller-provided enqueue span and return the response receiver.
    pub fn subscribe_with_span<A>(&self, message: A, span: Span) -> oneshot::Receiver<A::Response>
    where
        A: Ask<I>,
    {
        let (sender, receiver) = oneshot::channel();
        let _ = self.enqueue(message.into_ingress(span, sender));
        receiver
    }
}

impl<I: Policy> From<mailbox::Sender<I>> for Mailbox<I> {
    fn from(sender: mailbox::Sender<I>) -> Self {
        Self::new(sender)
    }
}

/// Typed unreliable mailbox endpoint.
pub struct UnreliableMailbox<I: UnreliablePolicy> {
    sender: mailbox::UnreliableSender<I>,
}

impl<I: UnreliablePolicy> Clone for UnreliableMailbox<I> {
    fn clone(&self) -> Self {
        Self {
            sender: self.sender.clone(),
        }
    }
}

impl<I: UnreliablePolicy> fmt::Debug for UnreliableMailbox<I> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("UnreliableMailbox").finish_non_exhaustive()
    }
}

impl<I: UnreliablePolicy> UnreliableMailbox<I> {
    /// Create a typed mailbox from an unreliable sender.
    pub const fn new(sender: mailbox::UnreliableSender<I>) -> Self {
        Self { sender }
    }

    /// Submit a fully-constructed ingress message.
    ///
    /// Callers are responsible for any span carried inside `message`.
    /// Generated mailboxes use this to enqueue without conversion traits.
    #[must_use = "caller must handle enqueue feedback"]
    pub fn enqueue(&self, message: I) -> Unreliable<Feedback> {
        self.sender.enqueue(message)
    }

    /// Send a fire-and-forget message.
    #[must_use = "caller must handle enqueue feedback"]
    pub fn tell<T>(&self, message: T) -> Unreliable<Feedback>
    where
        T: Tell<I>,
    {
        self.tell_with_span(message, tell_span())
    }

    /// Send a fire-and-forget message with a caller-provided enqueue span.
    #[must_use = "caller must handle enqueue feedback"]
    pub fn tell_with_span<T>(&self, message: T, span: Span) -> Unreliable<Feedback>
    where
        T: Tell<I>,
    {
        self.enqueue(message.into_ingress(span))
    }

    /// Send a request and wait for the response.
    ///
    /// This is [`UnreliableMailbox::subscribe`] with the receiver awaited
    /// inline. Rejection under backpressure also surfaces as [`Cancelled`];
    /// callers that need to observe rejection directly should use
    /// [`UnreliableMailbox::tell`]-style messages or
    /// [`UnreliableMailbox::enqueue`].
    pub async fn ask<A>(&self, message: A) -> Result<A::Response, Cancelled>
    where
        A: Ask<I>,
    {
        self.ask_with_span(message, debug_span!("actor.mailbox.ask"))
            .await
    }

    /// Send a request with a caller-provided enqueue span and wait for the response.
    pub async fn ask_with_span<A>(&self, message: A, span: Span) -> Result<A::Response, Cancelled>
    where
        A: Ask<I>,
    {
        response(self.subscribe_with_span(message, span)).await
    }

    /// Enqueue a request and return the response receiver to be awaited later.
    ///
    /// The receiver resolves to an error when the mailbox is closed, the
    /// message is rejected under backpressure, or the actor drops the
    /// response sender.
    pub fn subscribe<A>(&self, message: A) -> oneshot::Receiver<A::Response>
    where
        A: Ask<I>,
    {
        self.subscribe_with_span(message, debug_span!("actor.mailbox.subscribe"))
    }

    /// Enqueue a request with a caller-provided enqueue span and return the response receiver.
    pub fn subscribe_with_span<A>(&self, message: A, span: Span) -> oneshot::Receiver<A::Response>
    where
        A: Ask<I>,
    {
        let (sender, receiver) = oneshot::channel();
        let _ = self.enqueue(message.into_ingress(span, sender));
        receiver
    }
}

impl<I: UnreliablePolicy> From<mailbox::UnreliableSender<I>> for UnreliableMailbox<I> {
    fn from(sender: mailbox::UnreliableSender<I>) -> Self {
        Self::new(sender)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mocks::TraceRecorder;
    use commonware_runtime::{deterministic, Runner as _, Supervisor as _};
    use commonware_utils::NZUsize;
    use std::{collections::VecDeque, sync::mpsc::TryRecvError};

    crate::ingress! {
        GeneratedMailbox,
        pub tell Ping { value: u64 };
        pub ask Get -> u64;
        pub ask read_write Set { value: u64 } -> u64;
        pub subscribe Watch -> u64;
    }

    crate::ingress! {
        unreliable,
        LossyMailbox,
        pub tell Pulse;
        pub ask Fetch -> u64;
    }

    // A generic payload exercising type parameters in both ingress enums.
    crate::ingress! {
        TypedMailbox<T: Clone + Send + 'static>,
        pub tell Store { value: T };
        pub ask read_write Take -> T;
    }

    // `T` reaches only the read-only enum, so the read-write enum drops it and
    // is generic-free.
    crate::ingress! {
        HalfGenericMailbox<T: Send + 'static>,
        pub tell Nudge;
        pub ask Peek -> T;
    }

    // `N` reaches only the read-only enum (via the `Get` response), so it is
    // filtered onto the read-only enum and dropped from the read-write enum.
    crate::ingress! {
        ConstMailbox<const N: usize>,
        pub tell Push { value: u64 };
        pub ask Get -> [u8; N];
    }

    // The log-shape protocol: the read-write branch uses `T` but the read-only
    // branch does not, so the read-only enum is generic-free.
    crate::ingress! {
        LogShapeMailbox<T: Clone + Send + 'static>,
        subscribe read_write Propose -> T;
        subscribe Verify -> bool;
    }

    // Each branch uses a different parameter, so each sub-enum keeps exactly
    // one of them.
    crate::ingress! {
        SplitMailbox<A: Send + 'static, B: Send + 'static>,
        pub tell Left { value: A };
        pub ask Right -> B;
    }

    // Every item is a `tell`, so the read-only enum is an uninhabited `enum {}`
    // even though the mailbox is generic.
    crate::ingress! {
        AllTellMailbox<T: Send + 'static>,
        pub tell Store { value: T };
    }

    // Fields annotated with `#[span]` are recorded on the enqueue span.
    crate::ingress! {
        ObservedMailbox,
        pub tell Observe { #[span] view: &'static str, #[span(debug)] tag: &'static str, payload: u64 };
        pub ask Lookup { #[span] key: &'static str } -> u64;
    }

    // Hand-written coalescing policy: overflow keeps only the latest message.
    crate::ingress! {
        custom_policy,
        CoalescingMailbox,
        pub tell Set2 { value: u64 };
    }

    #[derive(Default)]
    pub struct Latest(Option<CoalescingMailboxMessage>);

    impl mailbox::Overflow<CoalescingMailboxMessage> for Latest {
        fn is_empty(&self) -> bool {
            self.0.is_none()
        }

        fn drain<F>(&mut self, mut push: F)
        where
            F: FnMut(CoalescingMailboxMessage) -> Option<CoalescingMailboxMessage>,
        {
            if let Some(message) = self.0.take() {
                self.0 = push(message);
            }
        }
    }

    impl mailbox::Policy for CoalescingMailboxMessage {
        type Overflow = Latest;

        fn handle(overflow: &mut Self::Overflow, message: Self) {
            overflow.0 = Some(message);
        }
    }

    // Hand-written unreliable policy composed with the `unreliable` flag.
    crate::ingress! {
        unreliable custom_policy,
        DroppyMailbox,
        pub tell Poke;
    }

    #[derive(Default)]
    pub struct NoOverflow;

    impl mailbox::Overflow<DroppyMailboxMessage> for NoOverflow {
        fn is_empty(&self) -> bool {
            true
        }

        fn drain<F>(&mut self, _push: F)
        where
            F: FnMut(DroppyMailboxMessage) -> Option<DroppyMailboxMessage>,
        {
        }
    }

    impl mailbox::UnreliablePolicy for DroppyMailboxMessage {
        type Overflow = NoOverflow;

        fn handle(_overflow: &mut Self::Overflow, _message: Self) -> bool {
            false
        }
    }

    enum Message {
        Tell {
            span: Span,
            value: u64,
        },
        Ask {
            span: Span,
            response: oneshot::Sender<u64>,
        },
    }

    impl mailbox::Policy for Message {
        type Overflow = VecDeque<Self>;

        fn handle(overflow: &mut Self::Overflow, message: Self) {
            overflow.push_back(message);
        }
    }

    impl mailbox::UnreliablePolicy for Message {
        type Overflow = VecDeque<Self>;

        fn handle(_overflow: &mut Self::Overflow, _message: Self) -> bool {
            false
        }
    }

    struct TellValue(u64);

    impl Tell<Message> for TellValue {
        fn into_ingress(self, span: Span) -> Message {
            Message::Tell {
                span,
                value: self.0,
            }
        }
    }

    struct AskValue;

    impl Ask<Message> for AskValue {
        type Response = u64;

        fn into_ingress(self, span: Span, response: oneshot::Sender<u64>) -> Message {
            Message::Ask { span, response }
        }
    }

    #[test]
    fn tell_returns_backoff_when_ready_is_full() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let (sender, mut receiver) = mailbox::new(context.child("mailbox"), NZUsize!(1));
            let mailbox = Mailbox::new(sender);

            assert_eq!(mailbox.tell(TellValue(1)), Feedback::Ok);
            assert_eq!(mailbox.tell(TellValue(2)), Feedback::Backoff);

            match receiver.try_recv().expect("first message") {
                Message::Tell { span, value } => {
                    assert!(span.is_disabled());
                    assert_eq!(value, 1);
                }
                Message::Ask { .. } => panic!("unexpected ask"),
            }
            match receiver.try_recv().expect("second message") {
                Message::Tell { span, value } => {
                    assert!(span.is_disabled());
                    assert_eq!(value, 2);
                }
                Message::Ask { .. } => panic!("unexpected ask"),
            }
        });
    }

    #[test]
    fn tell_starts_root_span_that_follows_caller() {
        let (recorder, state) = TraceRecorder::new();
        tracing::subscriber::with_default(recorder, || {
            let runner = deterministic::Runner::default();
            runner.start(|context| async move {
                let (sender, _receiver) =
                    mailbox::new::<Message>(context.child("mailbox"), NZUsize!(1));
                let mailbox = Mailbox::new(sender);

                let caller = tracing::info_span!("test.actor.caller");
                let _guard = caller.enter();
                assert_eq!(mailbox.tell(TellValue(1)), Feedback::Ok);
            });
        });

        let caller = state.span("test.actor.caller");
        let tell = state.span("actor.mailbox.tell");
        assert_eq!(tell.parent, None);
        assert_eq!(tell.follows, vec![caller.id]);
    }

    #[test]
    fn span_fields_recorded_from_annotated_fields() {
        let (recorder, state) = TraceRecorder::new();
        tracing::subscriber::with_default(recorder, || {
            let runner = deterministic::Runner::default();
            runner.start(|context| async move {
                let (sender, mut receiver) = mailbox::new(context.child("mailbox"), NZUsize!(2));
                let mailbox = ObservedMailbox::from(Mailbox::new(sender));

                assert_eq!(mailbox.observe_internal("7", "hot", 9), Feedback::Ok);
                let responder = async move {
                    let (_, first) = receiver.recv().await.unwrap().into_envelope();
                    match first {
                        Envelope::ReadWrite(ObservedMailboxReadWriteMessage::Observe {
                            view,
                            tag,
                            payload,
                        }) => {
                            assert_eq!((view, tag, payload), ("7", "hot", 9));
                        }
                        _ => panic!("expected observe"),
                    }

                    let (_, second) = receiver.recv().await.unwrap().into_envelope();
                    match second {
                        Envelope::ReadOnly(ObservedMailboxReadOnlyMessage::Lookup {
                            key,
                            response,
                        }) => {
                            assert_eq!(key, "3");
                            response.send(4).unwrap();
                        }
                        _ => panic!("expected lookup"),
                    }
                };
                let (looked, ()) = futures::join!(mailbox.lookup_internal("3"), responder);
                assert_eq!(looked.unwrap(), 4);
            });
        });

        let observe = state.span("actor.observed_mailbox.observe");
        assert_eq!(observe.field("view"), "7");
        assert_eq!(observe.field("tag"), "\"hot\"");
        assert!(observe.fields.iter().all(|(name, _)| *name != "payload"));

        let lookup = state.span("actor.observed_mailbox.lookup");
        assert_eq!(lookup.field("key"), "3");
    }

    #[test]
    fn ask_roundtrip() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let (sender, mut receiver) = mailbox::new(context.child("mailbox"), NZUsize!(1));
            let mailbox = Mailbox::new(sender);

            let requester = async move { mailbox.ask(AskValue).await.expect("response") };
            let responder = async move {
                match receiver.recv().await.expect("message") {
                    Message::Ask { span, response } => {
                        assert!(span.is_disabled());
                        response.send(7).expect("send response");
                    }
                    Message::Tell { .. } => panic!("unexpected tell"),
                }
            };
            assert_eq!(futures::join!(requester, responder).0, 7);
        });
    }

    #[test]
    fn ask_resolves_cancelled_when_mailbox_closed() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let (sender, receiver) = mailbox::new::<Message>(context.child("mailbox"), NZUsize!(1));
            let mailbox = Mailbox::new(sender);
            drop(receiver);

            assert_eq!(mailbox.ask(AskValue).await.unwrap_err(), Cancelled);
        });
    }

    #[test]
    fn ask_resolves_cancelled_when_actor_drops_response() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let (sender, mut receiver) = mailbox::new(context.child("mailbox"), NZUsize!(1));
            let mailbox = Mailbox::new(sender);

            let requester = async move { mailbox.ask(AskValue).await };
            let responder = async move {
                let message = receiver.recv().await.expect("message");
                drop(message);
            };
            assert_eq!(futures::join!(requester, responder).0, Err(Cancelled));
        });
    }

    #[test]
    fn subscribe_resolves_after_reply() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let (sender, mut receiver) = mailbox::new(context.child("mailbox"), NZUsize!(1));
            let mailbox = Mailbox::new(sender);

            let pending = mailbox.subscribe(AskValue);
            match receiver.recv().await.expect("message") {
                Message::Ask { response, .. } => response.send(3).expect("send response"),
                Message::Tell { .. } => panic!("unexpected tell"),
            }
            assert_eq!(pending.await.expect("response"), 3);
        });
    }

    #[test]
    fn unreliable_ask_rejection_resolves_cancelled() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let (sender, _receiver) =
                mailbox::new_unreliable(context.child("mailbox"), NZUsize!(1));
            let mailbox = UnreliableMailbox::new(sender);

            assert_eq!(mailbox.tell(TellValue(1)), Unreliable::new(Feedback::Ok));
            assert_eq!(mailbox.ask(AskValue).await.unwrap_err(), Cancelled);
        });
    }

    #[test]
    fn generated_mailbox_routes_messages() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let (sender, mut receiver) = mailbox::new(context.child("mailbox"), NZUsize!(2));
            let mailbox = GeneratedMailbox::from(Mailbox::new(sender));

            assert_eq!(mailbox.ping_internal(5), Feedback::Ok);
            let responder = async move {
                let (_, first) = receiver.recv().await.unwrap().into_envelope();
                assert!(matches!(
                    first,
                    Envelope::ReadWrite(GeneratedMailboxReadWriteMessage::Ping { value: 5 })
                ));

                let (_, second) = receiver.recv().await.unwrap().into_envelope();
                match second {
                    Envelope::ReadOnly(GeneratedMailboxReadOnlyMessage::Get { response }) => {
                        response.send(7).unwrap();
                    }
                    _ => panic!("expected read-only get"),
                }

                let (_, third) = receiver.recv().await.unwrap().into_envelope();
                match third {
                    Envelope::ReadWrite(GeneratedMailboxReadWriteMessage::Set {
                        value,
                        response,
                    }) => {
                        assert_eq!(value, 9);
                        response.send(10).unwrap();
                    }
                    _ => panic!("expected read-write set"),
                }
            };

            let (get_feedback, get_pending) = mailbox.enqueue_get_internal();
            let (set_feedback, set_pending) = mailbox.enqueue_set_internal(9);
            assert_eq!(get_feedback, Feedback::Ok);
            assert!(set_feedback.accepted());

            let (get, set, ()) = futures::join!(get_pending, set_pending, responder);
            assert_eq!(get.unwrap(), 7);
            assert_eq!(set.unwrap(), 10);
        });
    }

    #[test]
    fn generated_generic_mailbox_routes_messages() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let (sender, mut receiver) = mailbox::new(context.child("mailbox"), NZUsize!(2));
            let mailbox = TypedMailbox::from(Mailbox::new(sender));

            assert_eq!(mailbox.store_internal("payload".to_string()), Feedback::Ok);
            let responder = async move {
                let (_, first) = receiver.recv().await.unwrap().into_envelope();
                match first {
                    Envelope::ReadWrite(TypedMailboxReadWriteMessage::Store { value }) => {
                        assert_eq!(value, "payload");
                    }
                    _ => panic!("expected store"),
                }

                let (_, second) = receiver.recv().await.unwrap().into_envelope();
                match second {
                    Envelope::ReadWrite(TypedMailboxReadWriteMessage::Take { response }) => {
                        response.send("stored".to_string()).unwrap();
                    }
                    _ => panic!("expected take"),
                }
            };

            let (taken, ()) = futures::join!(mailbox.take_internal(), responder);
            assert_eq!(taken.unwrap(), "stored");
        });
    }

    #[test]
    fn generated_filtered_generics_compile_and_route() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            // `T` reaches only the read-only enum, so the read-write enum is
            // bare: the annotation names it without generics.
            let (sender, mut receiver) = mailbox::new(context.child("half_generic"), NZUsize!(1));
            let mailbox = HalfGenericMailbox::<u64>::from(Mailbox::new(sender));
            assert_eq!(mailbox.nudge_internal(), Feedback::Ok);
            let (_, event) = receiver.recv().await.unwrap().into_envelope();
            let nudge: HalfGenericMailboxReadWriteMessage = match event {
                Envelope::ReadWrite(message) => message,
                _ => panic!("expected nudge"),
            };
            match nudge {
                HalfGenericMailboxReadWriteMessage::Nudge => {}
            }

            // `N` reaches only the read-only enum. The read-write enum is bare
            // (named without generics) while the read-only enum routes `[u8; N]`.
            let (sender, mut receiver) = mailbox::new(context.child("const"), NZUsize!(2));
            let mailbox = ConstMailbox::<4>::from(Mailbox::new(sender));
            assert_eq!(mailbox.push_internal(3), Feedback::Ok);
            let responder = async move {
                let (_, first) = receiver.recv().await.unwrap().into_envelope();
                let push: ConstMailboxReadWriteMessage = match first {
                    Envelope::ReadWrite(message) => message,
                    _ => panic!("expected push"),
                };
                match push {
                    ConstMailboxReadWriteMessage::Push { value } => assert_eq!(value, 3),
                }

                let (_, second) = receiver.recv().await.unwrap().into_envelope();
                match second {
                    Envelope::ReadOnly(ConstMailboxReadOnlyMessage::Get { response }) => {
                        response.send([7u8; 4]).unwrap();
                    }
                    _ => panic!("expected get"),
                }
            };
            let (got, ()) = futures::join!(mailbox.get_internal(), responder);
            assert_eq!(got.unwrap(), [7u8; 4]);
        });
    }

    #[test]
    fn log_shape_readonly_enum_drops_unused_generic() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let (sender, mut receiver) = mailbox::new(context.child("log_shape"), NZUsize!(2));
            let mailbox = LogShapeMailbox::<u64>::from(Mailbox::new(sender));

            let responder = async move {
                let (_, first) = receiver.recv().await.unwrap().into_envelope();
                match first {
                    Envelope::ReadWrite(LogShapeMailboxReadWriteMessage::Propose { response }) => {
                        response.send(9).unwrap();
                    }
                    _ => panic!("expected propose"),
                }

                // The read-only enum is named without generics.
                let (_, second) = receiver.recv().await.unwrap().into_envelope();
                let verify: LogShapeMailboxReadOnlyMessage = match second {
                    Envelope::ReadOnly(message) => message,
                    _ => panic!("expected verify"),
                };
                match verify {
                    LogShapeMailboxReadOnlyMessage::Verify { response } => {
                        response.send(true).unwrap();
                    }
                }
            };

            let proposed = mailbox.propose_internal();
            let verified = mailbox.verify_internal();
            let (proposed, verified, ()) = futures::join!(proposed, verified, responder);
            assert_eq!(proposed.unwrap(), 9);
            assert!(verified.unwrap());
        });
    }

    #[test]
    fn split_generics_route_to_each_branch() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let (sender, mut receiver) = mailbox::new(context.child("split"), NZUsize!(2));
            let mailbox = SplitMailbox::<u64, bool>::from(Mailbox::new(sender));

            assert_eq!(mailbox.left_internal(5), Feedback::Ok);
            let responder = async move {
                // Each sub-enum keeps exactly the one parameter its branch uses.
                let (_, first) = receiver.recv().await.unwrap().into_envelope();
                let left: SplitMailboxReadWriteMessage<u64> = match first {
                    Envelope::ReadWrite(message) => message,
                    _ => panic!("expected left"),
                };
                match left {
                    SplitMailboxReadWriteMessage::Left { value } => assert_eq!(value, 5),
                }

                let (_, second) = receiver.recv().await.unwrap().into_envelope();
                let right: SplitMailboxReadOnlyMessage<bool> = match second {
                    Envelope::ReadOnly(message) => message,
                    _ => panic!("expected right"),
                };
                match right {
                    SplitMailboxReadOnlyMessage::Right { response } => response.send(true).unwrap(),
                }
            };

            let (right, ()) = futures::join!(mailbox.right_internal(), responder);
            assert!(right.unwrap());
        });
    }

    #[test]
    fn all_tell_generic_mailbox_has_uninhabited_readonly_enum() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let (sender, mut receiver) = mailbox::new(context.child("all_tell"), NZUsize!(1));
            let mailbox = AllTellMailbox::<u64>::from(Mailbox::new(sender));

            assert_eq!(mailbox.store_internal(7), Feedback::Ok);
            let (_, event) = receiver.recv().await.unwrap().into_envelope();
            match event {
                Envelope::ReadWrite(AllTellMailboxReadWriteMessage::Store { value }) => {
                    assert_eq!(value, 7);
                }
                // The read-only enum is uninhabited, so this arm is unreachable.
                Envelope::ReadOnly(message) => match message {},
            }
        });
    }

    #[test]
    fn generated_policy_skips_closed_response_in_overflow() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let (sender, mut receiver) = mailbox::new(context.child("mailbox"), NZUsize!(1));
            let mailbox = GeneratedMailbox::from(Mailbox::new(sender));

            assert_eq!(mailbox.ping_internal(1), Feedback::Ok);
            let response = mailbox.watch_internal();
            drop(response);

            let (_, first) = receiver.try_recv().unwrap().into_envelope();
            assert!(matches!(
                first,
                Envelope::ReadWrite(GeneratedMailboxReadWriteMessage::Ping { value: 1 })
            ));
            match receiver.try_recv() {
                Err(TryRecvError::Empty) => {}
                Ok(_) => panic!("closed response should be skipped"),
                Err(err) => panic!("unexpected error: {err:?}"),
            }
        });
    }

    #[test]
    fn custom_policy_coalesces_overflow() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let (sender, mut receiver) = mailbox::new(context.child("mailbox"), NZUsize!(1));
            let mailbox = CoalescingMailbox::from(Mailbox::new(sender));

            assert_eq!(mailbox.set2_internal(1), Feedback::Ok);
            assert_eq!(mailbox.set2_internal(2), Feedback::Backoff);
            assert_eq!(mailbox.set2_internal(3), Feedback::Backoff);

            let (_, first) = receiver.try_recv().unwrap().into_envelope();
            match first {
                Envelope::ReadWrite(CoalescingMailboxReadWriteMessage::Set2 { value }) => {
                    assert_eq!(value, 1);
                }
                _ => panic!("expected set"),
            }
            let (_, second) = receiver.try_recv().unwrap().into_envelope();
            match second {
                Envelope::ReadWrite(CoalescingMailboxReadWriteMessage::Set2 { value }) => {
                    assert_eq!(value, 3);
                }
                _ => panic!("expected coalesced set"),
            }
            assert!(matches!(receiver.try_recv(), Err(TryRecvError::Empty)));
        });
    }

    #[test]
    fn custom_unreliable_policy_rejects_overflow() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let (sender, _receiver) =
                mailbox::new_unreliable(context.child("mailbox"), NZUsize!(1));
            let mailbox = DroppyMailbox::from(UnreliableMailbox::new(sender));

            assert_eq!(mailbox.poke_internal(), Unreliable::new(Feedback::Ok));
            assert_eq!(mailbox.poke_internal(), Unreliable::Rejected);
        });
    }

    #[test]
    fn generated_unreliable_policy_rejects_overflow() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let (sender, _receiver) =
                mailbox::new_unreliable(context.child("mailbox"), NZUsize!(1));
            let mailbox = LossyMailbox::from(UnreliableMailbox::new(sender));

            assert_eq!(mailbox.pulse_internal(), Unreliable::new(Feedback::Ok));
            let (feedback, pending) = mailbox.enqueue_fetch_internal();
            assert_eq!(feedback, Unreliable::Rejected);
            assert!(pending.await.is_err());
        });
    }
}
