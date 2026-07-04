#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://commonware.xyz/imgs/rustdoc_logo.svg",
    html_favicon_url = "https://commonware.xyz/favicon.ico"
)]

use proc_macro::TokenStream;

mod ingress;

/// Defines ingress enums, a queue policy, and a typed mailbox API for one actor.
///
/// You declare the message protocol; the macro generates the types needed by
/// callers (typed mailbox methods) and by actor implementations (`ReadOnly`
/// and `ReadWrite` ingress enums).
///
/// # DSL
///
/// ```rust,ignore
/// ingress! {
///     // Optional header flags (terminated by a comma when present):
///     //   unreliable,               // unreliable mailbox, generated reject-all policy
///     //   custom_policy,            // reliable mailbox, hand-written Policy impl
///     //   unreliable custom_policy, // unreliable mailbox, hand-written UnreliablePolicy impl
///     //
///     // Optional mailbox name (defaults to `Mailbox`) plus generics with
///     // inline bounds (`where` clauses are not supported).
///     MailboxName<Generics...>,
///
///     pub tell Name { fields... };
///     pub ask Name { fields... } -> Response;
///     pub ask read_write Name { fields... } -> Response;
///     pub subscribe [read_write] Name { fields... } -> Response;
/// }
/// ```
///
/// Fields may be annotated with `#[span]`, `#[span(display)]`, or
/// `#[span(debug)]` to attach their values to the enqueue span. Bare
/// `#[span]` is an alias for `#[span(display)]`. Only annotated fields incur
/// formatting bounds.
///
/// # Item semantics
///
/// - `tell`: fire-and-forget, routed to the read-write enum. The generated
///   method is synchronous, never blocks, and returns `Feedback`
///   (`Unreliable<Feedback>` for unreliable mailboxes).
/// - `ask`: request/response, routed to the read-only enum by default. The
///   generated method enqueues exactly like `subscribe` and awaits the
///   response receiver inline, returning
///   `Result<Response, commonware_actor::ingress::Cancelled>`.
/// - `ask read_write`: as `ask`, but routed to the read-write enum. Use this
///   when handling the request mutates actor state.
/// - `subscribe`: request/response split into enqueue-now, await-later. Like
///   `ask`, it is routed to the read-only enum by default, and
///   `subscribe read_write` routes to the read-write enum. The generated
///   method returns the `oneshot::Receiver<Response>` immediately. The
///   receiver resolves to an error if the mailbox is closed, the queue policy
///   drops the message, or the actor drops the response sender.
/// - Each `ask` and `subscribe` item also generates an `enqueue_<method>`
///   variant that returns enqueue feedback and the response receiver
///   immediately. Use this when the caller needs to distinguish direct
///   acceptance, overflow handling, closure, or unreliable rejection before
///   awaiting the response.
///
/// Item visibility controls mailbox method visibility. `pub` items generate
/// public methods; items without `pub` generate private methods that can be
/// called from the declaring module. Private items are useful for messages
/// exposed through another trait or for messages that only internal sources
/// construct, such as events returned from `Actor::next_event`.
///
/// # Generated code shape
///
/// Given:
///
/// ```rust,ignore
/// ingress! {
///     MyMailbox,
///     pub tell Ping;
///     pub ask GetValue -> u64;
/// }
/// ```
///
/// the macro expands to (attributes and hidden items elided):
///
/// ```rust,ignore
/// // --- Ingress enums (matched by Actor::on_read_only / on_read_write) ---
///
/// pub enum MyMailboxReadOnlyMessage {
///     GetValue { response: oneshot::Sender<u64> },
/// }
///
/// pub enum MyMailboxReadWriteMessage {
///     Ping,
/// }
///
/// // --- Top-level ingress carrying the enqueue span ---
///
/// pub enum MyMailboxMessage {
///     ReadOnly { span: tracing::Span, message: MyMailboxReadOnlyMessage },
///     ReadWrite { span: tracing::Span, message: MyMailboxReadWriteMessage },
/// }
///
/// impl MyMailboxMessage {
///     pub fn response_closed(&self) -> bool { /* ... */ }
/// }
///
/// // --- Default queue policy (skipped with `custom_policy`) ---
///
/// impl commonware_actor::mailbox::Policy for MyMailboxMessage { /* FIFO */ }
///
/// // --- Typed mailbox newtype over the ingress endpoint ---
///
/// pub struct MyMailbox(commonware_actor::ingress::Mailbox<MyMailboxMessage>);
///
/// impl MyMailbox {
///     pub fn ping(&self) -> Feedback { /* enqueue */ }
///     pub fn enqueue_get_value(&self) -> (Feedback, oneshot::Receiver<u64>) { /* enqueue */ }
///     pub async fn get_value(&self) -> Result<u64, ingress::Cancelled> { /* subscribe + await */ }
/// }
///
/// // --- Envelope routing (consumed by the service loop) ---
///
/// impl commonware_actor::ingress::IntoEnvelope for MyMailboxMessage { /* ... */ }
/// ```
///
/// # Generics
///
/// Each generated branch enum carries only the mailbox generics its own items
/// use. If no read-only item references a parameter, the read-only enum drops
/// it (and vice versa), so the enum can be named without that parameter. The
/// top-level `{Mailbox}Message` enum and the `{Mailbox}` struct keep the full
/// mailbox generics.
///
/// Every mailbox generic must be used by at least one item; a parameter used by
/// no item is a compile error. Likewise, a parameter's bounds may only
/// reference other parameters that the same branch retains.
///
/// # Queue policies
///
/// By default the macro implements `mailbox::Policy` for the top-level
/// ingress enum: overflow is retained in FIFO order and messages whose
/// response channel has already closed are dropped. With the `unreliable`
/// flag it implements `mailbox::UnreliablePolicy` instead: overflow is
/// rejected outright and senders observe `Unreliable::Rejected`.
///
/// `custom_policy` suppresses policy generation so the enclosing module can
/// implement `Policy` (or `UnreliablePolicy` with `unreliable custom_policy`)
/// by hand, e.g. to coalesce redundant messages. The generated
/// `response_closed` helper is public for use in such implementations.
///
/// # Tracing
///
/// Every generated variant carries a debug-level `tracing::Span` created at enqueue time
/// and hidden from actor handlers; the service loop re-enters it when the
/// message is dispatched, so traces follow requests across the mailbox
/// boundary. Span names are `actor.<mailbox_snake>.<method>`.
///
/// Fields annotated with `#[span]`, `#[span(display)]`, or `#[span(debug)]`
/// are recorded on that span at enqueue time, so identifying values (epochs,
/// views, digests) appear in traces without exposing spans to handlers:
///
/// ```rust,ignore
/// ingress! {
///     VoterMailbox,
///     pub tell Vote { #[span] view: u64, #[span(debug)] digest: Digest, payload: Bytes };
/// }
/// // span: actor.voter_mailbox.vote{view=42 digest=0x51ae...}
/// ```
///
/// To keep traces bounded, `tell` methods start a *new root* span that
/// `follows_from` the caller's current span: fire-and-forget messages begin a
/// new causal unit of work, so actors that `tell` each other in a loop link
/// their traces instead of growing one trace without bound. `ask` and
/// `subscribe` methods create a *child* of the caller's current span: the
/// caller awaits the response inside its own span, so depth is bounded by the
/// request chain.
///
/// # Reserved names
///
/// Field names `response`, `span`, and any name beginning with
/// `__commonware_actor` are reserved for generated code.
///
/// # Examples
///
/// Mixed ingress with a generic payload:
///
/// ```rust,ignore
/// use commonware_actor::ingress;
///
/// ingress! {
///     CounterMailbox,
///     pub tell Increment { amount: u64 };
///     pub ask Get -> u64;
///     pub ask read_write AddAndGet { amount: u64 } -> u64;
///     pub subscribe WaitForNext -> u64;
/// }
///
/// ingress! {
///     PeerMailbox<P: Clone + Send + 'static>,
///     pub tell Connect { peer: P };
///     pub ask IsConnected { peer: P } -> bool;
/// }
/// ```
///
/// A lossy mailbox that rejects work under backpressure:
///
/// ```rust,ignore
/// use commonware_actor::ingress;
///
/// ingress! {
///     unreliable,
///     SampleMailbox,
///     pub tell Sample { value: u64 };
/// }
/// ```
#[proc_macro]
pub fn ingress(input: TokenStream) -> TokenStream {
    ingress::expand(input)
}
