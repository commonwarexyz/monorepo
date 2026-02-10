#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://commonware.xyz/imgs/rustdoc_logo.svg",
    html_favicon_url = "https://commonware.xyz/favicon.ico"
)]

use proc_macro::TokenStream;

mod ingress;

/// Defines ingress enums, wrapper message types, and a typed mailbox API.
///
/// `ingress!` is the API-shaping macro for `commonware-actor`. You declare the
/// message protocol for one actor, and the macro generates the types needed by:
/// - callers (typed mailbox methods), and
/// - actor implementations (`ReadOnly` vs `ReadWrite` ingress enums).
///
/// # DSL
///
/// ```rust,ignore
/// ingress! {
///     // Optional: `unbounded` mailbox kind.
///     // Optional: mailbox name + generics.
///     unbounded MailboxName<Generics...>,
///
///     // Optional `pub` per item.
///     pub tell Name { fields... };
///     pub ask Name { fields... } -> Response;
///     pub ask read_write Name { fields... } -> Response;
///     pub subscribe Name { fields... } -> Response;
/// }
/// ```
///
/// # Generated code shape
///
/// Given:
///
/// ```rust,ignore
/// ingress! {
///     ApiMailbox,
///     pub tell Increment { amount: u64 };
///     pub ask Get -> u64;
///     pub ask read_write AddAndGet { amount: u64 } -> u64;
///     pub subscribe Watch -> u64;
/// }
/// ```
///
/// the macro emits (names simplified):
/// - `ApiMailboxMessage` with variants `ReadOnly(ApiMailboxReadOnlyMessage)` and
///   `ReadWrite(ApiMailboxReadWriteMessage)`
/// - `ApiMailboxReadOnlyMessage::{Get { response }}`
/// - `ApiMailboxReadWriteMessage::{Increment { .. }, AddAndGet { .., response }, Watch { response }}`
/// - `ApiMailbox` newtype over bounded/unbounded base mailbox
/// - internal wrapper structs implementing `Tell`/`Ask`
///
/// Only `pub` items generate mailbox convenience methods.
///
/// # Item semantics
///
/// - `tell`: fire-and-forget.
///   - `pub tell X` generates `x`, `x_lossy`, and `try_x` (bounded only).
/// - `ask`: request-response, routed to `ReadOnly` by default.
///   - `pub ask X` generates `x` and `x_timeout`.
/// - `ask read_write`: request-response routed to `ReadWrite`.
///   - Use this when handling the request may mutate actor state.
/// - `subscribe`: request-response split into enqueue-now / await-later.
///   - `x` returns `oneshot::Receiver<Response>` and enqueues lossily.
///   - `try_x` returns `Result<oneshot::Receiver<Response>, MailboxError>`.
///
/// # Examples
///
/// Mixed ingress including `ask read_write`:
///
/// ```rust,ignore
/// use commonware_actor_macros::ingress;
///
/// ingress! {
///     CounterMailbox,
///     pub tell Increment { amount: u64 };
///     pub ask Get -> u64;
///     pub ask read_write AddAndGet { amount: u64 } -> u64;
///     pub subscribe WaitForNext -> u64;
/// }
/// ```
///
/// Unbounded mailbox declaration:
///
/// ```ignore
/// use commonware_actor_macros::ingress;
///
/// ingress! {
///     unbounded QueueMailbox,
///     pub tell Enqueue { bytes: Vec<u8> };
///     pub ask Len -> usize;
/// }
/// ```
///
/// Named mailbox with generic parameters:
///
/// ```ignore
/// use commonware_actor_macros::ingress;
///
/// ingress! {
///     PeerMailbox<P: Clone + Send + 'static>,
///     pub tell Connect { peer: P };
///     pub ask IsConnected { peer: P } -> bool;
/// }
/// ```
#[proc_macro]
pub fn ingress(input: TokenStream) -> TokenStream {
    ingress::expand(input)
}
