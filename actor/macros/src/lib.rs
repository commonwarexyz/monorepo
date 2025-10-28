//! Procedural macros for [`commonware_actor`](https://docs.rs/commonware-actor).

#![doc(
    html_logo_url = "https://commonware.xyz/imgs/rustdoc_logo.svg",
    html_favicon_url = "https://commonware.xyz/favicon.ico"
)]

use proc_macro::TokenStream;

mod ingress;

/// Define ingress variants, wrapper request/tell types, and a typed mailbox wrapper.
///
/// # DSL
///
/// ```ignore
/// ingress! {
///     // `unbounded` is optional.
///     // `pub` is optional on each item.
///     unbounded MailboxName<Generics...>,
///     pub tell Name { fields... };
///     pub ask Name { fields... } -> Response;
/// }
/// ```
///
/// # Examples
///
/// Default mailbox name and mixed tell/ask items:
///
/// ```ignore
/// ingress! {
///     tell LocalOnly;
///     pub tell Increment { amount: u64 };
///     pub ask Get -> u64;
/// }
/// ```
///
/// Named mailbox with generics:
///
/// ```ignore
/// ingress! {
///     Mailbox<P: PublicKey>,
///     pub tell Connect { peer: P };
///     pub ask IsConnected { peer: P } -> bool;
/// }
/// ```
///
/// Unbounded mailbox (sync tell methods, async ask methods):
///
/// ```ignore
/// ingress! {
///     unbounded Mailbox,
///     pub tell Enqueue { bytes: Vec<u8> };
///     pub ask Len -> usize;
/// }
/// ```
///
/// Private items with no generated convenience methods:
///
/// ```ignore
/// ingress! {
///     Mailbox,
///     tell InternalTick;
///     ask Snapshot -> State;
/// }
/// ```
///
/// The macro generates:
/// - `<MailboxName>Message` ingress enum
/// - per-item wrapper types implementing `Tell`/`Request`
/// - mailbox newtype wrapper over `Mailbox<_>` or `UnboundedMailbox<_>`
/// - convenience methods only for `pub` items
#[proc_macro]
pub fn ingress(input: TokenStream) -> TokenStream {
    ingress::expand(input)
}
