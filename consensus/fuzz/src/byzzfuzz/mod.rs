//! Per-message strict-replace ByzzFuzz interception (Algorithm 1, paper).
//!
//! Implements the fault model from "ByzzFuzz: Foundations and Applications of
//! Random Testing for BFT Protocols" on top of the simulated p2p network:
//!
//! - **round attribution** (`rnd(m)`): per-sender atomic
//!   ([`intercept::SenderViewCell`]) tracking "the maximal round in which the
//!   sender has sent or received a message". Outgoing forwarders fold each
//!   transmitted view in; [`intercept::RoundTrackingReceiver`] wrappers on
//!   inbound vote / cert / resolver receivers fold each *received* view in.
//!   Resolver inbound participates via a wire-format hand-decoder
//!   ([`intercept::resolver_view_extractor`]) that recovers the view from
//!   `Request(U64)` keys and from the `Certificate` embedded in `Response`
//!   bytes -- so even a node that has never voted on a view but receives a
//!   fetch request for it correctly raises its round cell;
//! - **network faults** (`networkFaults`): per-channel
//!   [`commonware_p2p::simulated::SplitForwarder`]s drop recipients isolated
//!   by the partition active at the *sender's* current `rnd(m)`. Old-view
//!   retransmissions therefore inherit the sender's current round and do
//!   not re-trigger old-window faults;
//! - **process faults** (`procFaults`): the byzantine sender's forwarders
//!   capture each intercepted message-fault pair into an [`Intercept`] queue;
//!   a [`ByzzFuzzInjector`] consumes the queue, decodes the *actual*
//!   intercepted message, runs a strategy mutator on it (votes are re-signed
//!   with the byzantine keys; certs / resolver are byte-mutated), and emits
//!   the result through unforwarded sender clones to the dropped subset.
//!
//! Public surface used from `lib.rs`:
//! - [`run`]      -- entry point invoked by the `Mode::Byzzfuzz` dispatcher;
//! - [`log`]      -- on-panic decision-log facility, drained by `fuzz()`'s
//!                   panic handler.
//!
//! All other items live in private submodules. Cross-submodule references
//! use direct `crate::byzzfuzz::<sub>::<item>` paths so internals do not
//! leak through this module's public surface.

mod fault;
mod forwarder;
mod injector;
mod intercept;
pub mod log;
mod runner;

pub use runner::run;
