//! Fetch and serve retrieval-keyed artifacts for one Multimmit epoch.
//!
//! The machine asks for an artifact it needs but has not received, named by a
//! [`RetrievalKey`](crate::multimmit::machine::RetrievalKey): a sender's vote of a view tag, a
//! header, a V-QC, a view's leader block, or an L-QC. Peers serve the artifacts they retain. The
//! resolver only moves bytes; the machine verifies and admits every artifact.
//!
//! # Request flow
//!
//! 1. The voter forwards a machine-issued resolution job as a [`ResolveRequest`].
//! 2. When a retained artifact provides the key, a codec worker copies it and the job completes
//!    without a fetch.
//! 3. Otherwise the key is fetched from peers through `commonware-resolver`. Each response is
//!    decoded as the artifact kind the key names on the codec pool, and an artifact that provides
//!    the key goes to the voter.
//! 4. The machine settles the job with `Cancel` (resolved or no longer needed) or `Reject` (the
//!    artifact failed verification). Only then does the resolver answer the peer delivery, valid
//!    or invalid; an invalid answer makes the fetcher retry elsewhere. No peer is blocked, because
//!    a bad response is not portable proof of a fault.
//!
//! # Serving
//!
//! The voter retains the artifacts the machine authenticated, and the resolver serves each under
//! every key it provides. A peer asking for a key gets the canonical encoding of the artifact
//! retained under it, else nothing. An encoding is cached once computed: a certificate's when a
//! codec worker identifies it, any other artifact's after its first request.
//!
//! A node serves only its own vote updates, each in the form naming every chain, and a sender and
//! tag serve the latest of them. A fetched update must name every chain, the form a reader that
//! missed the sender's earlier updates can read.
//!
//! The machine owns retention, through two floors. Pruning through a view retires every
//! view-scoped artifact of that view or earlier and every outstanding retrieval of a pruned view;
//! the newest L-QC survives, so a peer that fell behind the window can still fetch the finality
//! evidence it resumes from. Settling a chain at a height retires that chain's headers at or below
//! it.
//!
//! # Relation to marshal backfill
//!
//! Marshal's backfill actor fetches application-chain data (L-QCs by identity, tip histories, and
//! producer blocks) for block delivery and persists what it completes. This resolver fetches only
//! the consensus artifacts the voter's machine waits on, and keeps them in memory.

mod actor;
mod config;
mod key;
mod mailbox;
mod metrics;
#[cfg(test)]
mod tests;

pub(crate) use actor::Actor;
pub(crate) use config::Config;
#[cfg(test)]
pub(crate) use mailbox::Server;
pub(crate) use mailbox::{Mailbox, Message, ResolveRequest, Serve};
