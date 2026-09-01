//! Fetch and serve view proofs for one Multimmit epoch.
//!
//! A [`ViewProof`](crate::multimmit::types::ViewProof) shows how a view ended: a V-QC or a
//! nullification of that view, or an L-QC finalizing a view at or above it. The machine asks for
//! one when it must leave a view it holds no proof for, and peers serve the proofs they retain.
//! The resolver only moves bytes; the machine verifies and admits every proof.
//!
//! # Request flow
//!
//! 1. The voter forwards a machine-issued resolution job as a [`ResolveRequest`].
//! 2. When a retained proof resolves the view, a codec worker copies it and the job completes
//!    without a fetch.
//! 3. Otherwise the view is fetched from peers through `commonware-resolver`. Each response is
//!    decoded on the codec pool, and every usable proof goes to the voter.
//! 4. The machine settles the job with `Cancel` (resolved or no longer needed) or `Reject` (the
//!    proof failed verification). Only then does the resolver answer the peer delivery, valid or
//!    invalid; an invalid answer makes the fetcher retry elsewhere. No peer is blocked, because a
//!    bad response is not portable proof of a fault.
//!
//! # Serving
//!
//! The voter retains the proofs the machine authenticated. The resolver keeps the highest L-QC,
//! which covers every view at or below it, and above it one exit proof per view, where a V-QC
//! beats a nullification. Exits at or below the machine's prune point are dropped. A peer asking
//! for a view gets the L-QC when it covers the view, else the exit of exactly that view, else
//! nothing. A proof's encoding is cached after its first request.
//!
//! # Relation to marshal backfill
//!
//! Marshal's backfill actor fetches application-chain data (L-QCs by identity, tip histories, and
//! producer blocks) for block delivery and persists what it completes. This resolver fetches only
//! consensus view proofs by view number, for the voter's machine, and keeps them in memory.

mod actor;
mod config;
mod custody;
mod mailbox;
mod metrics;
#[cfg(test)]
mod tests;

pub(crate) use actor::Actor;
pub(crate) use config::Config;
#[cfg(any(test, feature = "mocks"))]
pub(crate) use mailbox::Server;
pub(crate) use mailbox::{Mailbox, Message, ResolveRequest, Serve};
