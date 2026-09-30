//! Find a checkpoint to state-sync from, and serve this node's checkpoint to peers.
//!
//! A node whose executor starts from a checkpoint needs a recent block the validators certified,
//! and a floor to resume its marshal from. It cannot trust any single peer to name them, so the
//! [`Probe`] asks every validator for its newest [`Checkpoint`] and adopts the highest valid one
//! among replies from `f + 1` distinct validators, where `f` is the number of faults the
//! checkpoint scheme tolerates. [`join`](fn@join) drives a joining node through it.
//!
//! # Protocol
//!
//! A sample sends a request to every validator. Each validator answers with its newest
//! checkpoint: a certificate, the executed block it certifies, and a floor at or below that block.
//! A reply counts only if its sender is a validator, its certificate verifies, and its block is
//! the one the certificate names at the checkpoint's height. A peer whose reply is malformed or
//! names another block is blocked; a reply whose certificate does not verify is ignored, since it
//! may come from a validator set this node does not know. At most one reply counts per peer. Once
//! `f + 1` validators have replied, the highest checkpoint is selected. If too few reply, the
//! validators that have not replied are asked again after `retry_timeout`.
//!
//! # Why the sample is `f + 1`
//!
//! A certificate is self-certifying: any checkpoint that verifies names a block the validators
//! agreed on. A Byzantine peer can still replay an old one to drag a joining node far behind. At
//! most `f` of `f + 1` repliers are faulty, so the selected checkpoint is at least as recent as the
//! honest reply in the sample, which may date from the sample's first request.
//!
//! Checkpoint signatures do not cover the executed chain or its incarnation, so the checkpoint
//! namespace must be unique to one executed chain.
//!
//! # Floors
//!
//! A sample returns every reply's floor, ranked by its round, newest first. The probe does not
//! verify floors: [`Floors::install`](commonware_consensus::marshal::Floors::install) verifies one
//! against marshal's own view of the committee and rejects it otherwise, so [`join`](fn@join) installs the
//! first floor marshal accepts, then waits for a checkpoint at or above the index it resumes
//! after.
//!
//! # Serving
//!
//! The probe answers requests with its [`Source`]'s newest checkpoint, such as the one
//! [`Checkpoints`](super::Checkpoints) holds with the engine marshal's floor at or below it
//! ([`Local`]). It answers from an encoded response it refreshes in the background once a newer
//! checkpoint is certified, so a request never waits on the executor or marshal; the channel's
//! quota bounds how often each peer is served. A node without a certified checkpoint stays silent.

mod actor;
pub use actor::{Config, Probe};
mod join;
pub use join::join;
mod mailbox;
pub use mailbox::Mailbox;
mod source;
pub use source::{Local, Source};
mod types;
pub use types::{Checkpoint, Sampled};
mod wire;

#[cfg(test)]
mod tests;
