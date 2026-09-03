//! Settlement chain built on `glue::stateful`, and its client surface.
//!
//! Block height is the clock, every deadline is an absolute block height
//! chosen when its obligation is created, every read is certified against
//! the canonical current-database root, and the settlement transition logic
//! runs as deterministic block execution (see [`state`]). [`ingress`] carries
//! transactions from peers and local RPC into proposals, [`query`] serves
//! certified reads and accepts submissions, [`light`] verifies certified
//! reads client-side, [`client`] packages the settlement operations the
//! wallet and operator roles consume, [`da`] carries dealing dissemination
//! and votes for distributed certification, [`node`] runs the operator as a
//! non-signing p2p secondary, [`harness`] runs an in-process
//! single-validator chain for the scripted walkthrough and tests, and
//! [`validator`] with [`setup`] assemble a runnable committee.

pub(crate) mod app;
pub(crate) mod client;
pub(crate) mod da;
pub(crate) mod harness;
pub(crate) mod ingress;
pub(crate) mod light;
pub(crate) mod node;
pub(crate) mod query;
pub(crate) mod setup;
pub(crate) mod state;
pub(crate) mod tx;
pub(crate) mod types;
pub(crate) mod validator;

#[cfg(test)]
mod tests;
