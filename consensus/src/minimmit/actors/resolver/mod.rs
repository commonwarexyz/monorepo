//! Resolver actor for minimmit consensus.
//!
//! The Resolver fetches missing certificates from peers when the voter
//! needs them to advance views.

#![allow(unused_imports)] // Re-exports for public API

mod actor;
mod ingress;
mod state;

pub use actor::{Actor, Config};
pub use ingress::Mailbox;
