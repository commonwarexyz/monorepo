//! Provide an ordered stream of finalized blocks.
//!
//! This module is responsible for taking the output of the consensus protocol,
//! which may be out of order and have gaps, and ordering it into a canonical,
//! contiguous sequence of finalized blocks. It handles fetching missing data
//! from peers.
//!
//! The main component is the [`actor::Actor`], which drives the process.

pub mod actor;
pub mod config;
pub mod finalizer;
pub mod handler;
pub mod ingress;
pub mod types;
