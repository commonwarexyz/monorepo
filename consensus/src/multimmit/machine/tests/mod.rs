//! Unit tests for the synchronous Multimmit machine, one module per protocol concern, over the
//! shared symbolic [`fixtures`].

mod admission;
mod capacity;
mod certificate_resolution;
mod chain_limits;
mod config;
mod cost;
mod crypto;
mod da;
mod durability;
mod finality;
pub(super) mod fixtures;
mod floors;
mod forwarding;
mod history;
mod placement;
mod producer;
mod properties;
mod proposal;
mod signing;
mod view;
