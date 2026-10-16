//! Unit tests for the synchronous machine, one module per concern, over the deterministic
//! [`testing`](super::testing) driver.

mod accountability;
mod admission;
mod anchor;
mod chain;
mod declare;
mod durability;
mod emit;
mod forwarding;
mod pipeline;
mod pool;
mod producer;
mod resolution;
mod retention;
mod signing;
mod timing;
mod view;
mod vqc;
