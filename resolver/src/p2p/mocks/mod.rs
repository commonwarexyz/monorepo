//! Mock implementations for testing.

mod consumer;
mod key;
mod producer;

pub use crate::p2p::wire::{Message, Payload};
pub use consumer::{Consumer, Event};
pub use key::Key;
pub use producer::Producer;
