//! Mock implementations for testing.

mod consumer;
mod key;
mod message;
mod producer;

pub use consumer::{Consumer, Event};
pub use key::Key;
pub use message::Envelope;
pub use producer::Producer;
