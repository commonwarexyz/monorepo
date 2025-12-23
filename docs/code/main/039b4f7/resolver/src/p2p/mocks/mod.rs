//! Mock implementations for testing.

mod consumer;
mod key;
mod producer;

pub use consumer::{Consumer, Event};
pub use key::Key;
pub use producer::Producer;
