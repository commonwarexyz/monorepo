//! Utilities for stream implementations.

pub mod codec;
mod timeout;
pub use timeout::{Timeout, TimeoutError};
