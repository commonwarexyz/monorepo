//! Immutable protocol adapter; delegates to generic net::wire types.

use crate::immutable::Operation;
use crate::net::wire;
use commonware_cryptography::sha256::Digest;

pub type Message = wire::Message<Operation, Digest>;

// Protocol removed; wire module provides the shared message types.
