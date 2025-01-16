//! Replication of messages across a network.

pub mod public_key;
pub mod utils;

use bytes::Bytes;
use prost::DecodeError;
use std::future::Future;
use thiserror::Error;

/// Errors that can occur when interacting with a stream.
#[derive(Error, Debug)]
pub enum Error {
    #[error("Unable to decode protobuf message")]
    UnableToDecode,
}

/// A trait for reliable replication of messages across a network.
pub trait Broadcast {
    // TODO
}