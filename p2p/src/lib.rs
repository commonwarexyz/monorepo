//! Communicate with authenticated peers over encrypted connections.
//!
//! # Status
//!
//! `commonware-p2p` is **ALPHA** software and is not yet recommended for production use. Developers should
//! expect breaking changes and occasional instability.

use bytes::Bytes;
use commonware_cryptography::PublicKey;
use std::error::Error as StdError;
use std::fmt::Debug;
use std::future::Future;

pub mod authenticated;
pub mod simulated;

/// Tuple representing a message received from a given public key.
///
/// This message is guranteed to adhere to the configuration of the channel and
/// will already be decrypted and authenticated.
pub type Message = (PublicKey, Bytes);

/// Enum indicating the set of recipients to send a message to.
#[derive(Clone)]
pub enum Recipients {
    All,
    Some(Vec<PublicKey>),
    One(PublicKey),
}

/// Interface for sending messages to a set of recipients.
pub trait Sender: Clone {
    type Error: Debug + StdError;

    /// Send a message to a set of recipients.
    fn send(
        &self,
        recipients: Recipients,
        message: Bytes,
        priority: bool,
    ) -> impl Future<Output = Result<Vec<PublicKey>, Self::Error>> + Send;
}

/// Interface for receiving messages from arbitrary recipients.
pub trait Receiver {
    type Error: Debug + StdError;

    /// Receive a message from an arbitrary recipient.
    fn recv(&mut self) -> impl Future<Output = Result<Message, Self::Error>> + Send;
}
