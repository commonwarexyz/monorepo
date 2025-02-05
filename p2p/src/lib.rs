//! Communicate with authenticated peers over encrypted connections.
//!
//! # Status
//!
//! `commonware-p2p` is **ALPHA** software and is not yet recommended for production use. Developers should
//! expect breaking changes and occasional instability.

use bytes::Bytes;
use commonware_cryptography::Octets;
use std::error::Error as StdError;
use std::fmt::Debug;
use std::future::Future;

pub mod authenticated;
pub mod simulated;
pub mod utils;

/// Tuple representing a message received from a given public key.
///
/// This message is guaranteed to adhere to the configuration of the channel and
/// will already be decrypted and authenticated.
pub type Message<Pk> = (Pk, Bytes);

/// Alias for identifying communication channels.
pub type Channel = u32;

/// Enum indicating the set of recipients to send a message to.
#[derive(Clone)]
pub enum Recipients<P: Octets> {
    All,
    Some(Vec<P>),
    One(P),
}

/// Interface for sending messages to a set of recipients.
pub trait Sender: Clone + Debug + Send + 'static {
    type Error: Debug + StdError + Send;
    type PublicKey: Octets;

    /// Send a message to a set of recipients.
    fn send(
        &mut self,
        recipients: Recipients<Self::PublicKey>,
        message: Bytes,
        priority: bool,
    ) -> impl Future<Output = Result<Vec<Self::PublicKey>, Self::Error>> + Send;
}

/// Interface for receiving messages from arbitrary recipients.
pub trait Receiver: Debug + Send + 'static {
    type Error: Debug + StdError + Send;
    type PublicKey: Octets;

    /// Receive a message from an arbitrary recipient.
    fn recv(
        &mut self,
    ) -> impl Future<Output = Result<Message<Self::PublicKey>, Self::Error>> + Send;
}
