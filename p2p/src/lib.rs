use bytes::Bytes;
use commonware_cryptography::PublicKey;
use std::future::Future;

pub mod authenticated;
pub mod simulated;

/// Tuple representing a message received from a given public key.
///
/// This message is guranteed to adhere to the configuration of the channel and
/// will already be decrypted and authenticated.
pub type Message = (PublicKey, Bytes);

/// Enum indicating the set of recipients to send a message to.
///
/// TODO: message never sent to self
#[derive(Clone)]
pub enum Recipients {
    All,
    Some(Vec<PublicKey>),
    One(PublicKey),
}

/// Separate from Receiver because clone-able.
pub trait Sender: Clone {
    type Error;

    fn send(
        &self,
        recipients: Recipients,
        message: Bytes,
        priority: bool,
    ) -> impl Future<Output = Result<Vec<PublicKey>, Self::Error>> + Send;
}

pub trait Receiver {
    type Error;

    fn recv(&self) -> impl Future<Output = Result<Message, Self::Error>> + Send;
}
