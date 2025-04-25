//! Codec wrapper for [Sender] and [Receiver].

use crate::{Receiver, Recipients, Sender};
use bytes::Bytes;
use commonware_codec::{Codec, Config, Error};

/// Wrap a [Sender] and [Receiver] with some [Codec].
pub fn wrap<S: Sender, R: Receiver, VC: Config, V: Codec<VC>>(
    config: VC,
    sender: S,
    receiver: R,
) -> (WrappedSender<S, VC, V>, WrappedReceiver<R, VC, V>) {
    (
        WrappedSender::new(sender),
        WrappedReceiver::new(config, receiver),
    )
}

/// Tuple representing a message received from a given public key.
pub type WrappedMessage<P, V> = (P, Result<V, Error>);

/// Wrapper around a [Sender] that encodes messages using a [Codec].
pub struct WrappedSender<S: Sender, VC: Config, V: Codec<VC>> {
    sender: S,

    _phantom_vc: std::marker::PhantomData<VC>,
    _phantom_v: std::marker::PhantomData<V>,
}

impl<S: Sender, VC: Config, V: Codec<VC>> WrappedSender<S, VC, V> {
    /// Create a new [WrappedSender] with the given [Sender].
    pub fn new(sender: S) -> Self {
        Self {
            sender,
            _phantom_vc: std::marker::PhantomData,
            _phantom_v: std::marker::PhantomData,
        }
    }

    /// Send a message to a set of recipients.
    pub async fn send(
        &mut self,
        recipients: Recipients<S::PublicKey>,
        message: V,
        priority: bool,
    ) -> Result<Vec<S::PublicKey>, S::Error> {
        let encoded = message.encode();
        self.sender
            .send(recipients, Bytes::from(encoded), priority)
            .await
    }
}

/// Wrapper around a [Receiver] that decodes messages using a [Codec].
pub struct WrappedReceiver<R: Receiver, VC: Config, V: Codec<VC>> {
    config: VC,
    receiver: R,

    _phantom_v: std::marker::PhantomData<V>,
}

impl<R: Receiver, VC: Config, V: Codec<VC>> WrappedReceiver<R, VC, V> {
    /// Create a new [WrappedReceiver] with the given [Receiver].
    pub fn new(config: VC, receiver: R) -> Self {
        Self {
            config,
            receiver,
            _phantom_v: std::marker::PhantomData,
        }
    }

    /// Receive a message from an arbitrary recipient.
    pub async fn recv(&mut self) -> Result<WrappedMessage<R::PublicKey, V>, R::Error> {
        let (pk, bytes) = self.receiver.recv().await?;
        let decoded = match V::decode_cfg(bytes.as_ref(), &self.config) {
            Ok(decoded) => decoded,
            Err(e) => {
                return Ok((pk, Err(e)));
            }
        };
        Ok((pk, Ok(decoded)))
    }
}
