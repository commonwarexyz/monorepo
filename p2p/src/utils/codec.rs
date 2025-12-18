//! Codec wrapper for [Sender] and [Receiver].

use crate::{CheckedSender, Receiver, Recipients, Sender};
use commonware_codec::{Codec, Error};
use std::time::SystemTime;

/// Wrap a [Sender] and [Receiver] with some [Codec].
pub const fn wrap<S: Sender, R: Receiver, V: Codec>(
    config: V::Cfg,
    sender: S,
    receiver: R,
) -> (WrappedSender<S, V>, WrappedReceiver<R, V>) {
    (
        WrappedSender::new(sender),
        WrappedReceiver::new(config, receiver),
    )
}

/// Tuple representing a message received from a given public key.
pub type WrappedMessage<P, V> = (P, Result<V, Error>);

/// Wrapper around a [Sender] that encodes messages using a [Codec].
#[derive(Clone)]
pub struct WrappedSender<S: Sender, V: Codec> {
    sender: S,
    _phantom_v: std::marker::PhantomData<V>,
}

impl<S: Sender, V: Codec> WrappedSender<S, V> {
    /// Create a new [WrappedSender] with the given [Sender].
    pub const fn new(sender: S) -> Self {
        Self {
            sender,
            _phantom_v: std::marker::PhantomData,
        }
    }

    /// Send a message to a set of recipients.
    pub async fn send(
        &mut self,
        recipients: Recipients<S::PublicKey>,
        message: V,
        priority: bool,
    ) -> Result<Vec<S::PublicKey>, <S::Checked<'_> as CheckedSender>::Error> {
        let encoded = message.encode();
        self.sender
            .send(recipients, encoded.freeze(), priority)
            .await
    }

    /// Check if a message can be sent to a set of recipients, returning a [CheckedWrappedSender]
    /// or the time at which the send can be retried.
    pub async fn check(
        &mut self,
        recipients: Recipients<S::PublicKey>,
    ) -> Result<CheckedWrappedSender<'_, S, V>, SystemTime> {
        self.sender
            .check(recipients)
            .await
            .map(|checked| CheckedWrappedSender {
                sender: checked,
                _phantom_v: std::marker::PhantomData,
            })
    }
}

#[derive(Debug)]
pub struct CheckedWrappedSender<'a, S: Sender, V: Codec> {
    sender: S::Checked<'a>,
    _phantom_v: std::marker::PhantomData<V>,
}

impl<'a, S: Sender, V: Codec> CheckedWrappedSender<'a, S, V> {
    pub async fn send(
        self,
        message: V,
        priority: bool,
    ) -> Result<Vec<S::PublicKey>, <S::Checked<'a> as CheckedSender>::Error> {
        let encoded = message.encode();
        self.sender.send(encoded.freeze(), priority).await
    }
}

/// Wrapper around a [Receiver] that decodes messages using a [Codec].
pub struct WrappedReceiver<R: Receiver, V: Codec> {
    config: V::Cfg,
    receiver: R,
    _phantom_v: std::marker::PhantomData<V>,
}

impl<R: Receiver, V: Codec> WrappedReceiver<R, V> {
    /// Create a new [WrappedReceiver] with the given [Receiver].
    pub const fn new(config: V::Cfg, receiver: R) -> Self {
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
