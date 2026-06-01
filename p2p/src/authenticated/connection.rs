use crate::ChannelEncryption;
use commonware_cryptography::Signer;
use commonware_runtime::{BufferPooler, Clock, IoBufs, Sink, Stream};
use commonware_stream::encrypted::{
    self, Frame, Protection, Receiver as EncryptedReceiver, Sender as EncryptedSender,
    SessionReceiver, SessionSender,
};
use rand_core::CryptoRngCore;
use std::future::Future;

/// Sends p2p frames over either the legacy encrypted stream or the mixed stream.
pub enum Sender<O> {
    Encrypted(EncryptedSender<O>),
    Mixed(SessionSender<O>),
}

/// Receives p2p frames over either the legacy encrypted stream or the mixed stream.
pub enum Receiver<I> {
    Encrypted(EncryptedReceiver<I>),
    Mixed(SessionReceiver<I>),
}

impl<O> From<EncryptedSender<O>> for Sender<O> {
    fn from(sender: EncryptedSender<O>) -> Self {
        Self::Encrypted(sender)
    }
}

impl<I> From<EncryptedReceiver<I>> for Receiver<I> {
    fn from(receiver: EncryptedReceiver<I>) -> Self {
        Self::Encrypted(receiver)
    }
}

const fn protection(encryption: ChannelEncryption) -> Protection {
    match encryption {
        ChannelEncryption::Encrypted => Protection::Encrypted,
        ChannelEncryption::Plaintext => Protection::Authenticated,
    }
}

const fn encryption(protection: Protection) -> ChannelEncryption {
    match protection {
        Protection::Encrypted => ChannelEncryption::Encrypted,
        Protection::Authenticated => ChannelEncryption::Plaintext,
    }
}

impl<O: Sink> Sender<O> {
    /// Sends one p2p frame.
    pub(crate) async fn send(
        &mut self,
        encryption: ChannelEncryption,
        payload: impl Into<IoBufs>,
    ) -> Result<(), encrypted::Error> {
        self.send_many(std::iter::once((encryption, payload.into())))
            .await
    }

    /// Sends multiple p2p frames.
    pub(crate) async fn send_many<I>(&mut self, frames: I) -> Result<(), encrypted::Error>
    where
        I: IntoIterator<Item = (ChannelEncryption, IoBufs)>,
    {
        match self {
            Self::Encrypted(sender) => {
                sender
                    .send_many(frames.into_iter().map(|(_, payload)| payload))
                    .await
            }
            Self::Mixed(sender) => {
                sender
                    .send_many_protected(
                        frames
                            .into_iter()
                            .map(|(encryption, payload)| (protection(encryption), payload)),
                    )
                    .await
            }
        }
    }
}

impl<I: Stream> Receiver<I> {
    /// Receives one p2p frame.
    pub(crate) async fn recv(&mut self) -> Result<(ChannelEncryption, IoBufs), encrypted::Error> {
        match self {
            Self::Encrypted(receiver) => receiver
                .recv()
                .await
                .map(|payload| (ChannelEncryption::Encrypted, payload)),
            Self::Mixed(receiver) => {
                let Frame {
                    protection,
                    payload,
                } = receiver.recv_protected().await?;
                Ok((encryption(protection), payload))
            }
        }
    }
}

/// Establishes a p2p connection to a peer.
pub(crate) async fn dial<R, S, I, O>(
    ctx: R,
    config: encrypted::Config<S>,
    peer: S::PublicKey,
    stream: I,
    sink: O,
    mixed: bool,
) -> Result<(Sender<O>, Receiver<I>), encrypted::Error>
where
    R: BufferPooler + CryptoRngCore + Clock,
    S: Signer,
    I: Stream,
    O: Sink,
{
    if mixed {
        let (sender, receiver) = encrypted::dial_session(ctx, config, peer, stream, sink).await?;
        return Ok((Sender::Mixed(sender), Receiver::Mixed(receiver)));
    }

    let (sender, receiver) = encrypted::dial(ctx, config, peer, stream, sink).await?;
    Ok((Sender::Encrypted(sender), Receiver::Encrypted(receiver)))
}

/// Accepts a p2p connection from a peer.
pub(crate) async fn listen<R, S, I, O, Fut, F>(
    ctx: R,
    bouncer: F,
    config: encrypted::Config<S>,
    stream: I,
    sink: O,
    mixed: bool,
) -> Result<(S::PublicKey, Sender<O>, Receiver<I>), encrypted::Error>
where
    R: BufferPooler + CryptoRngCore + Clock,
    S: Signer,
    I: Stream,
    O: Sink,
    Fut: Future<Output = bool>,
    F: FnOnce(S::PublicKey) -> Fut,
{
    if mixed {
        let (peer, sender, receiver) =
            encrypted::listen_session(ctx, bouncer, config, stream, sink).await?;
        return Ok((peer, Sender::Mixed(sender), Receiver::Mixed(receiver)));
    }

    let (peer, sender, receiver) = encrypted::listen(ctx, bouncer, config, stream, sink).await?;
    Ok((
        peer,
        Sender::Encrypted(sender),
        Receiver::Encrypted(receiver),
    ))
}
