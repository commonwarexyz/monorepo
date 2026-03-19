use commonware_cryptography::ed25519::PublicKey;
use commonware_p2p::{CheckedSender, LimitedSender, Message, Receiver, Recipients};
use commonware_runtime::{IoBuf, IoBufs};
use commonware_utils::channel::mpsc;
use std::{
    error::Error as StdError,
    fmt,
    future::{self, Future},
    time::SystemTime,
};

/// Error returned by [`InjectedReceiver`] when the channel is closed.
#[derive(Debug)]
pub struct ChannelClosed;

impl fmt::Display for ChannelClosed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "injected channel closed")
    }
}

impl StdError for ChannelClosed {}

/// Receives messages injected externally via an [`Injector`].
#[derive(Debug)]
pub struct InjectedReceiver {
    rx: mpsc::UnboundedReceiver<(PublicKey, IoBuf)>,
}

impl Receiver for InjectedReceiver {
    type Error = ChannelClosed;
    type PublicKey = PublicKey;

    async fn recv(&mut self) -> Result<Message<Self::PublicKey>, Self::Error> {
        self.rx.recv().await.ok_or(ChannelClosed)
    }
}

/// Injects messages into a paired [`InjectedReceiver`].
#[derive(Clone)]
pub struct Injector {
    tx: mpsc::UnboundedSender<(PublicKey, IoBuf)>,
}

impl Injector {
    pub fn inject(&self, sender: PublicKey, payload: IoBuf) {
        let _ = self.tx.send((sender, payload));
    }
}

/// Creates a paired (Injector, InjectedReceiver).
pub fn channel() -> (Injector, InjectedReceiver) {
    let (tx, rx) = mpsc::unbounded_channel();
    (Injector { tx }, InjectedReceiver { rx })
}

/// Error type for [`NullSender`] (never actually returned).
#[derive(Debug)]
pub struct NullSendError;

impl fmt::Display for NullSendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "null send")
    }
}

impl StdError for NullSendError {}

/// A checked sender that silently drops all messages.
pub struct NullCheckedSender;

impl CheckedSender for NullCheckedSender {
    type PublicKey = PublicKey;
    type Error = NullSendError;

    fn send(
        self,
        _message: impl Into<IoBufs> + Send,
        _priority: bool,
    ) -> impl Future<Output = Result<Vec<Self::PublicKey>, Self::Error>> + Send {
        future::ready(Ok(Vec::new()))
    }
}

/// A sender that silently drops all outgoing messages.
#[derive(Clone, Debug)]
pub struct NullSender;

impl LimitedSender for NullSender {
    type PublicKey = PublicKey;
    type Checked<'a> = NullCheckedSender;

    fn check<'a>(
        &'a mut self,
        _recipients: Recipients<Self::PublicKey>,
    ) -> impl Future<Output = Result<Self::Checked<'a>, SystemTime>> + Send {
        future::ready(Ok(NullCheckedSender))
    }
}

/// A receiver that never returns a message (blocks forever).
#[derive(Debug)]
pub struct PendingReceiver;

impl Receiver for PendingReceiver {
    type Error = ChannelClosed;
    type PublicKey = PublicKey;

    fn recv(
        &mut self,
    ) -> impl Future<Output = Result<Message<Self::PublicKey>, Self::Error>> + Send {
        future::pending()
    }
}

/// A blocker that does nothing when asked to block a peer.
#[derive(Clone, Debug)]
pub struct NullBlocker;

impl commonware_p2p::Blocker for NullBlocker {
    type PublicKey = PublicKey;

    fn block(&mut self, _peer: Self::PublicKey) -> impl Future<Output = ()> + Send {
        future::ready(())
    }
}
