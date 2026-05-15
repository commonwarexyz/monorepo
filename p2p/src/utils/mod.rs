//! Utility functions for exchanging messages with many peers.

use crate::{PeerSetUpdate, Provider, TrackedPeers};
use commonware_actor::{mailbox, Feedback};
use commonware_cryptography::PublicKey;
use commonware_utils::{
    channel::{
        fallible::FallibleExt,
        mpsc::{self, UnboundedReceiver, UnboundedSender},
        oneshot,
    },
    ordered::Set,
};

pub mod codec;
pub mod limited;
#[cfg(feature = "mocks")]
pub mod mocks;
pub mod mux;

/// Submit a message to a mailbox and return the enqueue feedback.
pub(crate) fn mailbox_enqueue<T: mailbox::Policy>(
    sender: &mailbox::Sender<T>,
    message: T,
) -> Feedback {
    sender.enqueue(message)
}

/// Send a request message to a mailbox and await a one-shot response.
pub(crate) async fn mailbox_request<T, R, F>(sender: &mailbox::Sender<T>, make_msg: F) -> Option<R>
where
    T: mailbox::Policy,
    R: Send,
    F: FnOnce(oneshot::Sender<R>) -> T + Send,
{
    let (tx, rx) = oneshot::channel();
    let _ = sender.enqueue(make_msg(tx));
    rx.await.ok()
}

/// Send a mailbox request and return `default` if no response is received.
pub(crate) async fn mailbox_request_or<T, R, F>(
    sender: &mailbox::Sender<T>,
    make_msg: F,
    default: R,
) -> R
where
    T: mailbox::Policy,
    R: Send,
    F: FnOnce(oneshot::Sender<R>) -> T + Send,
{
    mailbox_request(sender, make_msg).await.unwrap_or(default)
}

/// Send a mailbox request and return `R::default()` if no response is received.
pub(crate) async fn mailbox_request_or_default<T, R, F>(
    sender: &mailbox::Sender<T>,
    make_msg: F,
) -> R
where
    T: mailbox::Policy,
    R: Default + Send,
    F: FnOnce(oneshot::Sender<R>) -> T + Send,
{
    mailbox_request(sender, make_msg).await.unwrap_or_default()
}

/// Primary and secondary peer memberships at one peer set index.
///
/// Import as `PeerSetsAtIndexBase` (or similar) and define a local
/// `type PeerSetsAtIndex<P> = PeerSetsAtIndexBase<...>` with the primary/secondary types you use.
pub(crate) struct PeerSetsAtIndex<Primary, Secondary> {
    pub(crate) primary: Primary,
    pub(crate) secondary: Secondary,
}

/// A [Provider] over a static set of peers.
#[derive(Debug, Clone)]
pub struct StaticProvider<P: PublicKey> {
    id: u64,
    peers: Set<P>,
    senders: Vec<UnboundedSender<PeerSetUpdate<P>>>,
}

impl<P: PublicKey> StaticProvider<P> {
    /// Create a new [StaticProvider] with the given ID and peers.
    pub const fn new(id: u64, peers: Set<P>) -> Self {
        Self {
            id,
            peers,
            senders: vec![],
        }
    }
}

impl<P: PublicKey> Provider for StaticProvider<P> {
    type PublicKey = P;

    async fn peer_set(&mut self, id: u64) -> Option<TrackedPeers<P>> {
        assert_eq!(id, self.id);
        Some(TrackedPeers::primary(self.peers.clone()))
    }

    async fn subscribe(&mut self) -> UnboundedReceiver<PeerSetUpdate<P>> {
        let (sender, receiver) = mpsc::unbounded_channel();
        sender.send_lossy(PeerSetUpdate {
            index: self.id,
            latest: TrackedPeers::new(self.peers.clone(), Set::default()),
            all: TrackedPeers::new(self.peers.clone(), Set::default()),
        });
        self.senders.push(sender); // prevent the receiver from closing
        receiver
    }
}
