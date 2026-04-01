use super::Error;
use crate::{
    authenticated::primary::PrimaryPeers,
    authenticated::lookup::actors::router::{self, Messenger},
    utils::limited::{CheckedSender, LimitedSender},
    Channel, Message, Recipients,
};
use commonware_cryptography::PublicKey;
use commonware_runtime::{Clock, IoBufs, Quota};
use commonware_utils::channel::mpsc::{self, error::TrySendError};
use std::{
    collections::{BTreeMap, VecDeque},
    fmt::Debug,
    time::SystemTime,
};

/// An interior sender that enforces message size limits and
/// supports sending arbitrary bytes to a set of recipients over
/// a pre-defined [`Channel`].
#[derive(Debug, Clone)]
pub struct UnlimitedSender<P: PublicKey> {
    channel: Channel,
    max_size: u32,
    messenger: Messenger<P>,
}

impl<P: PublicKey> crate::UnlimitedSender for UnlimitedSender<P> {
    type Error = Error;
    type PublicKey = P;

    async fn send(
        &mut self,
        recipients: Recipients<Self::PublicKey>,
        message: impl Into<IoBufs> + Send,
        priority: bool,
    ) -> Result<Vec<Self::PublicKey>, Self::Error> {
        let message = message.into();
        if message.len() > self.max_size as usize {
            return Err(Error::MessageTooLarge(message.len()));
        }

        Ok(self
            .messenger
            .content(recipients, self.channel, message, priority)
            .await)
    }
}

/// Sender is the mechanism used to send arbitrary bytes to a set of recipients over a pre-defined channel.
#[derive(Clone)]
pub struct Sender<P: PublicKey, C: Clock> {
    limited_sender: LimitedSender<C, UnlimitedSender<P>, Messenger<P>>,
}

impl<P: PublicKey, C: Clock> Sender<P, C> {
    pub(super) fn new(
        channel: Channel,
        max_size: u32,
        messenger: Messenger<P>,
        clock: C,
        quota: Quota,
    ) -> Self {
        let master_sender = UnlimitedSender {
            channel,
            max_size,
            messenger: messenger.clone(),
        };
        let limited_sender = LimitedSender::new(master_sender, quota, clock, messenger);
        Self { limited_sender }
    }
}

impl<P, C> crate::LimitedSender for Sender<P, C>
where
    P: PublicKey,
    C: Clock + Clone + Send + 'static,
{
    type PublicKey = P;
    type Checked<'a>
        = CheckedSender<'a, UnlimitedSender<P>>
    where
        Self: 'a;

    async fn check(
        &mut self,
        recipients: Recipients<Self::PublicKey>,
    ) -> Result<Self::Checked<'_>, SystemTime> {
        self.limited_sender.check(recipients).await
    }
}

/// Channel to asynchronously receive messages from a channel.
#[derive(Clone, Debug)]
pub(crate) struct PrioritizedSender<P: PublicKey> {
    sender: mpsc::Sender<Message<P>>,
}

impl<P: PublicKey> PrioritizedSender<P> {
    pub(crate) fn try_send(&self, message: Message<P>) -> Result<(), TrySendError<Message<P>>> {
        self.sender.try_send(message)
    }
}

#[derive(Debug)]
pub struct Receiver<P: PublicKey> {
    receiver: mpsc::Receiver<Message<P>>,
    primary_peers: PrimaryPeers<P>,
    buffered: BTreeMap<P, VecDeque<(u64, crate::IoBuf)>>,
    next_sequence: u64,
}

impl<P: PublicKey> Receiver<P> {
    pub(super) fn new(receiver: mpsc::Receiver<Message<P>>, primary_peers: PrimaryPeers<P>) -> Self {
        Self {
            receiver,
            primary_peers,
            buffered: BTreeMap::new(),
            next_sequence: 0,
        }
    }

    fn buffer(&mut self, message: Message<P>) {
        let (peer, message) = message;
        self.buffered
            .entry(peer)
            .or_default()
            .push_back((self.next_sequence, message));
        self.next_sequence += 1;
    }

    fn head_peer(&self, primary_only: bool) -> Option<P> {
        self.buffered
            .iter()
            .filter_map(|(peer, queue)| {
                let (sequence, _) = queue.front()?;
                let is_primary = self.primary_peers.contains(peer);
                if primary_only && !is_primary {
                    return None;
                }
                Some((*sequence, peer.clone()))
            })
            .min_by_key(|(sequence, _)| *sequence)
            .map(|(_, peer)| peer)
    }

    fn pop_buffered(&mut self, peer: P) -> Message<P> {
        let mut queue = self
            .buffered
            .remove(&peer)
            .expect("selected peer must have buffered messages");
        let (_, message) = queue
            .pop_front()
            .expect("selected peer must have a buffered head message");
        if !queue.is_empty() {
            self.buffered.insert(peer.clone(), queue);
        }
        (peer, message)
    }
}

impl<P: PublicKey> crate::Receiver for Receiver<P> {
    type Error = Error;
    type PublicKey = P;

    /// Receives a message from the channel.
    ///
    /// This method will block until a message is received or the underlying
    /// network shuts down.
    async fn recv(&mut self) -> Result<Message<Self::PublicKey>, Error> {
        loop {
            while let Ok(message) = self.receiver.try_recv() {
                self.buffer(message);
            }

            if let Some(peer) = self.head_peer(true).or_else(|| self.head_peer(false)) {
                return Ok(self.pop_buffered(peer));
            }

            let Some(message) = self.receiver.recv().await else {
                return Err(Error::NetworkClosed);
            };
            self.buffer(message);
        }
    }
}

#[derive(Clone, Debug)]
pub struct Channels<P: PublicKey> {
    messenger: router::Messenger<P>,
    max_size: u32,
    primary_peers: PrimaryPeers<P>,
    receivers: BTreeMap<Channel, (Quota, PrioritizedSender<P>)>,
}

impl<P: PublicKey> Channels<P> {
    pub fn new(messenger: router::Messenger<P>, max_size: u32) -> Self {
        Self::with_primary_peers(messenger, max_size, PrimaryPeers::default())
    }

    pub(super) const fn with_primary_peers(
        messenger: router::Messenger<P>,
        max_size: u32,
        primary_peers: PrimaryPeers<P>,
    ) -> Self {
        Self {
            messenger,
            max_size,
            primary_peers,
            receivers: BTreeMap::new(),
        }
    }

    pub(super) fn primary_peers(&self) -> PrimaryPeers<P> {
        self.primary_peers.clone()
    }

    pub fn register<C: Clock>(
        &mut self,
        channel: Channel,
        rate: Quota,
        backlog: usize,
        clock: C,
    ) -> (Sender<P, C>, Receiver<P>) {
        let (receiver_tx, receiver_rx) = mpsc::channel(backlog);
        let sender = PrioritizedSender { sender: receiver_tx };
        if self.receivers.insert(channel, (rate, sender)).is_some() {
            panic!("duplicate channel registration: {channel}");
        }
        (
            Sender::new(channel, self.max_size, self.messenger.clone(), clock, rate),
            Receiver::new(receiver_rx, self.primary_peers.clone()),
        )
    }

    pub(crate) fn collect(self) -> BTreeMap<u64, (Quota, PrioritizedSender<P>)> {
        self.receivers
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{authenticated::{lookup::actors::router, Mailbox}, Receiver as _};
    use commonware_cryptography::{ed25519, Signer as _};
    use commonware_runtime::{deterministic, BufferPooler, IoBuf, Quota, Runner};
    use commonware_utils::{ordered::Set, NZU32};

    #[test]
    fn test_receiver_prioritizes_live_primary_peers() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (router_mailbox, _router_receiver) = Mailbox::<router::Message<_>>::new(10);
            let messenger =
                router::Messenger::new(context.network_buffer_pool().clone(), router_mailbox);
            let primary_peers = PrimaryPeers::default();
            let mut channels = Channels::with_primary_peers(messenger, 1024, primary_peers.clone());
            let (_sender, mut receiver) = channels.register(
                0,
                Quota::per_second(NZU32!(100)),
                1,
                context.clone(),
            );
            let (_, sender) = channels.collect().remove(&0).unwrap();
            let secondary_peer = ed25519::PrivateKey::from_seed(1).public_key();
            let primary_peer = ed25519::PrivateKey::from_seed(2).public_key();

            sender
                .try_send((secondary_peer, IoBuf::from(b"secondary")))
                .unwrap();
            primary_peers.replace(Set::try_from([primary_peer.clone()]).unwrap());
            sender
                .try_send((primary_peer, IoBuf::from(b"primary")))
                .unwrap();

            let (_, first) = receiver.recv().await.unwrap();
            assert_eq!(first.as_ref(), b"primary");
            let (_, second) = receiver.recv().await.unwrap();
            assert_eq!(second.as_ref(), b"secondary");
        });
    }

    #[test]
    fn test_receiver_preserves_fifo_when_peer_priority_changes() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (router_mailbox, _router_receiver) = Mailbox::<router::Message<_>>::new(10);
            let messenger =
                router::Messenger::new(context.network_buffer_pool().clone(), router_mailbox);
            let primary_peers = PrimaryPeers::default();
            let mut channels = Channels::with_primary_peers(messenger, 1024, primary_peers.clone());
            let (_sender, mut receiver) = channels.register(
                0,
                Quota::per_second(NZU32!(100)),
                1,
                context.clone(),
            );
            let (_, sender) = channels.collect().remove(&0).unwrap();
            let peer = ed25519::PrivateKey::from_seed(3).public_key();

            sender
                .try_send((peer.clone(), IoBuf::from(b"first")))
                .unwrap();
            primary_peers.replace(Set::try_from([peer.clone()]).unwrap());
            sender.try_send((peer, IoBuf::from(b"second"))).unwrap();

            let (_, first) = receiver.recv().await.unwrap();
            assert_eq!(first.as_ref(), b"first");
            let (_, second) = receiver.recv().await.unwrap();
            assert_eq!(second.as_ref(), b"second");
        });
    }
}
