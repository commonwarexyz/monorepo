use crate::{
    authenticated::primary::PrimaryPeers,
    utils::limited::{CheckedSender, Connected, LimitedSender},
    Channel, Message, Recipients,
};
use commonware_cryptography::PublicKey;
use commonware_runtime::{Clock, IoBufs, Quota};
use commonware_utils::channel::mpsc::{self, error::TrySendError};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    fmt::Debug,
    time::SystemTime,
};
use thiserror::Error as ThisError;

/// Errors that can occur when interacting with the network.
#[derive(ThisError, Debug)]
pub enum Error {
    #[error("message too large: {0}")]
    MessageTooLarge(usize),
    #[error("network closed")]
    NetworkClosed,
}

/// Trait abstracting the ability to route content to peers.
///
/// Both `discovery` and `lookup` provide concrete implementations.
pub trait ContentRouter: Connected + Debug {
    fn content(
        &mut self,
        recipients: Recipients<Self::PublicKey>,
        channel: Channel,
        message: IoBufs,
        priority: bool,
    ) -> impl std::future::Future<Output = Vec<Self::PublicKey>> + Send;
}

/// An interior sender that enforces message size limits and
/// supports sending arbitrary bytes to a set of recipients over
/// a pre-defined [`Channel`].
#[derive(Debug, Clone)]
pub struct UnlimitedSender<M: ContentRouter> {
    channel: Channel,
    max_size: u32,
    messenger: M,
}

impl<M: ContentRouter> crate::UnlimitedSender for UnlimitedSender<M> {
    type PublicKey = M::PublicKey;
    type Error = Error;

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
pub struct Sender<M: ContentRouter, C: Clock> {
    limited_sender: LimitedSender<C, UnlimitedSender<M>, M>,
}

impl<M: ContentRouter, C: Clock> Sender<M, C> {
    pub(in crate::authenticated) fn new(
        channel: Channel,
        max_size: u32,
        messenger: M,
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

impl<M, C> crate::LimitedSender for Sender<M, C>
where
    M: ContentRouter,
    C: Clock + Clone + Send + 'static,
{
    type PublicKey = M::PublicKey;
    type Checked<'a>
        = CheckedSender<'a, UnlimitedSender<M>>
    where
        Self: 'a;

    async fn check(
        &mut self,
        recipients: Recipients<Self::PublicKey>,
    ) -> Result<Self::Checked<'_>, SystemTime> {
        self.limited_sender.check(recipients).await
    }
}

/// Sender half of a channel whose [`Receiver`] prioritizes primary peers.
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
struct BufferedPeer {
    is_primary: bool,
    messages: VecDeque<(u64, crate::IoBuf)>,
}

#[derive(Debug)]
pub struct Receiver<P: PublicKey> {
    receiver: mpsc::Receiver<Message<P>>,
    primary_peers: PrimaryPeers<P>,
    buffered: BTreeMap<P, BufferedPeer>,
    primary_ready: BTreeSet<(u64, P)>,
    secondary_ready: BTreeSet<(u64, P)>,
    next_sequence: u64,
    primary_generation: u64,
}

impl<P: PublicKey> Receiver<P> {
    pub(in crate::authenticated) fn new(
        receiver: mpsc::Receiver<Message<P>>,
        primary_peers: PrimaryPeers<P>,
    ) -> Self {
        Self {
            receiver,
            primary_generation: primary_peers.generation(),
            primary_peers,
            buffered: BTreeMap::new(),
            primary_ready: BTreeSet::new(),
            secondary_ready: BTreeSet::new(),
            next_sequence: 0,
        }
    }

    fn buffer(&mut self, message: Message<P>) {
        let (peer, message) = message;
        let sequence = self.next_sequence;
        self.next_sequence += 1;
        if let Some(entry) = self.buffered.get_mut(&peer) {
            entry.messages.push_back((sequence, message));
            return;
        }
        let is_primary = self.primary_peers.contains(&peer);
        let ready = if is_primary {
            &mut self.primary_ready
        } else {
            &mut self.secondary_ready
        };
        ready.insert((sequence, peer.clone()));
        self.buffered.insert(
            peer,
            BufferedPeer {
                is_primary,
                messages: VecDeque::from([(sequence, message)]),
            },
        );
    }

    fn refresh_priorities(&mut self) {
        let generation = self.primary_peers.generation();
        if generation == self.primary_generation {
            return;
        }
        self.primary_generation = generation;

        let updates: Vec<_> = self
            .buffered
            .iter_mut()
            .filter_map(|(peer, state)| {
                let is_primary = self.primary_peers.contains(peer);
                if is_primary == state.is_primary {
                    return None;
                }
                let sequence = state
                    .messages
                    .front()
                    .expect("buffered peers must have a head message")
                    .0;
                let previous = state.is_primary;
                state.is_primary = is_primary;
                Some((sequence, peer.clone(), previous, is_primary))
            })
            .collect();

        for (sequence, peer, previous, is_primary) in updates {
            let key = (sequence, peer.clone());
            if previous {
                self.primary_ready.remove(&key);
            } else {
                self.secondary_ready.remove(&key);
            }
            if is_primary {
                self.primary_ready.insert(key);
            } else {
                self.secondary_ready.insert(key);
            }
        }
    }

    fn pop_ready(&mut self, primary: bool) -> Option<Message<P>> {
        let (_, peer) = if primary {
            self.primary_ready.pop_first()
        } else {
            self.secondary_ready.pop_first()
        }?;
        let mut state = self
            .buffered
            .remove(&peer)
            .expect("selected peer must have buffered messages");
        let (_, message) = state
            .messages
            .pop_front()
            .expect("selected peer must have a buffered head message");
        if let Some((sequence, _)) = state.messages.front() {
            let key = (*sequence, peer.clone());
            if state.is_primary {
                self.primary_ready.insert(key);
            } else {
                self.secondary_ready.insert(key);
            }
            self.buffered.insert(peer.clone(), state);
        }
        Some((peer, message))
    }
}

impl<P: PublicKey> crate::Receiver for Receiver<P> {
    type Error = Error;
    type PublicKey = P;

    async fn recv(&mut self) -> Result<Message<Self::PublicKey>, Error> {
        loop {
            while let Ok(message) = self.receiver.try_recv() {
                self.buffer(message);
            }

            self.refresh_priorities();

            if let Some(message) = self.pop_ready(true).or_else(|| self.pop_ready(false)) {
                return Ok(message);
            }

            let Some(message) = self.receiver.recv().await else {
                return Err(Error::NetworkClosed);
            };
            self.buffer(message);
        }
    }
}

#[derive(Clone, Debug)]
pub struct Channels<M: ContentRouter> {
    messenger: M,
    max_size: u32,
    primary_peers: PrimaryPeers<M::PublicKey>,
    receivers: BTreeMap<Channel, (Quota, PrioritizedSender<M::PublicKey>)>,
}

impl<M: ContentRouter> Channels<M> {
    pub fn new(messenger: M, max_size: u32) -> Self {
        Self::with_primary_peers(messenger, max_size, PrimaryPeers::default())
    }

    pub(in crate::authenticated) const fn with_primary_peers(
        messenger: M,
        max_size: u32,
        primary_peers: PrimaryPeers<M::PublicKey>,
    ) -> Self {
        Self {
            messenger,
            max_size,
            primary_peers,
            receivers: BTreeMap::new(),
        }
    }

    pub(in crate::authenticated) fn primary_peers(&self) -> PrimaryPeers<M::PublicKey> {
        self.primary_peers.clone()
    }

    pub fn register<C: Clock>(
        &mut self,
        channel: Channel,
        rate: Quota,
        backlog: usize,
        clock: C,
    ) -> (Sender<M, C>, Receiver<M::PublicKey>) {
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

    pub(crate) fn collect(self) -> BTreeMap<u64, (Quota, PrioritizedSender<M::PublicKey>)> {
        self.receivers
    }
}

