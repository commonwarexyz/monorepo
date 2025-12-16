//! Implementation of a simulated p2p network.

use super::{
    ingress::{self, Oracle},
    metrics,
    transmitter::{self, Completion},
    Error,
};
use crate::{Channel, Message, Recipients};
use bytes::Bytes;
use commonware_codec::{DecodeExt, FixedSize};
use commonware_cryptography::PublicKey;
use commonware_macros::{select, select_loop};
use commonware_runtime::{
    spawn_cell, Clock, ContextCell, Handle, Listener as _, Metrics, Network as RNetwork,
    RateLimiter, Spawner,
};
use commonware_stream::utils::codec::{recv_frame, send_frame};
use commonware_utils::{ordered::Set, TryCollect};
use either::Either;
use futures::{
    channel::{mpsc, oneshot},
    future, SinkExt, StreamExt,
};
use governor::clock::Clock as GClock;
use prometheus_client::metrics::{counter::Counter, family::Family};
use rand::Rng;
use rand_distr::{Distribution, Normal};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fmt::Debug,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::{Duration, SystemTime},
};
use tracing::{debug, error, trace, warn};

/// Task type representing a message to be sent within the network.
type Task<P> = (Channel, P, Recipients<P>, Bytes, oneshot::Sender<Vec<P>>);

/// Target for a message in a split receiver.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub enum SplitTarget {
    None,
    Primary,
    Secondary,
    Both,
}

/// Origin of a message in a split sender.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub enum SplitOrigin {
    Primary,
    Secondary,
}

/// A function that forwards messages from [SplitOrigin] to [Recipients].
pub trait SplitForwarder<P: PublicKey>:
    Fn(SplitOrigin, &Recipients<P>, &Bytes) -> Option<Recipients<P>> + Send + Sync + Clone + 'static
{
}

impl<P: PublicKey, F> SplitForwarder<P> for F where
    F: Fn(SplitOrigin, &Recipients<P>, &Bytes) -> Option<Recipients<P>>
        + Send
        + Sync
        + Clone
        + 'static
{
}

/// A function that routes incoming [Message]s to a [SplitTarget].
pub trait SplitRouter<P: PublicKey>:
    Fn(&Message<P>) -> SplitTarget + Send + Sync + 'static
{
}

impl<P: PublicKey, F> SplitRouter<P> for F where
    F: Fn(&Message<P>) -> SplitTarget + Send + Sync + 'static
{
}

/// Configuration for the simulated network.
pub struct Config {
    /// Maximum size of a message that can be sent over the network.
    pub max_size: usize,

    /// True if peers should disconnect upon being blocked. While production networking would
    /// typically disconnect, for testing purposes it may be useful to keep peers connected,
    /// allowing byzantine actors the ability to continue sending messages.
    pub disconnect_on_block: bool,

    /// The maximum number of peer sets to track. When a new peer set is registered and this
    /// limit is exceeded, the oldest peer set is removed. Peers that are no longer in any
    /// tracked peer set will have their links removed and messages to them will be dropped.
    ///
    /// If [None], peer sets are not considered.
    pub tracked_peer_sets: Option<usize>,
}

/// Implementation of a simulated network.
pub struct Network<E: RNetwork + Spawner + Rng + Clock + GClock + Metrics, P: PublicKey> {
    context: ContextCell<E>,

    // Maximum size of a message that can be sent over the network
    max_size: usize,

    // True if peers should disconnect upon being blocked.
    // While production networking would typically disconnect, for testing purposes it may be useful
    // to keep peers connected, allowing byzantine actors the ability to continue sending messages.
    disconnect_on_block: bool,

    // Next socket address to assign to a new peer
    // Incremented for each new peer
    next_addr: SocketAddr,

    // Channel to receive messages from the oracle
    ingress: mpsc::UnboundedReceiver<ingress::Message<P>>,

    // A channel to receive tasks from peers
    // The sender is cloned and given to each peer
    // The receiver is polled in the main loop
    sender: mpsc::UnboundedSender<Task<P>>,
    receiver: mpsc::UnboundedReceiver<Task<P>>,

    // A map from a pair of public keys (from, to) to a link between the two peers
    links: HashMap<(P, P), Link>,

    // A map from a public key to a peer
    peers: BTreeMap<P, Peer<P>>,

    // Peer sets indexed by their ID
    peer_sets: BTreeMap<u64, Set<P>>,

    // Reference count for each peer (number of peer sets they belong to)
    peer_refs: BTreeMap<P, usize>,

    // Maximum number of peer sets to track
    tracked_peer_sets: Option<usize>,

    // A map of peers blocking each other
    blocks: HashSet<(P, P)>,

    // State of the transmitter
    transmitter: transmitter::State<P>,

    // Subscribers to peer set updates (used by Manager::subscribe())
    #[allow(clippy::type_complexity)]
    subscribers: Vec<mpsc::UnboundedSender<(u64, Set<P>, Set<P>)>>,

    // Rate limiters for each (sender, channel) pair
    rate_limiters: HashMap<(P, Channel), RateLimiter<P, E>>,

    // Metrics for received and sent messages
    received_messages: Family<metrics::Message, Counter>,
    sent_messages: Family<metrics::Message, Counter>,
}

impl<E: RNetwork + Spawner + Rng + Clock + GClock + Metrics, P: PublicKey> Network<E, P> {
    /// Create a new simulated network with a given runtime and configuration.
    ///
    /// Returns a tuple containing the network instance and the oracle that can
    /// be used to modify the state of the network during context.
    pub fn new(mut context: E, cfg: Config) -> (Self, Oracle<P>) {
        let (sender, receiver) = mpsc::unbounded();
        let (oracle_sender, oracle_receiver) = mpsc::unbounded();
        let sent_messages = Family::<metrics::Message, Counter>::default();
        let received_messages = Family::<metrics::Message, Counter>::default();
        context.register("messages_sent", "messages sent", sent_messages.clone());
        context.register(
            "messages_received",
            "messages received",
            received_messages.clone(),
        );

        // Start with a pseudo-random IP address to assign sockets to for new peers
        let next_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::from_bits(context.next_u32())), 0);
        (
            Self {
                context: ContextCell::new(context),
                max_size: cfg.max_size,
                disconnect_on_block: cfg.disconnect_on_block,
                tracked_peer_sets: cfg.tracked_peer_sets,
                next_addr,
                ingress: oracle_receiver,
                sender,
                receiver,
                links: HashMap::new(),
                peers: BTreeMap::new(),
                peer_sets: BTreeMap::new(),
                peer_refs: BTreeMap::new(),
                blocks: HashSet::new(),
                transmitter: transmitter::State::new(),
                subscribers: Vec::new(),
                rate_limiters: HashMap::new(),
                received_messages,
                sent_messages,
            },
            Oracle::new(oracle_sender),
        )
    }

    /// Returns (and increments) the next available socket address.
    ///
    /// The port number is incremented for each call, and the IP address is incremented if the port
    /// number overflows.
    fn get_next_socket(&mut self) -> SocketAddr {
        let result = self.next_addr;

        // Increment the port number, or the IP address if the port number overflows.
        // Allows the ip address to overflow (wrapping).
        match self.next_addr.port().checked_add(1) {
            Some(port) => {
                self.next_addr.set_port(port);
            }
            None => {
                let ip = match self.next_addr.ip() {
                    IpAddr::V4(ipv4) => ipv4,
                    _ => unreachable!(),
                };
                let next_ip = Ipv4Addr::to_bits(ip).wrapping_add(1);
                self.next_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::from_bits(next_ip)), 0);
            }
        }

        result
    }

    /// Handle an ingress message.
    ///
    /// This method is called when a message is received from the oracle.
    async fn handle_ingress(&mut self, message: ingress::Message<P>) {
        // It is important to ensure that no failed receipt of a message will cause us to exit.
        // This could happen if the caller drops the `Oracle` after updating the network topology.
        // Thus, we create a helper function to send the result to the oracle and log any errors.
        fn send_result<T: std::fmt::Debug>(
            result: oneshot::Sender<Result<T, Error>>,
            value: Result<T, Error>,
        ) {
            let success = value.is_ok();
            if let Err(e) = result.send(value) {
                error!(?e, "failed to send result to oracle (ok = {})", success);
            }
        }

        match message {
            ingress::Message::Update { id, peers } => {
                let Some(tracked_peer_sets) = self.tracked_peer_sets else {
                    warn!("attempted to register peer set when tracking is disabled");
                    return;
                };

                // Check if peer set already exists
                if self.peer_sets.contains_key(&id) {
                    warn!(id, "peer set already exists");
                    return;
                }

                // Ensure that peer set is monotonically increasing
                if let Some((last, _)) = self.peer_sets.last_key_value() {
                    if id <= *last {
                        warn!(
                            new_id = id,
                            old_id = last,
                            "attempted to register peer set with non-monotonically increasing ID"
                        );
                        return;
                    }
                }

                // Create and store new peer set
                for public_key in peers.iter() {
                    // Create peer if it doesn't exist
                    self.ensure_peer_exists(public_key).await;

                    // Increment reference count
                    *self.peer_refs.entry(public_key.clone()).or_insert(0) += 1;
                }
                self.peer_sets.insert(id, peers.clone());

                // Remove oldest peer set if we exceed the limit
                while self.peer_sets.len() > tracked_peer_sets {
                    let (id, set) = self.peer_sets.pop_first().unwrap();
                    debug!(id, "removed oldest peer set");

                    // Decrement reference counts and clean up peers/links
                    for public_key in set.iter() {
                        let refs = self.peer_refs.get_mut(public_key).unwrap();
                        *refs = refs.checked_sub(1).expect("reference count underflow");

                        // If peer is no longer in any tracked set, remove it. We explicitly keep the peer around
                        // in `self.peers` to keep its network alive, in-case the peer re-joins in a future peer set.
                        if *refs == 0 {
                            self.peer_refs.remove(public_key);
                            debug!(?public_key, "removed peer no longer in any tracked set");
                        }
                    }
                }

                // Notify all subscribers about the new peer set
                let all = self.all_tracked_peers();
                let notification = (id, peers, all);
                self.subscribers
                    .retain(|subscriber| subscriber.unbounded_send(notification.clone()).is_ok());
            }
            ingress::Message::Register {
                channel,
                public_key,
                quota,
                result,
            } => {
                // If peer does not exist, then create it.
                self.ensure_peer_exists(&public_key).await;

                // Create rate limiter for this (sender, channel) pair
                let clock = self
                    .context
                    .with_label(&format!("rate_limiter_{channel}_{public_key}"))
                    .take();
                let rate_limiter = RateLimiter::hashmap_with_clock(quota, clock);
                self.rate_limiters
                    .insert((public_key.clone(), channel), rate_limiter);

                // Create a sender that allows sending messages to the network for a certain channel
                let (sender, handle) = Sender::new(
                    self.context.with_label("sender"),
                    public_key.clone(),
                    channel,
                    self.max_size,
                    self.sender.clone(),
                );

                // Create a receiver that allows receiving messages from the network for a certain channel
                let peer = self.peers.get_mut(&public_key).unwrap();
                let receiver = match peer.register(channel, handle).await {
                    Ok(receiver) => Receiver { receiver },
                    Err(err) => return send_result(result, Err(err)),
                };

                send_result(result, Ok((sender, receiver)))
            }
            ingress::Message::PeerSet { id, response } => {
                if self.peer_sets.is_empty() {
                    // Return all peers if no peer sets are registered.
                    let _ = response.send(Some(
                        self.peers
                            .keys()
                            .cloned()
                            .try_collect()
                            .expect("BTreeMap keys are unique"),
                    ));
                } else {
                    // Return the peer set at the given index
                    let _ = response.send(self.peer_sets.get(&id).cloned());
                }
            }
            ingress::Message::Subscribe { sender } => {
                // Send the latest peer set upon subscription
                if let Some((index, peers)) = self.peer_sets.last_key_value() {
                    let all = self.all_tracked_peers();
                    let notification = (*index, peers.clone(), all);
                    let _ = sender.unbounded_send(notification);
                }
                self.subscribers.push(sender);
            }
            ingress::Message::LimitBandwidth {
                public_key,
                egress_cap,
                ingress_cap,
                result,
            } => {
                // If peer does not exist, then create it.
                self.ensure_peer_exists(&public_key).await;

                // Update bandwidth limits
                let now = self.context.current();
                let completions = self
                    .transmitter
                    .limit(now, &public_key, egress_cap, ingress_cap);
                self.process_completions(completions);

                // Notify the caller that the bandwidth update has been applied
                let _ = result.send(());
            }
            ingress::Message::AddLink {
                sender,
                receiver,
                sampler,
                success_rate,
                result,
            } => {
                // If sender or receiver does not exist, then create it.
                self.ensure_peer_exists(&sender).await;
                let receiver_socket = self.ensure_peer_exists(&receiver).await;

                // Require link to not already exist
                let key = (sender.clone(), receiver.clone());
                if self.links.contains_key(&key) {
                    return send_result(result, Err(Error::LinkExists));
                }

                let link = Link::new(
                    &mut self.context,
                    sender,
                    receiver,
                    receiver_socket,
                    sampler,
                    success_rate,
                    self.max_size,
                    self.received_messages.clone(),
                );
                self.links.insert(key, link);
                send_result(result, Ok(()))
            }
            ingress::Message::RemoveLink {
                sender,
                receiver,
                result,
            } => {
                match self.links.remove(&(sender, receiver)) {
                    Some(_) => (),
                    None => return send_result(result, Err(Error::LinkMissing)),
                }
                send_result(result, Ok(()))
            }
            ingress::Message::Block { from, to } => {
                self.blocks.insert((from, to));
            }
            ingress::Message::Blocked { result } => {
                send_result(result, Ok(self.blocks.iter().cloned().collect()))
            }
        }
    }

    /// Ensure a peer exists, creating it if necessary.
    ///
    /// Returns the socket address of the peer.
    async fn ensure_peer_exists(&mut self, public_key: &P) -> SocketAddr {
        if !self.peers.contains_key(public_key) {
            // Create peer
            let socket = self.get_next_socket();
            let peer = Peer::new(
                self.context.with_label("peer"),
                public_key.clone(),
                socket,
                self.max_size,
            )
            .await;

            // Once ready, add to peers
            self.peers.insert(public_key.clone(), peer);

            socket
        } else {
            self.peers.get(public_key).unwrap().socket
        }
    }

    /// Get all tracked peers as an ordered set.
    fn all_tracked_peers(&self) -> Set<P> {
        self.peer_refs
            .keys()
            .cloned()
            .try_collect()
            .expect("BTreeMap keys are unique")
    }
}

impl<E: RNetwork + Spawner + Rng + Clock + GClock + Metrics, P: PublicKey> Network<E, P> {
    /// Process completions from the transmitter.
    fn process_completions(&mut self, completions: Vec<Completion<P>>) {
        for completion in completions {
            // If there is no message to deliver, then skip
            let Some(deliver_at) = completion.deliver_at else {
                trace!(
                    origin = ?completion.origin,
                    recipient = ?completion.recipient,
                    "message dropped before delivery",
                );
                continue;
            };

            // Send message to link
            let key = (completion.origin.clone(), completion.recipient.clone());
            let Some(link) = self.links.get_mut(&key) else {
                // This can happen if the link is removed before the message is delivered
                trace!(
                    origin = ?completion.origin,
                    recipient = ?completion.recipient,
                    "missing link for completion",
                );
                continue;
            };
            if let Err(err) = link.send(completion.channel, completion.message, deliver_at) {
                error!(?err, "failed to send");
            }
        }
    }

    /// Handle a task.
    ///
    /// This method is called when a task is received from the sender, which can come from
    /// any peer in the network.
    fn handle_task(&mut self, task: Task<P>) {
        // If peer sets are enabled and we are not in one, ignore the message (we are disconnected from all)
        let (channel, origin, recipients, message, reply) = task;
        if self.tracked_peer_sets.is_some() && !self.peer_refs.contains_key(&origin) {
            warn!(
                ?origin,
                reason = "not in tracked peer set",
                "dropping message"
            );
            if let Err(err) = reply.send(Vec::new()) {
                error!(?err, "failed to send ack");
            }
            return;
        }

        // Collect recipients
        let recipients = match recipients {
            Recipients::All => {
                // If peer sets have been registered, send only to tracked peers
                // Otherwise, send to all registered peers (compatibility
                // with tests that do not register peer sets.)
                if self.peer_sets.is_empty() {
                    self.peers.keys().cloned().collect()
                } else {
                    self.peer_refs.keys().cloned().collect()
                }
            }
            Recipients::Some(keys) => keys,
            Recipients::One(key) => vec![key],
        };

        // Send to all recipients
        let now = self.context.current();
        let mut sent = Vec::new();
        for recipient in recipients {
            // Skip self
            if recipient == origin {
                trace!(?recipient, reason = "self", "dropping message");
                continue;
            }

            // If tracking peer sets, ensure recipient and sender are in a tracked peer set
            if self.tracked_peer_sets.is_some() && !self.peer_refs.contains_key(&recipient) {
                trace!(
                    ?origin,
                    ?recipient,
                    reason = "not in tracked peer set",
                    "dropping message"
                );
                continue;
            }

            // Determine if the sender or recipient has blocked the other
            let o_r = (origin.clone(), recipient.clone());
            let r_o = (recipient.clone(), origin.clone());
            if self.disconnect_on_block
                && (self.blocks.contains(&o_r) || self.blocks.contains(&r_o))
            {
                trace!(?origin, ?recipient, reason = "blocked", "dropping message");
                continue;
            }

            // Determine if there is a link between the origin and recipient
            let Some(link) = self.links.get_mut(&o_r) else {
                trace!(?origin, ?recipient, reason = "no link", "dropping message");
                continue;
            };

            // Check rate limit for this (sender, channel) pair
            if let Some(limiter) = self.rate_limiters.get(&(origin.clone(), channel)) {
                if limiter.check_key(&recipient).is_err() {
                    trace!(
                        ?origin,
                        ?recipient,
                        reason = "rate limited",
                        "dropping message"
                    );
                    continue;
                }
            }

            // Record sent message as soon as we determine there is a link with recipient (approximates
            // having an open connection)
            self.sent_messages
                .get_or_create(&metrics::Message::new(&origin, &recipient, channel))
                .inc();

            // Sample latency
            let latency = Duration::from_millis(link.sampler.sample(&mut self.context) as u64);

            // Determine if the message should be delivered
            let should_deliver = self.context.gen_bool(link.success_rate);

            // Enqueue message for delivery
            let completions = self.transmitter.enqueue(
                now,
                origin.clone(),
                recipient.clone(),
                channel,
                message.clone(),
                latency,
                should_deliver,
            );
            self.process_completions(completions);

            sent.push(recipient);
        }

        // Alert application of sent messages
        if let Err(err) = reply.send(sent) {
            error!(?err, "failed to send ack");
        }
    }

    /// Run the simulated network.
    ///
    /// It is not necessary to invoke this method before modifying the network topology, however,
    /// no messages will be sent until this method is called.
    pub fn start(mut self) -> Handle<()> {
        spawn_cell!(self.context, self.run().await)
    }

    async fn run(mut self) {
        loop {
            let tick = match self.transmitter.next() {
                Some(when) => Either::Left(self.context.sleep_until(when)),
                None => Either::Right(future::pending()),
            };
            select! {
                _ = tick => {
                    let now = self.context.current();
                    let completions = self.transmitter.advance(now);
                    self.process_completions(completions);
                },
                message = self.ingress.next() => {
                    // If ingress is closed, exit
                    let message = match message {
                        Some(message) => message,
                        None => break,
                    };
                    self.handle_ingress(message).await;
                },
                task = self.receiver.next() => {
                    // If receiver is closed, exit
                    let task = match task {
                        Some(task) => task,
                        None => break,
                    };
                    self.handle_task(task);
                },
            }
        }
    }
}

/// Implementation of a [crate::Sender] for the simulated network.
#[derive(Clone, Debug)]
pub struct Sender<P: PublicKey> {
    me: P,
    channel: Channel,
    max_size: usize,
    high: mpsc::UnboundedSender<Task<P>>,
    low: mpsc::UnboundedSender<Task<P>>,
}

impl<P: PublicKey> Sender<P> {
    fn new(
        context: impl Spawner + Metrics,
        me: P,
        channel: Channel,
        max_size: usize,
        mut sender: mpsc::UnboundedSender<Task<P>>,
    ) -> (Self, Handle<()>) {
        // Listen for messages
        let (high, mut high_receiver) = mpsc::unbounded();
        let (low, mut low_receiver) = mpsc::unbounded();
        let processor = context.with_label("processor").spawn(move |_| async move {
            loop {
                // Wait for task
                let task;
                select! {
                    high_task = high_receiver.next() => {
                        task = match high_task {
                            Some(task) => task,
                            None => break,
                        };
                    },
                    low_task = low_receiver.next() => {
                        task = match low_task {
                            Some(task) => task,
                            None => break,
                        };
                    }
                }

                // Send task
                if let Err(err) = sender.send(task).await {
                    error!(?err, channel, "failed to send task");
                }
            }
        });

        // Return sender
        (
            Self {
                me,
                channel,
                max_size,
                high,
                low,
            },
            processor,
        )
    }

    /// Split this [Sender] into a [SplitOrigin::Primary] and [SplitOrigin::Secondary] sender.
    pub fn split_with<F: SplitForwarder<P>>(
        self,
        forwarder: F,
    ) -> (SplitSender<P, F>, SplitSender<P, F>) {
        (
            SplitSender {
                replica: SplitOrigin::Primary,
                inner: self.clone(),
                forwarder: forwarder.clone(),
            },
            SplitSender {
                replica: SplitOrigin::Secondary,
                inner: self,
                forwarder,
            },
        )
    }
}

impl<P: PublicKey> crate::Sender for Sender<P> {
    type Error = Error;
    type PublicKey = P;

    async fn send(
        &mut self,
        recipients: Recipients<P>,
        message: Bytes,
        priority: bool,
    ) -> Result<Vec<P>, Error> {
        // Check message size
        if message.len() > self.max_size {
            return Err(Error::MessageTooLarge(message.len()));
        }

        // Send message
        let (sender, receiver) = oneshot::channel();
        let channel = if priority { &self.high } else { &self.low };
        channel
            .unbounded_send((self.channel, self.me.clone(), recipients, message, sender))
            .map_err(|_| Error::NetworkClosed)?;
        receiver.await.map_err(|_| Error::NetworkClosed)
    }
}

/// A sender that routes recipients per message via a user-provided function.
#[derive(Clone)]
pub struct SplitSender<P: PublicKey, F: SplitForwarder<P>> {
    replica: SplitOrigin,
    inner: Sender<P>,
    forwarder: F,
}

impl<P: PublicKey, F: SplitForwarder<P>> std::fmt::Debug for SplitSender<P, F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SplitSender")
            .field("replica", &self.replica)
            .field("inner", &self.inner)
            .finish()
    }
}

impl<P: PublicKey, F: SplitForwarder<P>> crate::Sender for SplitSender<P, F> {
    type Error = Error;
    type PublicKey = P;

    async fn send(
        &mut self,
        recipients: Recipients<P>,
        message: Bytes,
        priority: bool,
    ) -> Result<Vec<P>, Error> {
        let recipients = (self.forwarder)(self.replica, &recipients, &message);
        let Some(recipients) = recipients else {
            // If the forwarder returns None, drop the message
            return Ok(Vec::new());
        };
        self.inner.send(recipients, message, priority).await
    }
}

type MessageReceiver<P> = mpsc::UnboundedReceiver<Message<P>>;

/// Implementation of a [crate::Receiver] for the simulated network.
#[derive(Debug)]
pub struct Receiver<P: PublicKey> {
    receiver: MessageReceiver<P>,
}

impl<P: PublicKey> crate::Receiver for Receiver<P> {
    type Error = Error;
    type PublicKey = P;

    async fn recv(&mut self) -> Result<Message<Self::PublicKey>, Error> {
        self.receiver.next().await.ok_or(Error::NetworkClosed)
    }
}

impl<P: PublicKey> Receiver<P> {
    /// Split this [Receiver] into a [SplitTarget::Primary] and [SplitTarget::Secondary] receiver.
    pub fn split_with<E: Spawner, R: SplitRouter<P>>(
        mut self,
        context: E,
        router: R,
    ) -> (Self, Self) {
        let (mut primary_tx, primary_rx) = mpsc::unbounded();
        let (mut secondary_tx, secondary_rx) = mpsc::unbounded();
        context.spawn(move |_| async move {
            while let Some(message) = self.receiver.next().await {
                // Route message to the appropriate target
                let direction = router(&message);
                match direction {
                    SplitTarget::None => {}
                    SplitTarget::Primary => {
                        if let Err(err) = primary_tx.send(message).await {
                            error!(?err, "failed to send message to primary");
                        }
                    }
                    SplitTarget::Secondary => {
                        if let Err(err) = secondary_tx.send(message).await {
                            error!(?err, "failed to send message to secondary");
                        }
                    }
                    SplitTarget::Both => {
                        if let Err(err) = primary_tx.send(message.clone()).await {
                            error!(?err, "failed to send message to primary");
                        }
                        if let Err(err) = secondary_tx.send(message).await {
                            error!(?err, "failed to send message to secondary");
                        }
                    }
                }

                // Exit if both channels are closed
                if primary_tx.is_closed() && secondary_tx.is_closed() {
                    break;
                }
            }
        });

        (
            Self {
                receiver: primary_rx,
            },
            Self {
                receiver: secondary_rx,
            },
        )
    }
}

/// A peer in the simulated network.
///
/// The peer can register channels, which allows it to receive messages sent to the channel from other peers.
struct Peer<P: PublicKey> {
    // Socket address that the peer is listening on
    socket: SocketAddr,

    // Control to register new channels
    control: mpsc::UnboundedSender<(Channel, Handle<()>, oneshot::Sender<MessageReceiver<P>>)>,
}

impl<P: PublicKey> Peer<P> {
    /// Create and return a new peer.
    ///
    /// The peer will listen for incoming connections on the given `socket` address.
    /// `max_size` is the maximum size of a message that can be sent to the peer.
    async fn new<E: Spawner + RNetwork + Metrics + Clock>(
        context: E,
        public_key: P,
        socket: SocketAddr,
        max_size: usize,
    ) -> Self {
        // The control is used to register channels.
        // There is exactly one mailbox created for each channel that the peer is registered for.
        let (control_sender, mut control_receiver) = mpsc::unbounded();

        // Whenever a message is received from a peer, it is placed in the inbox.
        // The router polls the inbox and forwards the message to the appropriate mailbox.
        let (inbox_sender, mut inbox_receiver) = mpsc::unbounded();

        // Spawn router
        context.with_label("router").spawn(|context| async move {
            // Map of channels to mailboxes (senders to particular channels)
            let mut mailboxes = HashMap::new();

            // Continually listen for control messages and outbound messages
            select_loop! {
                context,
                on_stopped => {},
                // Listen for control messages, which are used to register channels
                control = control_receiver.next() => {
                    // If control is closed, exit
                    let (channel, sender, result_tx): (Channel, Handle<()>, oneshot::Sender<MessageReceiver<P>>) = match control {
                        Some(control) => control,
                        None => break,
                    };

                    // Register channel
                    let (receiver_tx, receiver_rx) = mpsc::unbounded();
                    if let Some((_, existing_sender)) = mailboxes.insert(channel, (receiver_tx, sender)) {
                        warn!(?public_key, ?channel, "overwriting existing channel");
                        existing_sender.abort();
                    }
                    result_tx.send(receiver_rx).unwrap();
                },

                // Listen for messages from the inbox, which are forwarded to the appropriate mailbox
                inbox = inbox_receiver.next() => {
                    // If inbox is closed, exit
                    let (channel, message) = match inbox {
                        Some(message) => message,
                        None => break,
                    };

                    // Send message to mailbox
                    match mailboxes.get_mut(&channel) {
                        Some((receiver_tx, _)) => {
                            if let Err(err) = receiver_tx.send(message).await {
                                debug!(?err, "failed to send message to mailbox");
                            }
                        }
                        None => {
                            trace!(
                                recipient = ?public_key,
                                channel,
                                reason = "missing channel",
                                "dropping message",
                            );
                        }
                    }
                },
            }
        });

        // Spawn a task that accepts new connections and spawns a task for each connection
        let (ready_tx, ready_rx) = oneshot::channel();
        context
            .with_label("listener")
            .spawn(move |context| async move {
                // Initialize listener
                let mut listener = context.bind(socket).await.unwrap();
                let _ = ready_tx.send(());

                // Continually accept new connections
                while let Ok((_, _, mut stream)) = listener.accept().await {
                    // New connection accepted. Spawn a task for this connection
                    context.with_label("receiver").spawn({
                        let mut inbox_sender = inbox_sender.clone();
                        move |_| async move {
                            // Receive dialer's public key as a handshake
                            let dialer = match recv_frame(&mut stream, max_size).await {
                                Ok(data) => data,
                                Err(_) => {
                                    error!("failed to receive public key from dialer");
                                    return;
                                }
                            };
                            let Ok(dialer) = P::decode(dialer.as_ref()) else {
                                error!("received public key is invalid");
                                return;
                            };

                            // Continually receive messages from the dialer and send them to the inbox
                            while let Ok(data) = recv_frame(&mut stream, max_size).await {
                                let channel = Channel::from_be_bytes(
                                    data[..Channel::SIZE].try_into().unwrap(),
                                );
                                let message = data.slice(Channel::SIZE..);
                                if let Err(err) = inbox_sender
                                    .send((channel, (dialer.clone(), message)))
                                    .await
                                {
                                    debug!(?err, "failed to send message to mailbox");
                                    break;
                                }
                            }
                        }
                    });
                }
            });

        // Wait for listener to start before returning
        let _ = ready_rx.await;

        // Return peer
        Self {
            socket,
            control: control_sender,
        }
    }

    /// Register a channel with the peer.
    ///
    /// This allows the peer to receive messages sent to the channel.
    /// Returns a receiver that can be used to receive messages sent to the channel.
    async fn register(
        &mut self,
        channel: Channel,
        sender: Handle<()>,
    ) -> Result<MessageReceiver<P>, Error> {
        let (result_tx, result_rx) = oneshot::channel();
        self.control
            .send((channel, sender, result_tx))
            .await
            .map_err(|_| Error::NetworkClosed)?;
        result_rx.await.map_err(|_| Error::NetworkClosed)
    }
}

// A unidirectional link between two peers.
// Messages can be sent over the link with a given latency, jitter, and success rate.
struct Link {
    sampler: Normal<f64>,
    success_rate: f64,
    // Messages with their receive time for ordered delivery
    inbox: mpsc::UnboundedSender<(Channel, Bytes, SystemTime)>,
}

/// Buffered payload waiting for earlier messages on the same link to complete.
impl Link {
    #[allow(clippy::too_many_arguments)]
    fn new<E: Spawner + RNetwork + Clock + Metrics, P: PublicKey>(
        context: &mut E,
        dialer: P,
        receiver: P,
        socket: SocketAddr,
        sampler: Normal<f64>,
        success_rate: f64,
        max_size: usize,
        received_messages: Family<metrics::Message, Counter>,
    ) -> Self {
        // Spawn a task that will wait for messages to be sent to the link and then send them
        // over the network.
        let (inbox, mut outbox) = mpsc::unbounded::<(Channel, Bytes, SystemTime)>();
        context.with_label("link").spawn(move |context| async move {
            // Dial the peer and handshake by sending it the dialer's public key
            let (mut sink, _) = context.dial(socket).await.unwrap();
            if let Err(err) = send_frame(&mut sink, &dialer, max_size).await {
                error!(?err, "failed to send public key to listener");
                return;
            }

            // Process messages in order, waiting for their receive time
            while let Some((channel, message, receive_complete_at)) = outbox.next().await {
                // Wait until the message should arrive at receiver
                context.sleep_until(receive_complete_at).await;

                // Send the message
                let mut data = bytes::BytesMut::with_capacity(Channel::SIZE + message.len());
                data.extend_from_slice(&channel.to_be_bytes());
                data.extend_from_slice(&message);
                let data = data.freeze();
                let _ = send_frame(&mut sink, &data, max_size).await;

                // Bump received messages metric
                received_messages
                    .get_or_create(&metrics::Message::new(&dialer, &receiver, channel))
                    .inc();
            }
        });

        Self {
            sampler,
            success_rate,
            inbox,
        }
    }

    // Send a message over the link with receive timing.
    fn send(
        &mut self,
        channel: Channel,
        message: Bytes,
        receive_complete_at: SystemTime,
    ) -> Result<(), Error> {
        self.inbox
            .unbounded_send((channel, message, receive_complete_at))
            .map_err(|_| Error::NetworkClosed)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Manager, Receiver as _, Recipients, Sender as _};
    use bytes::Bytes;
    use commonware_cryptography::{ed25519, Signer as _};
    use commonware_runtime::{deterministic, Runner as _};
    use futures::FutureExt;
    use governor::Quota;
    use std::num::NonZeroU32;

    const MAX_MESSAGE_SIZE: usize = 1024 * 1024;

    /// Default rate limit set high enough to not interfere with normal operation
    const TEST_QUOTA: Quota = Quota::per_second(NonZeroU32::MAX);

    #[test]
    fn test_register_and_link() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                max_size: MAX_MESSAGE_SIZE,
                disconnect_on_block: true,
                tracked_peer_sets: Some(3),
            };
            let network_context = context.with_label("network");
            let (network, mut oracle) = Network::new(network_context.clone(), cfg);
            network_context.spawn(|_| network.run());

            // Create two public keys
            let pk1 = ed25519::PrivateKey::from_seed(1).public_key();
            let pk2 = ed25519::PrivateKey::from_seed(2).public_key();

            // Register the peer set
            let mut manager = oracle.manager();
            manager
                .update(0, [pk1.clone(), pk2.clone()].try_into().unwrap())
                .await;
            let mut control = oracle.control(pk1.clone());
            control.register(0, TEST_QUOTA).await.unwrap();
            control.register(1, TEST_QUOTA).await.unwrap();
            let mut control = oracle.control(pk2.clone());
            control.register(0, TEST_QUOTA).await.unwrap();
            control.register(1, TEST_QUOTA).await.unwrap();

            // Overwrite if registering again
            control.register(1, TEST_QUOTA).await.unwrap();

            // Add link
            let link = ingress::Link {
                latency: Duration::from_millis(2),
                jitter: Duration::from_millis(1),
                success_rate: 0.9,
            };
            oracle
                .add_link(pk1.clone(), pk2.clone(), link.clone())
                .await
                .unwrap();

            // Expect error when adding link again
            assert!(matches!(
                oracle.add_link(pk1, pk2, link).await,
                Err(Error::LinkExists)
            ));
        });
    }

    #[test]
    fn test_split_channel_single() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                max_size: MAX_MESSAGE_SIZE,
                disconnect_on_block: true,
                tracked_peer_sets: Some(3),
            };
            let network_context = context.with_label("network");
            let (network, mut oracle) = Network::new(network_context.clone(), cfg);
            network_context.spawn(|_| network.run());

            // Create a "twin" node that will be split, plus two normal peers
            let twin = ed25519::PrivateKey::from_seed(20).public_key();
            let peer_a = ed25519::PrivateKey::from_seed(21).public_key();
            let peer_b = ed25519::PrivateKey::from_seed(22).public_key();

            // Register all peers
            let mut manager = oracle.manager();
            manager
                .update(
                    0,
                    [twin.clone(), peer_a.clone(), peer_b.clone()]
                        .try_into()
                        .unwrap(),
                )
                .await;

            // Register normal peers
            let (mut peer_a_sender, mut peer_a_recv) = oracle
                .control(peer_a.clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();
            let (mut peer_b_sender, mut peer_b_recv) = oracle
                .control(peer_b.clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();

            // Register and split the twin's channel:
            // - Primary sends only to peer_a
            // - Secondary sends only to peer_b
            // - Messages from peer_a go to primary receiver
            // - Messages from peer_b go to secondary receiver
            let (twin_sender, twin_receiver) = oracle
                .control(twin.clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();
            let peer_a_for_router = peer_a.clone();
            let peer_b_for_router = peer_b.clone();
            let (mut twin_primary_sender, mut twin_secondary_sender) =
                twin_sender.split_with(move |origin, _, _| match origin {
                    SplitOrigin::Primary => Some(Recipients::One(peer_a_for_router.clone())),
                    SplitOrigin::Secondary => Some(Recipients::One(peer_b_for_router.clone())),
                });
            let peer_a_for_recv = peer_a.clone();
            let peer_b_for_recv = peer_b.clone();
            let (mut twin_primary_recv, mut twin_secondary_recv) = twin_receiver.split_with(
                context.with_label("split_receiver"),
                move |(sender, _)| {
                    if sender == &peer_a_for_recv {
                        SplitTarget::Primary
                    } else if sender == &peer_b_for_recv {
                        SplitTarget::Secondary
                    } else {
                        panic!("unexpected sender");
                    }
                },
            );

            // Establish bidirectional links
            let link = ingress::Link {
                latency: Duration::from_millis(0),
                jitter: Duration::from_millis(0),
                success_rate: 1.0,
            };
            oracle
                .add_link(peer_a.clone(), twin.clone(), link.clone())
                .await
                .unwrap();
            oracle
                .add_link(twin.clone(), peer_a.clone(), link.clone())
                .await
                .unwrap();
            oracle
                .add_link(peer_b.clone(), twin.clone(), link.clone())
                .await
                .unwrap();
            oracle
                .add_link(twin.clone(), peer_b.clone(), link.clone())
                .await
                .unwrap();

            // Send messages in both directions
            let msg_a_to_twin = Bytes::from_static(b"from_a");
            let msg_b_to_twin = Bytes::from_static(b"from_b");
            let msg_primary_out = Bytes::from_static(b"primary_out");
            let msg_secondary_out = Bytes::from_static(b"secondary_out");
            peer_a_sender
                .send(Recipients::One(twin.clone()), msg_a_to_twin.clone(), false)
                .await
                .unwrap();
            peer_b_sender
                .send(Recipients::One(twin.clone()), msg_b_to_twin.clone(), false)
                .await
                .unwrap();
            twin_primary_sender
                .send(Recipients::All, msg_primary_out.clone(), false)
                .await
                .unwrap();
            twin_secondary_sender
                .send(Recipients::All, msg_secondary_out.clone(), false)
                .await
                .unwrap();

            // Verify routing: peer_a messages go to primary, peer_b to secondary
            let (sender, payload) = twin_primary_recv.recv().await.unwrap();
            assert_eq!(sender, peer_a);
            assert_eq!(payload, msg_a_to_twin);
            let (sender, payload) = twin_secondary_recv.recv().await.unwrap();
            assert_eq!(sender, peer_b);
            assert_eq!(payload, msg_b_to_twin);

            // Verify routing: primary sends to peer_a, secondary to peer_b
            let (sender, payload) = peer_a_recv.recv().await.unwrap();
            assert_eq!(sender, twin);
            assert_eq!(payload, msg_primary_out);
            let (sender, payload) = peer_b_recv.recv().await.unwrap();
            assert_eq!(sender, twin);
            assert_eq!(payload, msg_secondary_out);
        });
    }

    #[test]
    fn test_split_channel_both() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                max_size: MAX_MESSAGE_SIZE,
                disconnect_on_block: true,
                tracked_peer_sets: Some(3),
            };
            let network_context = context.with_label("network");
            let (network, mut oracle) = Network::new(network_context.clone(), cfg);
            network_context.spawn(|_| network.run());

            // Create a "twin" node that will be split, plus a third peer
            let twin = ed25519::PrivateKey::from_seed(30).public_key();
            let peer_c = ed25519::PrivateKey::from_seed(31).public_key();

            // Register all peers
            let mut manager = oracle.manager();
            manager
                .update(0, [twin.clone(), peer_c.clone()].try_into().unwrap())
                .await;

            // Register normal peer
            let (mut peer_c_sender, _peer_c_recv) = oracle
                .control(peer_c.clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();

            // Register and split the twin's channel with a router that sends to Both
            let (twin_sender, twin_receiver) = oracle
                .control(twin.clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();
            let (_twin_primary_sender, _twin_secondary_sender) =
                twin_sender.split_with(|_origin, recipients, _| Some(recipients.clone()));
            let (mut twin_primary_recv, mut twin_secondary_recv) = twin_receiver
                .split_with(context.with_label("split_receiver_both"), |_| {
                    SplitTarget::Both
                });

            // Establish bidirectional links
            let link = ingress::Link {
                latency: Duration::from_millis(0),
                jitter: Duration::from_millis(0),
                success_rate: 1.0,
            };
            oracle
                .add_link(peer_c.clone(), twin.clone(), link.clone())
                .await
                .unwrap();
            oracle
                .add_link(twin.clone(), peer_c.clone(), link)
                .await
                .unwrap();

            // Send a message from peer_c to twin
            let msg_both = Bytes::from_static(b"to_both");
            peer_c_sender
                .send(Recipients::One(twin.clone()), msg_both.clone(), false)
                .await
                .unwrap();

            // Verify both receivers get the message
            let (sender, payload) = twin_primary_recv.recv().await.unwrap();
            assert_eq!(sender, peer_c);
            assert_eq!(payload, msg_both);
            let (sender, payload) = twin_secondary_recv.recv().await.unwrap();
            assert_eq!(sender, peer_c);
            assert_eq!(payload, msg_both);
        });
    }

    #[test]
    fn test_split_channel_none() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                max_size: MAX_MESSAGE_SIZE,
                disconnect_on_block: true,
                tracked_peer_sets: Some(3),
            };
            let network_context = context.with_label("network");
            let (network, mut oracle) = Network::new(network_context.clone(), cfg);
            network_context.spawn(|_| network.run());

            // Create a "twin" node that will be split, plus a third peer
            let twin = ed25519::PrivateKey::from_seed(30).public_key();
            let peer_c = ed25519::PrivateKey::from_seed(31).public_key();

            // Register all peers
            let mut manager = oracle.manager();
            manager
                .update(0, [twin.clone(), peer_c.clone()].try_into().unwrap())
                .await;

            // Register normal peer
            let (mut peer_c_sender, _peer_c_recv) = oracle
                .control(peer_c.clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();

            // Register and split the twin's channel with a router that sends to Both
            let (twin_sender, twin_receiver) = oracle
                .control(twin.clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();
            let (mut twin_primary_sender, mut twin_secondary_sender) =
                twin_sender.split_with(|_origin, _, _| None);
            let (mut twin_primary_recv, mut twin_secondary_recv) = twin_receiver
                .split_with(context.with_label("split_receiver_both"), |_| {
                    SplitTarget::None
                });

            // Establish bidirectional links
            let link = ingress::Link {
                latency: Duration::from_millis(0),
                jitter: Duration::from_millis(0),
                success_rate: 1.0,
            };
            oracle
                .add_link(peer_c.clone(), twin.clone(), link.clone())
                .await
                .unwrap();
            oracle
                .add_link(twin.clone(), peer_c.clone(), link)
                .await
                .unwrap();

            // Send a message from peer_c to twin
            let msg_both = Bytes::from_static(b"to_both");
            let sent = peer_c_sender
                .send(Recipients::One(twin.clone()), msg_both.clone(), false)
                .await
                .unwrap();
            assert_eq!(sent.len(), 1);
            assert_eq!(sent[0], twin);

            // Verify both receivers get the message
            context.sleep(Duration::from_millis(100)).await;
            assert!(twin_primary_recv.recv().now_or_never().is_none());
            assert!(twin_secondary_recv.recv().now_or_never().is_none());

            // Send a message from twin to peer_c
            let msg_both = Bytes::from_static(b"to_both");
            let sent = twin_primary_sender
                .send(Recipients::One(peer_c.clone()), msg_both.clone(), false)
                .await
                .unwrap();
            assert_eq!(sent.len(), 0);

            // Send a message from twin to peer_c
            let msg_both = Bytes::from_static(b"to_both");
            let sent = twin_secondary_sender
                .send(Recipients::One(peer_c.clone()), msg_both.clone(), false)
                .await
                .unwrap();
            assert_eq!(sent.len(), 0);
        });
    }

    #[test]
    fn test_unordered_peer_sets() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                max_size: MAX_MESSAGE_SIZE,
                disconnect_on_block: true,
                tracked_peer_sets: Some(3),
            };
            let network_context = context.with_label("network");
            let (network, oracle) = Network::new(network_context.clone(), cfg);
            network_context.spawn(|_| network.run());

            // Create two public keys
            let pk1 = ed25519::PrivateKey::from_seed(1).public_key();
            let pk2 = ed25519::PrivateKey::from_seed(2).public_key();

            // Subscribe to peer sets
            let mut manager = oracle.manager();
            let mut subscription = manager.subscribe().await;

            // Register initial peer set
            manager
                .update(10, [pk1.clone(), pk2.clone()].try_into().unwrap())
                .await;
            let (id, new, all) = subscription.next().await.unwrap();
            assert_eq!(id, 10);
            assert_eq!(new.len(), 2);
            assert_eq!(all.len(), 2);

            // Register old peer sets (ignored)
            let pk3 = ed25519::PrivateKey::from_seed(3).public_key();
            manager.update(9, [pk3.clone()].try_into().unwrap()).await;

            // Add new peer set
            let pk4 = ed25519::PrivateKey::from_seed(4).public_key();
            manager.update(11, [pk4.clone()].try_into().unwrap()).await;
            let (id, new, all) = subscription.next().await.unwrap();
            assert_eq!(id, 11);
            assert_eq!(new, [pk4.clone()].try_into().unwrap());
            assert_eq!(all, [pk1, pk2, pk4].try_into().unwrap());
        });
    }

    #[test]
    fn test_get_next_socket() {
        let cfg = Config {
            max_size: MAX_MESSAGE_SIZE,
            disconnect_on_block: true,
            tracked_peer_sets: None,
        };
        let runner = deterministic::Runner::default();

        runner.start(|context| async move {
            type PublicKey = ed25519::PublicKey;
            let (mut network, _) =
                Network::<deterministic::Context, PublicKey>::new(context.clone(), cfg);

            // Test that the next socket address is incremented correctly
            let mut original = network.next_addr;
            let next = network.get_next_socket();
            assert_eq!(next, original);
            let next = network.get_next_socket();
            original.set_port(1);
            assert_eq!(next, original);

            // Test that the port number overflows correctly
            let max_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(255, 0, 255, 255)), 65535);
            network.next_addr = max_addr;
            let next = network.get_next_socket();
            assert_eq!(next, max_addr);
            let next = network.get_next_socket();
            assert_eq!(
                next,
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(255, 1, 0, 0)), 0)
            );
        });
    }

    #[test]
    fn test_fifo_burst_same_recipient() {
        let cfg = Config {
            max_size: MAX_MESSAGE_SIZE,
            disconnect_on_block: true,
            tracked_peer_sets: Some(3),
        };
        let runner = deterministic::Runner::default();

        runner.start(|context| async move {
            let (network, mut oracle) = Network::new(context.with_label("network"), cfg);
            let network_handle = network.start();

            let sender_pk = ed25519::PrivateKey::from_seed(10).public_key();
            let recipient_pk = ed25519::PrivateKey::from_seed(11).public_key();

            let mut manager = oracle.manager();
            manager
                .update(
                    0,
                    [sender_pk.clone(), recipient_pk.clone()]
                        .try_into()
                        .unwrap(),
                )
                .await;
            let (mut sender, _sender_recv) = oracle
                .control(sender_pk.clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();
            let (_sender2, mut receiver) = oracle
                .control(recipient_pk.clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();

            oracle
                .limit_bandwidth(sender_pk.clone(), Some(5_000), None)
                .await
                .unwrap();
            oracle
                .limit_bandwidth(recipient_pk.clone(), None, Some(5_000))
                .await
                .unwrap();

            oracle
                .add_link(
                    sender_pk.clone(),
                    recipient_pk.clone(),
                    ingress::Link {
                        latency: Duration::from_millis(0),
                        jitter: Duration::from_millis(0),
                        success_rate: 1.0,
                    },
                )
                .await
                .unwrap();

            const COUNT: usize = 50;
            let mut expected = Vec::with_capacity(COUNT);
            for i in 0..COUNT {
                let msg = Bytes::from(vec![i as u8; 64]);
                sender
                    .send(Recipients::One(recipient_pk.clone()), msg.clone(), false)
                    .await
                    .unwrap();
                expected.push(msg);
            }

            for expected_msg in expected {
                let (_pk, bytes) = receiver.recv().await.unwrap();
                assert_eq!(bytes, expected_msg);
            }

            drop(oracle);
            drop(sender);
            network_handle.abort();
        });
    }

    #[test]
    fn test_broadcast_respects_transmit_latency() {
        let cfg = Config {
            max_size: MAX_MESSAGE_SIZE,
            disconnect_on_block: true,
            tracked_peer_sets: Some(3),
        };
        let runner = deterministic::Runner::default();

        runner.start(|context| async move {
            let (network, mut oracle) = Network::new(context.with_label("network"), cfg);
            let network_handle = network.start();

            let sender_pk = ed25519::PrivateKey::from_seed(42).public_key();
            let recipient_a = ed25519::PrivateKey::from_seed(43).public_key();
            let recipient_b = ed25519::PrivateKey::from_seed(44).public_key();

            let mut manager = oracle.manager();
            manager
                .update(
                    0,
                    [sender_pk.clone(), recipient_a.clone(), recipient_b.clone()]
                        .try_into()
                        .unwrap(),
                )
                .await;
            let (mut sender, _recv_sender) = oracle
                .control(sender_pk.clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();
            let (_sender2, mut recv_a) = oracle
                .control(recipient_a.clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();
            let (_sender3, mut recv_b) = oracle
                .control(recipient_b.clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();

            oracle
                .limit_bandwidth(sender_pk.clone(), Some(1_000), None)
                .await
                .unwrap();
            oracle
                .limit_bandwidth(recipient_a.clone(), None, Some(1_000))
                .await
                .unwrap();
            oracle
                .limit_bandwidth(recipient_b.clone(), None, Some(1_000))
                .await
                .unwrap();

            let link = ingress::Link {
                latency: Duration::from_millis(0),
                jitter: Duration::from_millis(0),
                success_rate: 1.0,
            };
            oracle
                .add_link(sender_pk.clone(), recipient_a.clone(), link.clone())
                .await
                .unwrap();
            oracle
                .add_link(sender_pk.clone(), recipient_b.clone(), link)
                .await
                .unwrap();

            let big_msg = Bytes::from(vec![7u8; 10_000]);
            let start = context.current();
            sender
                .send(Recipients::All, big_msg.clone(), false)
                .await
                .unwrap();

            let (_pk, received_a) = recv_a.recv().await.unwrap();
            assert_eq!(received_a, big_msg);
            let elapsed_a = context.current().duration_since(start).unwrap();
            assert!(elapsed_a >= Duration::from_secs(20));

            let (_pk, received_b) = recv_b.recv().await.unwrap();
            assert_eq!(received_b, big_msg);
            let elapsed_b = context.current().duration_since(start).unwrap();
            assert!(elapsed_b >= Duration::from_secs(20));

            // Because bandwidth is shared, the two messages should take about the same time
            assert!(elapsed_a.abs_diff(elapsed_b) <= Duration::from_secs(1));

            drop(oracle);
            drop(sender);
            network_handle.abort();
        });
    }
}
