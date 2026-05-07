//! Implementation of a simulated p2p network.

use super::{
    ingress::{self, Oracle},
    metrics,
    transmitter::{self, Completion},
    Error,
};
use crate::{
    authenticated::Mailbox,
    utils::{
        limited::{CheckedSender as LimitedCheckedSender, Connected, LimitedSender},
        PeerSetsAtIndex as PeerSetsAtIndexBase,
    },
    Channel, Message, PeerSetUpdate, Recipients, TrackedPeers, UnlimitedSender as _,
};
use commonware_codec::{DecodeExt, FixedSize};
use commonware_cryptography::PublicKey;
use commonware_macros::{select, select_loop};
use commonware_runtime::{
    spawn_cell,
    telemetry::metrics::{CounterFamily, MetricsExt as _},
    Clock, ContextCell, Handle, IoBuf, IoBufs, Listener as _, Metrics, Network as RNetwork, Quota,
    Spawner,
};
use commonware_stream::utils::codec::{recv_frame, send_frame};
use commonware_utils::{
    channel::{
        actor::{ActorInbox, Enqueue},
        fallible::FallibleExt,
        mpsc, oneshot, ring,
    },
    ordered::Set,
    NZUsize, TryCollect,
};
use either::Either;
use futures::{future, Sink};
use rand::Rng;
use rand_distr::{Distribution, Normal};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    fmt::Debug,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    num::NonZeroUsize,
    pin::Pin,
    time::{Duration, SystemTime},
};
use tracing::{debug, error, trace, warn};

/// Primary and secondary [`Set`] at one peer set index.
type PeerSetsAtIndex<P> = PeerSetsAtIndexBase<Set<P>, Set<P>>;

/// Task type representing a message to be sent within the network.
type Task<P> = (
    Channel,
    P,
    Recipients<P>,
    IoBuf,
    Option<oneshot::Sender<Vec<P>>>,
);

const ORACLE_MAILBOX_SIZE: usize = 1024;

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
    Fn(SplitOrigin, &Recipients<P>, &IoBuf) -> Option<Recipients<P>> + Send + Sync + Clone + 'static
{
}

impl<P: PublicKey, F> SplitForwarder<P> for F where
    F: Fn(SplitOrigin, &Recipients<P>, &IoBuf) -> Option<Recipients<P>>
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

/// Reference counts for how many tracked peer sets list a peer as primary vs secondary.
#[derive(Clone, Copy, Default)]
struct PeerRefCounts {
    primary: usize,
    secondary: usize,
}

/// Configuration for the simulated network.
pub struct Config {
    /// Maximum size of a message that can be sent over the network.
    pub max_size: u32,

    /// True if peers should disconnect upon being blocked. While production networking would
    /// typically disconnect, for testing purposes it may be useful to keep peers connected,
    /// allowing byzantine actors the ability to continue sending messages.
    pub disconnect_on_block: bool,

    /// The maximum number of peer sets to track (`tracked_peer_sets`). When a new peer set is
    /// tracked and this limit is exceeded, the oldest peer set is removed. Peers that are no
    /// longer in any tracked peer set will have their links removed and messages to them will be
    /// dropped.
    pub tracked_peer_sets: NonZeroUsize,
}

/// Implementation of a simulated network.
pub struct Network<E: RNetwork + Spawner + Rng + Clock + Metrics, P: PublicKey> {
    context: ContextCell<E>,

    // Maximum size of a message that can be sent over the network
    max_size: u32,

    // True if peers should disconnect upon being blocked.
    // While production networking would typically disconnect, for testing purposes it may be useful
    // to keep peers connected, allowing byzantine actors the ability to continue sending messages.
    disconnect_on_block: bool,

    // Next socket address to assign to a new peer
    // Incremented for each new peer
    next_addr: SocketAddr,

    // Channel to receive messages from the oracle
    ingress: ActorInbox<ingress::Message<P, E>>,

    // Mailbox for the oracle channel (passed to Senders for PeerSource subscriptions)
    oracle_mailbox: Mailbox<ingress::Message<P, E>>,

    // A channel to receive tasks from peers
    // The sender is cloned and given to each peer
    // The receiver is polled in the main loop
    sender: mpsc::UnboundedSender<Task<P>>,
    receiver: mpsc::UnboundedReceiver<Task<P>>,

    // A map from a pair of public keys (from, to) to a link between the two peers
    links: HashMap<(P, P), Link>,

    // A map from a public key to a peer
    peers: BTreeMap<P, Peer<P>>,

    // Primary and secondary peer sets indexed by peer set ID.
    peer_sets: BTreeMap<u64, PeerSetsAtIndex<P>>,

    // Per-peer reference counts across tracked peer sets (entry removed when both are zero).
    peer_ref_counts: BTreeMap<P, PeerRefCounts>,

    // Maximum number of peer sets to track.
    tracked_peer_sets: NonZeroUsize,

    // A map of peers blocking each other
    blocks: BTreeSet<(P, P)>,

    // State of the transmitter
    transmitter: transmitter::State<P>,

    // Subscribers to primary peer set updates (used by `Manager::subscribe`).
    subscribers: Vec<mpsc::UnboundedSender<PeerSetUpdate<P>>>,

    // Subscribers to the connectable peer list (used by PeerSource for LimitedSender)
    peer_subscribers: Vec<ring::Sender<Vec<P>>>,

    // Metrics for received and sent messages
    received_messages: CounterFamily<metrics::Message>,
    sent_messages: CounterFamily<metrics::Message>,
}

impl<E: RNetwork + Spawner + Rng + Clock + Metrics, P: PublicKey> Network<E, P> {
    /// Create a new simulated network with a given runtime and configuration.
    ///
    /// Returns a tuple containing the network instance and the oracle that can
    /// be used to modify the state of the network during context.
    pub fn new(mut context: E, cfg: Config) -> (Self, Oracle<P, E>) {
        let (sender, receiver) = mpsc::unbounded_channel();
        let (oracle_mailbox, oracle_receiver) = Mailbox::new(ORACLE_MAILBOX_SIZE);
        let sent_messages = context.family("messages_sent", "messages sent");
        let received_messages = context.family("messages_received", "messages received");

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
                oracle_mailbox: oracle_mailbox.clone(),
                sender,
                receiver,
                links: HashMap::new(),
                peers: BTreeMap::new(),
                peer_sets: BTreeMap::new(),
                peer_ref_counts: BTreeMap::new(),
                blocks: BTreeSet::new(),
                transmitter: transmitter::State::new(),
                subscribers: Vec::new(),
                peer_subscribers: Vec::new(),
                received_messages,
                sent_messages,
            },
            Oracle::new(oracle_mailbox),
        )
    }

    /// Create a new simulated network with an initial primary peer set.
    ///
    /// This is a convenience for test setups that would otherwise call
    /// [`crate::Manager::track`] immediately after construction.
    pub async fn new_with_peers<I>(context: E, cfg: Config, peers: I) -> (Self, Oracle<P, E>)
    where
        I: IntoIterator<Item = P>,
    {
        Self::new_with_split_peers(context, cfg, peers, std::iter::empty()).await
    }

    /// Create a new simulated network with primary and secondary peers split into two sets.
    ///
    /// Peers are tracked at peer set ID `0` as [`TrackedPeers`], matching the most common test
    /// setup.
    pub async fn new_with_split_peers<I, J>(
        context: E,
        cfg: Config,
        primary: I,
        secondary: J,
    ) -> (Self, Oracle<P, E>)
    where
        I: IntoIterator<Item = P>,
        J: IntoIterator<Item = P>,
    {
        let (mut network, oracle) = Self::new(context, cfg);
        network
            .register_tracked_peer_set(
                0,
                TrackedPeers::new(
                    Set::from_iter_dedup(primary),
                    Set::from_iter_dedup(secondary),
                ),
            )
            .await;
        (network, oracle)
    }

    /// Apply a tracked peer set to network state.
    async fn register_tracked_peer_set(&mut self, id: u64, peers: TrackedPeers<P>) -> bool {
        let primary = peers.primary;
        let secondary = peers.secondary;
        let tracked_peer_sets = self.tracked_peer_sets;

        // Check if peer set already exists
        if self.peer_sets.contains_key(&id) {
            warn!(id, "peer set already exists");
            return false;
        }

        // Ensure that peer set is monotonically increasing
        if let Some((last, _)) = self.peer_sets.last_key_value() {
            if id <= *last {
                warn!(
                    new_id = id,
                    old_id = last,
                    "attempted to register peer set with non-monotonically increasing ID"
                );
                return false;
            }
        }

        // Create and store new primary peer set.
        for public_key in primary.iter() {
            self.ensure_peer_exists(public_key).await;
            self.peer_ref_counts
                .entry(public_key.clone())
                .or_default()
                .primary += 1;
        }

        // Secondary peers: Peers in both roles count only as primary.
        let secondary_filtered = Set::from_iter_dedup(
            secondary
                .iter()
                .filter(|s| primary.position(s).is_none())
                .cloned(),
        );
        for public_key in secondary_filtered.iter() {
            self.ensure_peer_exists(public_key).await;
            self.peer_ref_counts
                .entry(public_key.clone())
                .or_default()
                .secondary += 1;
        }
        self.peer_sets.insert(
            id,
            PeerSetsAtIndex {
                primary: primary.clone(),
                secondary: secondary_filtered,
            },
        );

        // Remove oldest tracked peer sets if we exceed the limit.
        while self.peer_sets.len() > tracked_peer_sets.get() {
            let (removed_index, sets) = self.peer_sets.pop_first().unwrap();
            debug!(index = removed_index, "removed oldest tracked peer sets");

            for public_key in sets.primary.iter() {
                let counts = self
                    .peer_ref_counts
                    .get_mut(public_key)
                    .expect("reference map out of sync with peer sets");
                counts.primary = counts
                    .primary
                    .checked_sub(1)
                    .expect("reference count underflow");
                if counts.primary == 0 && counts.secondary == 0 {
                    self.peer_ref_counts.remove(public_key);
                    debug!(
                        ?public_key,
                        "removed peer no longer in any tracked peer set"
                    );
                }
            }

            for public_key in sets.secondary.iter() {
                let counts = self
                    .peer_ref_counts
                    .get_mut(public_key)
                    .expect("reference map out of sync with peer sets");
                counts.secondary = counts
                    .secondary
                    .checked_sub(1)
                    .expect("reference count underflow");
                if counts.primary == 0 && counts.secondary == 0 {
                    self.peer_ref_counts.remove(public_key);
                    debug!(
                        ?public_key,
                        "removed peer no longer in any tracked peer set"
                    );
                }
            }
        }

        true
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
    async fn handle_ingress(&mut self, message: ingress::Message<P, E>) {
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
            ingress::Message::Track { id, peers } => {
                if !self.register_tracked_peer_set(id, peers).await {
                    return;
                }

                // Notify all subscribers about the new peer set.
                let update = self
                    .latest_update()
                    .expect("latest update missing after successful track");
                self.subscribers
                    .retain(|subscriber| subscriber.send_lossy(update.clone()));

                // Broadcast updated tracked membership to SubscribeConnected subscribers
                self.broadcast_peer_list();
            }
            ingress::Message::Register {
                channel,
                public_key,
                quota,
                result,
            } => {
                // If peer does not exist, then create it.
                let _ = self.ensure_peer_exists(&public_key).await;

                // Get clock for the rate limiter
                let clock = self
                    .context
                    .child("rate_limiter")
                    .with_attribute("channel", channel)
                    .with_attribute("peer", &public_key);

                // Create a sender that allows sending messages to the network for a certain channel
                let (sender, handle) = Sender::new(
                    self.context.child("sender"),
                    public_key.clone(),
                    channel,
                    self.max_size,
                    self.sender.clone(),
                    self.oracle_mailbox.clone(),
                    clock,
                    quota,
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
                let _ = response.send(
                    self.peer_sets
                        .get(&id)
                        .map(|e| TrackedPeers::new(e.primary.clone(), e.secondary.clone())),
                );
            }
            ingress::Message::Subscribe { response } => {
                // Create a new subscription channel
                let (sender, receiver) = mpsc::unbounded_channel();

                // Send the latest peer set upon subscription.
                if let Some(update) = self.latest_update() {
                    sender.send_lossy(update);
                }
                self.subscribers.push(sender);

                // Return the receiver to the caller
                let _ = response.send(receiver);
            }
            ingress::Message::SubscribeConnected { response } => {
                // Create a ring channel for the subscriber
                let (mut sender, receiver) = ring::channel(NZUsize!(1));

                // Send current peer list immediately
                let peer_list = self.all_connected_peers();
                let _ = Pin::new(&mut sender).start_send(peer_list);

                // Store sender for future broadcasts
                self.peer_subscribers.push(sender);

                // Return the receiver to the subscriber
                let _ = response.send(receiver);
            }
            ingress::Message::LimitBandwidth {
                public_key,
                egress_cap,
                ingress_cap,
                result,
            } => {
                // If peer does not exist, then create it.
                let _ = self.ensure_peer_exists(&public_key).await;

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
                let _ = self.ensure_peer_exists(&sender).await;
                let (receiver_socket, _) = self.ensure_peer_exists(&receiver).await;

                // Require link to not already exist
                let key = (sender.clone(), receiver.clone());
                if self.links.contains_key(&key) {
                    return send_result(result, Err(Error::LinkExists));
                }

                let link = Link::new(
                    self.context.as_mut(),
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
    /// Returns the socket address of the peer and a boolean indicating if a new peer was created.
    async fn ensure_peer_exists(&mut self, public_key: &P) -> (SocketAddr, bool) {
        if !self.peers.contains_key(public_key) {
            // Create peer
            let socket = self.get_next_socket();
            let peer = Peer::new(
                self.context.child("peer"),
                public_key.clone(),
                socket,
                self.max_size,
            )
            .await;

            // Once ready, add to peers
            self.peers.insert(public_key.clone(), peer);

            (socket, true)
        } else {
            (self.peers.get(public_key).unwrap().socket, false)
        }
    }

    /// Broadcast updated peer list to all [`ingress::Message::SubscribeConnected`] subscribers.
    ///
    /// This runs when tracked membership changes ([`ingress::Message::Track`]), not when peers
    /// are first discovered via register, links, or bandwidth limits.
    ///
    /// Subscribers whose receivers have been dropped are removed to prevent
    /// memory leaks.
    fn broadcast_peer_list(&mut self) {
        let peer_list = self.all_connected_peers();
        let mut live_subscribers = Vec::with_capacity(self.peer_subscribers.len());
        for mut subscriber in self.peer_subscribers.drain(..) {
            if Pin::new(&mut subscriber)
                .start_send(peer_list.clone())
                .is_ok()
            {
                live_subscribers.push(subscriber);
            }
        }
        self.peer_subscribers = live_subscribers;
    }

    /// Primary and secondary peers across all tracked peer sets (reference-counted union).
    ///
    /// Primary wins over secondary for the same public key: `secondary` includes only peers whose
    /// only role across tracked sets is secondary (same as [`crate::Provider::subscribe`] for [`PeerSetUpdate::all`]).
    fn aggregate_peer_membership(&self) -> TrackedPeers<P> {
        let primary = self
            .peer_ref_counts
            .iter()
            .filter(|(_, c)| c.primary > 0)
            .map(|(k, _)| k.clone())
            .try_collect()
            .expect("BTreeMap keys are unique");
        let secondary = Set::from_iter_dedup(
            self.peer_ref_counts
                .iter()
                .filter(|(_, c)| c.secondary > 0 && c.primary == 0)
                .map(|(k, _)| k.clone()),
        );
        TrackedPeers::new(primary, secondary)
    }

    /// Returns a [`PeerSetUpdate`] for the latest peer set (by id), if any.
    fn latest_update(&self) -> Option<PeerSetUpdate<P>> {
        let (index, entry) = self.peer_sets.last_key_value()?;
        Some(PeerSetUpdate {
            index: *index,
            latest: TrackedPeers::new(entry.primary.clone(), entry.secondary.clone()),
            all: self.aggregate_peer_membership(),
        })
    }

    /// Peers used when expanding [`Recipients::All`].
    ///
    /// Every peer in a tracked peer set is treated as reachable for broadcast.
    /// Primary peers still drive primary-only behavior such as dialing; peers listed only as
    /// secondary still receive [`Recipients::All`] traffic, which matches how tests use this
    /// network.
    fn all_connected_peers(&self) -> Vec<P> {
        self.peer_ref_counts.keys().cloned().collect()
    }

    /// Returns whether the peer is currently allowed to use the network.
    fn is_connectable(&self, peer: &P) -> bool {
        self.peer_ref_counts.contains_key(peer)
    }
}

impl<E: RNetwork + Spawner + Rng + Clock + Metrics, P: PublicKey> Network<E, P> {
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
        let (channel, origin, recipients, message, reply) = task;

        // If tracking peer sets, ensure recipient and sender are in a tracked peer set
        if !self.is_connectable(&origin) {
            warn!(
                ?origin,
                reason = "not primary or secondary",
                "dropping message"
            );
            if let Some(reply) = reply {
                if let Err(err) = reply.send(Vec::new()) {
                    error!(?err, "failed to send ack");
                }
            }
            return;
        }

        // Collect recipients
        let recipients = match recipients {
            Recipients::All => self.all_connected_peers(),
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

            if !self.is_connectable(&recipient) {
                trace!(
                    ?origin,
                    ?recipient,
                    reason = "not primary or secondary",
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

            // Note: Rate limiting is handled by the Sender before messages reach here.
            // The Sender filters recipients via LimitedSender::check() or in Sender::send().

            // Record sent message as soon as we determine there is a link with recipient (approximates
            // having an open connection)
            self.sent_messages
                .get_or_create(&metrics::Message::new(&origin, &recipient, channel))
                .inc();

            // Sample latency
            let latency = Duration::from_millis(link.sampler.sample(self.context.as_mut()) as u64);

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
        if let Some(reply) = reply {
            if let Err(err) = reply.send(sent) {
                error!(?err, "failed to send ack");
            }
        }
    }

    /// Run the simulated network.
    ///
    /// It is not necessary to invoke this method before modifying the network topology, however,
    /// no messages will be sent until this method is called.
    pub fn start(mut self) -> Handle<()> {
        spawn_cell!(self.context, self.run())
    }

    async fn run(mut self) {
        select_loop! {
            self.context,
            on_start => {
                let tick = match self.transmitter.next() {
                    Some(when) => Either::Left(self.context.sleep_until(when)),
                    None => Either::Right(future::pending()),
                };
            },
            on_stopped => {},
            _ = tick => {
                let now = self.context.current();
                let completions = self.transmitter.advance(now);
                self.process_completions(completions);
            },
            Some(message) = self.ingress.recv() else break => {
                self.handle_ingress(message).await;
            },
            Some(task) = self.receiver.recv() else break => {
                self.handle_task(task);
            },
        }
    }
}

/// Provides online peers from the simulated network.
///
/// Implements [`crate::utils::limited::Connected`] to provide peer list updates
/// to [`crate::utils::limited::LimitedSender`].
pub struct ConnectedPeerProvider<P: PublicKey, E: Clock> {
    mailbox: Mailbox<ingress::Message<P, E>>,
}

impl<P: PublicKey, E: Clock> Clone for ConnectedPeerProvider<P, E> {
    fn clone(&self) -> Self {
        Self {
            mailbox: self.mailbox.clone(),
        }
    }
}

impl<P: PublicKey, E: Clock> ConnectedPeerProvider<P, E> {
    fn new(mailbox: Mailbox<ingress::Message<P, E>>) -> Self {
        Self { mailbox }
    }
}

impl<P: PublicKey, E: Clock> Connected for ConnectedPeerProvider<P, E> {
    type PublicKey = P;

    async fn subscribe(&mut self) -> ring::Receiver<Vec<Self::PublicKey>> {
        let (response, receiver) = oneshot::channel();
        match self
            .mailbox
            .enqueue(ingress::Message::SubscribeConnected { response })
        {
            Enqueue::Queued | Enqueue::Replaced => receiver.await.unwrap_or_else(|_| {
                let (_sender, receiver) = ring::channel(NZUsize!(1));
                receiver
            }),
            Enqueue::Dropped | Enqueue::Rejected | Enqueue::Closed => {
                let (_sender, receiver) = ring::channel(NZUsize!(1));
                receiver
            }
        }
    }
}

/// Implementation of a [crate::Sender] for the simulated network without rate limiting.
///
/// This is the inner sender used by [`Sender`] which wraps it with rate limiting.
#[derive(Clone)]
pub struct UnlimitedSender<P: PublicKey> {
    me: P,
    channel: Channel,
    max_size: u32,
    high: mpsc::UnboundedSender<Task<P>>,
    low: mpsc::UnboundedSender<Task<P>>,
}

impl<P: PublicKey> crate::UnlimitedSender for UnlimitedSender<P> {
    type Error = Error;
    type PublicKey = P;

    async fn send(
        &mut self,
        recipients: Recipients<P>,
        message: impl Into<IoBufs> + Send,
        priority: bool,
    ) -> Result<Vec<P>, Error> {
        let message = message.into().coalesce();

        // Check message size
        if message.len() > self.max_size as usize {
            return Err(Error::MessageTooLarge(message.len()));
        }

        // Send message
        let (sender, receiver) = oneshot::channel();
        let channel = if priority { &self.high } else { &self.low };
        if channel
            .send((
                self.channel,
                self.me.clone(),
                recipients,
                message,
                Some(sender),
            ))
            .is_err()
        {
            return Ok(Vec::new());
        }
        Ok(receiver.await.unwrap_or_default())
    }
}

impl<P: PublicKey> crate::MailboxSender for UnlimitedSender<P> {
    type PublicKey = P;

    fn send(
        &self,
        recipients: Recipients<P>,
        message: impl Into<IoBufs> + Send,
        priority: bool,
    ) -> Enqueue {
        let message = message.into().coalesce();

        if message.len() > self.max_size as usize {
            return Enqueue::Rejected;
        }

        let channel = if priority { &self.high } else { &self.low };
        if channel
            .send((self.channel, self.me.clone(), recipients, message, None))
            .is_err()
        {
            return Enqueue::Closed;
        }
        Enqueue::Queued
    }
}

/// Implementation of a [crate::Sender] for the simulated network.
///
/// Also implements [crate::LimitedSender] to support rate-limit checking
/// before sending messages.
pub struct Sender<P: PublicKey, E: Clock> {
    limited_sender: LimitedSender<E, UnlimitedSender<P>, ConnectedPeerProvider<P, E>>,
    mailbox_sender: UnlimitedSender<P>,
}

impl<P: PublicKey, E: Clock> Clone for Sender<P, E> {
    fn clone(&self) -> Self {
        Self {
            limited_sender: self.limited_sender.clone(),
            mailbox_sender: self.mailbox_sender.clone(),
        }
    }
}

impl<P: PublicKey, E: Clock> Debug for Sender<P, E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sender").finish_non_exhaustive()
    }
}

impl<P: PublicKey, E: Clock> Sender<P, E> {
    #[allow(clippy::too_many_arguments)]
    fn new(
        context: impl Spawner + Metrics,
        me: P,
        channel: Channel,
        max_size: u32,
        sender: mpsc::UnboundedSender<Task<P>>,
        oracle_mailbox: Mailbox<ingress::Message<P, E>>,
        clock: E,
        quota: Quota,
    ) -> (Self, Handle<()>) {
        // Listen for messages
        let (high, mut high_receiver) = mpsc::unbounded_channel();
        let (low, mut low_receiver) = mpsc::unbounded_channel();
        let processor = context.child("processor").spawn(move |_| async move {
            loop {
                // Wait for task
                let task;
                select! {
                    high_task = high_receiver.recv() => {
                        task = match high_task {
                            Some(task) => task,
                            None => break,
                        };
                    },
                    low_task = low_receiver.recv() => {
                        task = match low_task {
                            Some(task) => task,
                            None => break,
                        };
                    },
                }

                // Send task
                if let Err(err) = sender.send(task) {
                    error!(?err, channel, "failed to send task");
                }
            }
        });

        let unlimited_sender = UnlimitedSender {
            me,
            channel,
            max_size,
            high,
            low,
        };
        let peer_source = ConnectedPeerProvider::new(oracle_mailbox);
        let limited_sender = LimitedSender::new(unlimited_sender.clone(), quota, clock, peer_source);

        (
            Self {
                limited_sender,
                mailbox_sender: unlimited_sender,
            },
            processor,
        )
    }

    /// Split this [Sender] into a [SplitOrigin::Primary] and [SplitOrigin::Secondary] sender.
    pub fn split_with<F: SplitForwarder<P>>(
        self,
        forwarder: F,
    ) -> (SplitSender<P, E, F>, SplitSender<P, E, F>) {
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

impl<P: PublicKey, E: Clock + Send + 'static> crate::MailboxSender for Sender<P, E> {
    type PublicKey = P;

    fn send(
        &self,
        recipients: Recipients<Self::PublicKey>,
        message: impl Into<IoBufs> + Send,
        priority: bool,
    ) -> Enqueue {
        <UnlimitedSender<P> as crate::MailboxSender>::send(
            &self.mailbox_sender,
            recipients,
            message,
            priority,
        )
    }
}

impl<P: PublicKey, E: Clock> crate::LimitedSender for Sender<P, E> {
    type PublicKey = P;
    type Checked<'a>
        = crate::utils::limited::CheckedSender<'a, UnlimitedSender<P>>
    where
        Self: 'a;

    async fn check(
        &mut self,
        recipients: Recipients<Self::PublicKey>,
    ) -> Result<Self::Checked<'_>, SystemTime> {
        self.limited_sender.check(recipients).await
    }
}

/// A sender that routes recipients per message via a user-provided function.
pub struct SplitSender<P: PublicKey, E: Clock, F: SplitForwarder<P>> {
    replica: SplitOrigin,
    inner: Sender<P, E>,
    forwarder: F,
}

impl<P: PublicKey, E: Clock, F: SplitForwarder<P>> Clone for SplitSender<P, E, F> {
    fn clone(&self) -> Self {
        Self {
            replica: self.replica,
            inner: self.inner.clone(),
            forwarder: self.forwarder.clone(),
        }
    }
}

impl<P: PublicKey, E: Clock, F: SplitForwarder<P>> std::fmt::Debug for SplitSender<P, E, F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SplitSender")
            .field("replica", &self.replica)
            .field("inner", &self.inner)
            .finish()
    }
}

impl<P: PublicKey, E: Clock, F: SplitForwarder<P>> crate::LimitedSender for SplitSender<P, E, F> {
    type PublicKey = P;
    type Checked<'a> = SplitCheckedSender<'a, P, E, F>;

    async fn check(
        &mut self,
        recipients: Recipients<Self::PublicKey>,
    ) -> Result<Self::Checked<'_>, SystemTime> {
        Ok(SplitCheckedSender {
            // Perform a rate limit check with the entire set of original recipients although
            // the forwarder may filter these (based on message content) during send.
            checked: self.inner.limited_sender.check(recipients.clone()).await?,
            replica: self.replica,
            forwarder: self.forwarder.clone(),
            recipients,

            _phantom: std::marker::PhantomData,
        })
    }
}

impl<P, E, F> crate::MailboxSender for SplitSender<P, E, F>
where
    P: PublicKey,
    E: Clock + Send + 'static,
    F: SplitForwarder<P>,
{
    type PublicKey = P;

    fn send(
        &self,
        recipients: Recipients<Self::PublicKey>,
        message: impl Into<IoBufs> + Send,
        priority: bool,
    ) -> Enqueue {
        let message = message.into().coalesce();
        let Some(recipients) = (self.forwarder)(self.replica, &recipients, &message) else {
            return Enqueue::Dropped;
        };
        <Sender<P, E> as crate::MailboxSender>::send(&self.inner, recipients, message, priority)
    }
}

/// A checked sender for [`SplitSender`] that defers the forwarder call to send time.
///
/// This is necessary because [`SplitForwarder`] may examine message content to determine
/// routing, but the message is not available at [`LimitedSender::check`] time.
pub struct SplitCheckedSender<'a, P: PublicKey, E: Clock, F: SplitForwarder<P>> {
    checked: LimitedCheckedSender<'a, UnlimitedSender<P>>,
    replica: SplitOrigin,
    forwarder: F,
    recipients: Recipients<P>,

    _phantom: std::marker::PhantomData<E>,
}

impl<'a, P: PublicKey, E: Clock, F: SplitForwarder<P>> crate::CheckedSender
    for SplitCheckedSender<'a, P, E, F>
{
    type PublicKey = P;
    type Error = Error;

    async fn send(
        self,
        message: impl Into<IoBufs> + Send,
        priority: bool,
    ) -> Result<Vec<Self::PublicKey>, Self::Error> {
        // Convert to IoBuf here since forwarder needs to inspect the message
        let message = message.into().coalesce();

        // Determine the set of recipients that will receive the message
        let Some(recipients) = (self.forwarder)(self.replica, &self.recipients, &message) else {
            return Ok(Vec::new());
        };

        // Extract the inner sender and send directly with the new recipients
        //
        // While SplitForwarder does not enforce any relationship between the original recipients
        // and the new recipients, it is typically some subset of the original recipients. This
        // means we may over-rate limit some recipients (who are never actually sent a message here) but
        // we prefer this to not providing feedback at all (we would have to skip check entirely).
        self.checked
            .into_inner()
            .send(recipients, message, priority)
            .await
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
        self.receiver.recv().await.ok_or(Error::NetworkClosed)
    }
}

impl<P: PublicKey> Receiver<P> {
    /// Split this [Receiver] into a [SplitTarget::Primary] and [SplitTarget::Secondary] receiver.
    pub fn split_with<E: Spawner, R: SplitRouter<P>>(
        mut self,
        context: E,
        router: R,
    ) -> (Self, Self) {
        let (primary_tx, primary_rx) = mpsc::unbounded_channel();
        let (secondary_tx, secondary_rx) = mpsc::unbounded_channel();
        context.spawn(move |_| async move {
            while let Some(message) = self.receiver.recv().await {
                // Route message to the appropriate target
                let direction = router(&message);
                match direction {
                    SplitTarget::None => {}
                    SplitTarget::Primary => {
                        if let Err(err) = primary_tx.send(message) {
                            error!(?err, "failed to send message to primary");
                        }
                    }
                    SplitTarget::Secondary => {
                        if let Err(err) = secondary_tx.send(message) {
                            error!(?err, "failed to send message to secondary");
                        }
                    }
                    SplitTarget::Both => {
                        if let Err(err) = primary_tx.send(message.clone()) {
                            error!(?err, "failed to send message to primary");
                        }
                        if let Err(err) = secondary_tx.send(message) {
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
        max_size: u32,
    ) -> Self {
        // The control is used to register channels.
        // There is exactly one mailbox created for each channel that the peer is registered for.
        #[allow(clippy::type_complexity)]
        let (control_sender, mut control_receiver): (
            mpsc::UnboundedSender<(Channel, Handle<()>, oneshot::Sender<MessageReceiver<P>>)>,
            _,
        ) = mpsc::unbounded_channel();

        // Whenever a message is received from a peer, it is placed in the inbox.
        // The router polls the inbox and forwards the message to the appropriate mailbox.
        let (inbox_sender, mut inbox_receiver) = mpsc::unbounded_channel();

        // Spawn router
        context.child("router").spawn(|context| async move {
            // Map of channels to mailboxes (senders to particular channels)
            let mut mailboxes = HashMap::new();

            // Continually listen for control messages and outbound messages
            select_loop! {
                context,
                on_stopped => {},
                // Listen for control messages, which are used to register channels
                Some((channel, sender, result_tx)) = control_receiver.recv() else break => {
                    // Register channel
                    let (receiver_tx, receiver_rx) = mpsc::unbounded_channel();
                    if let Some((_, existing_sender)) =
                        mailboxes.insert(channel, (receiver_tx, sender))
                    {
                        warn!(?public_key, ?channel, "overwriting existing channel");
                        existing_sender.abort();
                    }
                    result_tx.send(receiver_rx).unwrap();
                },

                // Listen for messages from the inbox, which are forwarded to the appropriate mailbox
                Some((channel, message)) = inbox_receiver.recv() else break => {
                    // Send message to mailbox
                    match mailboxes.get_mut(&channel) {
                        Some((receiver_tx, _)) => {
                            if let Err(err) = receiver_tx.send(message) {
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
        context.child("listener").spawn(move |context| async move {
            // Initialize listener
            let mut listener = context.bind(socket).await.unwrap();
            let _ = ready_tx.send(());

            // Continually accept new connections
            while let Ok((_, _, mut stream)) = listener.accept().await {
                // New connection accepted. Spawn a task for this connection
                context.child("receiver").spawn({
                    let inbox_sender = inbox_sender.clone();
                    move |_| async move {
                        // Receive dialer's public key as a handshake
                        let dialer = match recv_frame(&mut stream, max_size).await {
                            Ok(data) => data,
                            Err(_) => {
                                error!("failed to receive public key from dialer");
                                return;
                            }
                        };
                        let Ok(dialer) = P::decode(dialer.coalesce()) else {
                            error!("received public key is invalid");
                            return;
                        };

                        // Continually receive messages from the dialer and send them to the inbox
                        while let Ok(data) = recv_frame(&mut stream, max_size).await {
                            let data = data.coalesce();
                            let channel = Channel::from_be_bytes(
                                data.as_ref()[..Channel::SIZE].try_into().unwrap(),
                            );
                            let message = data.slice(Channel::SIZE..);
                            if let Err(err) =
                                inbox_sender.send((channel, (dialer.clone(), message)))
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
    inbox: mpsc::UnboundedSender<(Channel, IoBuf, SystemTime)>,
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
        max_size: u32,
        received_messages: CounterFamily<metrics::Message>,
    ) -> Self {
        // Spawn a task that will wait for messages to be sent to the link and then send them
        // over the network.
        let (inbox, mut outbox) = mpsc::unbounded_channel::<(Channel, IoBuf, SystemTime)>();
        context.child("link").spawn(move |context| async move {
            // Dial the peer and handshake by sending it the dialer's public key
            let (mut sink, _) = context.dial(socket).await.unwrap();
            if let Err(err) = send_frame(&mut sink, dialer.as_ref().to_vec(), max_size).await {
                error!(?err, "failed to send public key to listener");
                return;
            }

            // Process messages in order, waiting for their receive time
            while let Some((channel, message, receive_complete_at)) = outbox.recv().await {
                // Wait until the message should arrive at receiver
                context.sleep_until(receive_complete_at).await;

                // Send the message
                let channel_bytes = channel.to_be_bytes();
                let mut data = Vec::with_capacity(channel_bytes.len() + message.len());
                data.extend_from_slice(&channel_bytes);
                data.extend_from_slice(message.as_ref());
                let _ = send_frame(&mut sink, data, max_size).await;

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
        message: IoBuf,
        receive_complete_at: SystemTime,
    ) -> Result<(), Error> {
        self.inbox
            .send((channel, message, receive_complete_at))
            .map_err(|_| Error::NetworkClosed)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Manager as _, Provider, Receiver as _, Recipients, Sender as _, TrackedPeers};
    use commonware_cryptography::{ed25519, Signer as _};
    use commonware_runtime::{deterministic, Quota, Runner as _, Supervisor as _};
    use commonware_utils::{ordered::Set, NZUsize};
    use futures::FutureExt;
    use std::num::NonZeroU32;

    const MAX_MESSAGE_SIZE: u32 = 1024 * 1024;

    /// Default rate limit set high enough to not interfere with normal operation
    const TEST_QUOTA: Quota = Quota::per_second(NonZeroU32::MAX);

    /// [`Network::new_with_peers`] seeds peers; controls can register channels and add a link once;
    /// a duplicate link between the same pair returns [`Error::LinkExists`].
    #[test]
    fn test_register_and_link() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                max_size: MAX_MESSAGE_SIZE,
                disconnect_on_block: true,
                tracked_peer_sets: NZUsize!(3),
            };
            // Create two public keys
            let pk1 = ed25519::PrivateKey::from_seed(1).public_key();
            let pk2 = ed25519::PrivateKey::from_seed(2).public_key();
            let peers = [pk1.clone(), pk2.clone()];

            let (network, oracle) =
                Network::new_with_peers(context.child("network"), cfg, peers).await;
            network.start();

            let control = oracle.control(pk1.clone());
            control.register(0, TEST_QUOTA).await.unwrap();
            control.register(1, TEST_QUOTA).await.unwrap();
            let control = oracle.control(pk2.clone());
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

    /// [`Network::new_with_split_peers`] registers id `0` with separate primary and secondary sets,
    /// exposes the same split from [`Manager::peer_set`], and emits a matching [`PeerSetUpdate`] on subscribe.
    #[test]
    fn test_new_with_split_peers_seeds_initial_update() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                max_size: MAX_MESSAGE_SIZE,
                disconnect_on_block: true,
                tracked_peer_sets: NZUsize!(3),
            };
            let primary = ed25519::PrivateKey::from_seed(11).public_key();
            let secondary = ed25519::PrivateKey::from_seed(12).public_key();

            let (network, oracle) = Network::new_with_split_peers(
                context.child("network"),
                cfg,
                [primary.clone()],
                [secondary.clone()],
            )
            .await;
            network.start();

            let mut manager = oracle.manager();
            let peer_set = manager.peer_set(0).await.unwrap();
            assert_eq!(peer_set.primary, Set::try_from([primary.clone()]).unwrap());
            assert_eq!(
                peer_set.secondary,
                Set::try_from([secondary.clone()]).unwrap()
            );

            let mut updates = manager.subscribe().await;
            let update = updates.recv().await.unwrap();
            assert_eq!(update.index, 0);
            assert_eq!(
                update.latest.primary,
                Set::try_from([primary.clone()]).unwrap()
            );
            assert_eq!(
                update.latest.secondary,
                Set::try_from([secondary.clone()]).unwrap()
            );
            assert_eq!(update.all.primary, Set::try_from([primary]).unwrap());
            assert_eq!(update.all.secondary, Set::try_from([secondary]).unwrap());
        });
    }

    /// Split sender/receiver routes each half to a different neighbor: primary out goes only to `peer_a`,
    /// secondary out only to `peer_b`, and inbound mail is demuxed by sender id.
    #[test]
    fn test_split_channel_single() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                max_size: MAX_MESSAGE_SIZE,
                disconnect_on_block: true,
                tracked_peer_sets: NZUsize!(3),
            };
            let (network, oracle) = Network::new(context.child("network"), cfg);
            network.start();

            // Create a "twin" node that will be split, plus two normal peers
            let twin = ed25519::PrivateKey::from_seed(20).public_key();
            let peer_a = ed25519::PrivateKey::from_seed(21).public_key();
            let peer_b = ed25519::PrivateKey::from_seed(22).public_key();

            // Register all peers
            let mut manager = oracle.manager();
            manager
                .track(
                    0,
                    Set::try_from([twin.clone(), peer_a.clone(), peer_b.clone()]).unwrap(),
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
            let (mut twin_primary_recv, mut twin_secondary_recv) =
                twin_receiver.split_with(context.child("split_receiver"), move |(sender, _)| {
                    if sender == &peer_a_for_recv {
                        SplitTarget::Primary
                    } else if sender == &peer_b_for_recv {
                        SplitTarget::Secondary
                    } else {
                        panic!("unexpected sender");
                    }
                });

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
            peer_a_sender
                .send(Recipients::One(twin.clone()), b"from_a", false)
                .await
                .unwrap();
            peer_b_sender
                .send(Recipients::One(twin.clone()), b"from_b", false)
                .await
                .unwrap();
            twin_primary_sender
                .send(Recipients::All, b"primary_out", false)
                .await
                .unwrap();
            twin_secondary_sender
                .send(Recipients::All, b"secondary_out", false)
                .await
                .unwrap();

            // Verify routing: peer_a messages go to primary, peer_b to secondary
            let (sender, payload) = twin_primary_recv.recv().await.unwrap();
            assert_eq!(sender, peer_a);
            assert_eq!(payload, b"from_a");
            let (sender, payload) = twin_secondary_recv.recv().await.unwrap();
            assert_eq!(sender, peer_b);
            assert_eq!(payload, b"from_b");

            // Verify routing: primary sends to peer_a, secondary to peer_b
            let (sender, payload) = peer_a_recv.recv().await.unwrap();
            assert_eq!(sender, twin);
            assert_eq!(payload, b"primary_out");
            let (sender, payload) = peer_b_recv.recv().await.unwrap();
            assert_eq!(sender, twin);
            assert_eq!(payload, b"secondary_out");
        });
    }

    /// When both split halves use [`SplitTarget::Both`], a single inbound message is delivered to primary and secondary receivers.
    #[test]
    fn test_split_channel_both() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                max_size: MAX_MESSAGE_SIZE,
                disconnect_on_block: true,
                tracked_peer_sets: NZUsize!(3),
            };
            let (network, oracle) = Network::new(context.child("network"), cfg);
            network.start();

            // Create a "twin" node that will be split, plus a third peer
            let twin = ed25519::PrivateKey::from_seed(30).public_key();
            let peer_c = ed25519::PrivateKey::from_seed(31).public_key();

            // Register all peers
            let mut manager = oracle.manager();
            manager
                .track(0, Set::try_from([twin.clone(), peer_c.clone()]).unwrap())
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
                .split_with(context.child("split_receiver_both"), |_| SplitTarget::Both);

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
            peer_c_sender
                .send(Recipients::One(twin.clone()), b"to_both", false)
                .await
                .unwrap();

            // Verify both receivers get the message
            let (sender, payload) = twin_primary_recv.recv().await.unwrap();
            assert_eq!(sender, peer_c);
            assert_eq!(payload, b"to_both");
            let (sender, payload) = twin_secondary_recv.recv().await.unwrap();
            assert_eq!(sender, peer_c);
            assert_eq!(payload, b"to_both");
        });
    }

    /// [`SplitTarget::None`] and a send router returning `None` drop traffic: inbound is not delivered to either half,
    /// and outbound sends report no recipients.
    #[test]
    fn test_split_channel_none() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                max_size: MAX_MESSAGE_SIZE,
                disconnect_on_block: true,
                tracked_peer_sets: NZUsize!(3),
            };
            let (network, oracle) = Network::new(context.child("network"), cfg);
            network.start();

            // Create a "twin" node that will be split, plus a third peer
            let twin = ed25519::PrivateKey::from_seed(30).public_key();
            let peer_c = ed25519::PrivateKey::from_seed(31).public_key();

            // Register all peers
            let mut manager = oracle.manager();
            manager
                .track(0, Set::try_from([twin.clone(), peer_c.clone()]).unwrap())
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
                .split_with(context.child("split_receiver_both"), |_| SplitTarget::None);

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
            let sent = peer_c_sender
                .send(Recipients::One(twin.clone()), b"to_both", false)
                .await
                .unwrap();
            assert_eq!(sent.len(), 1);
            assert_eq!(sent[0], twin);

            // Verify both receivers get the message
            context.sleep(Duration::from_millis(100)).await;
            assert!(twin_primary_recv.recv().now_or_never().is_none());
            assert!(twin_secondary_recv.recv().now_or_never().is_none());

            // Send a message from twin to peer_c
            let sent = twin_primary_sender
                .send(Recipients::One(peer_c.clone()), b"to_both", false)
                .await
                .unwrap();
            assert_eq!(sent.len(), 0);

            // Send a message from twin to peer_c
            let sent = twin_secondary_sender
                .send(Recipients::One(peer_c.clone()), b"to_both", false)
                .await
                .unwrap();
            assert_eq!(sent.len(), 0);
        });
    }

    /// [`Manager::track`] indices may arrive out of order: older indices are ignored; subscribers see updates in commit order
    /// and [`PeerSetUpdate::all`] accumulates primaries across applied sets.
    #[test]
    fn test_unordered_peer_sets() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                max_size: MAX_MESSAGE_SIZE,
                disconnect_on_block: true,
                tracked_peer_sets: NZUsize!(3),
            };
            let (network, oracle) = Network::new(context.child("network"), cfg);
            network.start();

            // Create two public keys
            let pk1 = ed25519::PrivateKey::from_seed(1).public_key();
            let pk2 = ed25519::PrivateKey::from_seed(2).public_key();

            // Subscribe to peer sets
            let mut manager = oracle.manager();
            let mut subscription = manager.subscribe().await;

            // Register initial peer set
            manager
                .track(10, Set::try_from([pk1.clone(), pk2.clone()]).unwrap())
                .await;
            let update = subscription.recv().await.unwrap();
            assert_eq!(update.index, 10);
            assert_eq!(update.latest.primary.len(), 2);
            assert!(update.latest.secondary.is_empty());
            assert_eq!(update.all.primary.len(), 2);
            assert!(update.all.secondary.is_empty());

            // Register old peer sets (ignored)
            let pk3 = ed25519::PrivateKey::from_seed(3).public_key();
            manager
                .track(9, Set::try_from([pk3.clone()]).unwrap())
                .await;

            // Add new peer set
            let pk4 = ed25519::PrivateKey::from_seed(4).public_key();
            manager
                .track(11, Set::try_from([pk4.clone()]).unwrap())
                .await;
            let update = subscription.recv().await.unwrap();
            assert_eq!(update.index, 11);
            assert_eq!(update.latest.primary, Set::try_from([pk4.clone()]).unwrap());
            assert!(update.latest.secondary.is_empty());
            assert_eq!(update.all.primary, Set::try_from([pk1, pk2, pk4]).unwrap());
            assert!(update.all.secondary.is_empty());
        });
    }

    /// [`PeerSetUpdate::all`] uses primary-wins across *tracked* indices: a peer who is primary in one
    /// peer set and secondary in another is listed only under `all.primary` (not in `all.secondary`).
    #[test]
    fn test_peer_set_update_all_cross_index_primary_wins() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                max_size: MAX_MESSAGE_SIZE,
                disconnect_on_block: true,
                tracked_peer_sets: NZUsize!(3),
            };
            let (network, oracle) = Network::new(context.child("network"), cfg);
            network.start();

            let pk_a = ed25519::PrivateKey::from_seed(21).public_key();
            let pk_b = ed25519::PrivateKey::from_seed(22).public_key();
            // Appears as primary in set 10 and (redundantly) as secondary in set 11.
            let pk_overlap = ed25519::PrivateKey::from_seed(23).public_key();
            // Secondary-only in set 11; should still appear under aggregate secondary.
            let pk_sec = ed25519::PrivateKey::from_seed(24).public_key();

            let mut manager = oracle.manager();
            let mut subscription = manager.subscribe().await;

            manager
                .track(
                    10,
                    TrackedPeers::new(
                        Set::try_from([pk_a.clone(), pk_overlap.clone()]).unwrap(),
                        Set::default(),
                    ),
                )
                .await;
            let _ = subscription.recv().await.unwrap();

            manager
                .track(
                    11,
                    TrackedPeers::new(
                        Set::try_from([pk_b.clone()]).unwrap(),
                        Set::try_from([pk_overlap.clone(), pk_sec.clone()]).unwrap(),
                    ),
                )
                .await;
            let update = subscription.recv().await.unwrap();
            assert_eq!(update.index, 11);

            assert_eq!(
                update.latest.primary,
                Set::try_from([pk_b.clone()]).unwrap()
            );
            // At index 11 alone, pk_overlap is secondary-only (primary at 11 is pk_b).
            assert!(update.latest.secondary.position(&pk_overlap).is_some());
            assert!(update.latest.secondary.position(&pk_sec).is_some());

            // Across tracked sets: pk_overlap is primary in set 10 -> aggregate lists them only under primary.
            assert!(update.all.primary.position(&pk_a).is_some());
            assert!(update.all.primary.position(&pk_b).is_some());
            assert!(update.all.primary.position(&pk_overlap).is_some());
            assert!(
                update.all.secondary.position(&pk_overlap).is_none(),
                "aggregate secondary must omit peers who have any primary membership"
            );
            assert!(update.all.secondary.position(&pk_sec).is_some());
        });
    }

    /// [`Network::get_next_socket`] hands out the current address then advances port, wrapping IPv4 and port at boundaries.
    #[test]
    fn test_get_next_socket() {
        let cfg = Config {
            max_size: MAX_MESSAGE_SIZE,
            disconnect_on_block: true,
            tracked_peer_sets: NZUsize!(1),
        };
        let runner = deterministic::Runner::default();

        runner.start(|context| async move {
            type PublicKey = ed25519::PublicKey;
            let (mut network, _) =
                Network::<deterministic::Context, PublicKey>::new(context.child("network"), cfg);

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

    /// Many sequential sends to one recipient arrive in order when symmetric per-link bandwidth limits apply.
    #[test]
    fn test_fifo_burst_same_recipient() {
        let cfg = Config {
            max_size: MAX_MESSAGE_SIZE,
            disconnect_on_block: true,
            tracked_peer_sets: NZUsize!(3),
        };
        let runner = deterministic::Runner::default();

        runner.start(|context| async move {
            let (network, oracle) = Network::new(context.child("network"), cfg);
            let network_handle = network.start();

            let sender_pk = ed25519::PrivateKey::from_seed(10).public_key();
            let recipient_pk = ed25519::PrivateKey::from_seed(11).public_key();

            let mut manager = oracle.manager();
            manager
                .track(
                    0,
                    Set::try_from([sender_pk.clone(), recipient_pk.clone()]).unwrap(),
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
                let msg = vec![i as u8; 64];
                sender
                    .send(Recipients::One(recipient_pk.clone()), msg.clone(), false)
                    .await
                    .unwrap();
                expected.push(msg);
            }

            for expected_msg in expected {
                let (_pk, bytes) = receiver.recv().await.unwrap();
                assert_eq!(bytes, expected_msg.as_slice());
            }

            drop(oracle);
            drop(sender);
            network_handle.abort();
        });
    }

    /// [`Recipients::All`] to two links shares the sender cap: both deliveries are delayed in line with the shared bandwidth model,
    /// not delivered back-to-back.
    #[test]
    fn test_broadcast_respects_transmit_latency() {
        let cfg = Config {
            max_size: MAX_MESSAGE_SIZE,
            disconnect_on_block: true,
            tracked_peer_sets: NZUsize!(3),
        };
        let runner = deterministic::Runner::default();

        runner.start(|context| async move {
            let (network, oracle) = Network::new(context.child("network"), cfg);
            let network_handle = network.start();

            let sender_pk = ed25519::PrivateKey::from_seed(42).public_key();
            let recipient_a = ed25519::PrivateKey::from_seed(43).public_key();
            let recipient_b = ed25519::PrivateKey::from_seed(44).public_key();

            let mut manager = oracle.manager();
            manager
                .track(
                    0,
                    Set::try_from([sender_pk.clone(), recipient_a.clone(), recipient_b.clone()])
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

            let big_msg = vec![7u8; 10_000];
            let start = context.current();
            sender
                .send(Recipients::All, big_msg.clone(), false)
                .await
                .unwrap();

            let (_pk, received_a) = recv_a.recv().await.unwrap();
            assert_eq!(received_a, big_msg.as_slice());
            let elapsed_a = context.current().duration_since(start).unwrap();
            assert!(elapsed_a >= Duration::from_secs(20));

            let (_pk, received_b) = recv_b.recv().await.unwrap();
            assert_eq!(received_b, big_msg.as_slice());
            let elapsed_b = context.current().duration_since(start).unwrap();
            assert!(elapsed_b >= Duration::from_secs(20));

            // Because bandwidth is shared, the two messages should take about the same time
            assert!(elapsed_a.abs_diff(elapsed_b) <= Duration::from_secs(1));

            drop(oracle);
            drop(sender);
            network_handle.abort();
        });
    }

    /// A peer listed in both primary and secondary appears only in [`PeerSetUpdate::latest`] primary; aggregate secondary omits
    /// primary keys. [`Recipients::All`] from another peer lists the overlap peer once and still reaches secondary-only peers.
    #[test]
    fn test_overlapping_primary_secondary_no_duplicate_recipients() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                max_size: MAX_MESSAGE_SIZE,
                disconnect_on_block: true,
                tracked_peer_sets: NZUsize!(3),
            };
            let (network, oracle) = Network::new(context.child("network"), cfg);
            network.start();

            let pk1 = ed25519::PrivateKey::from_seed(1).public_key();
            let pk2 = ed25519::PrivateKey::from_seed(2).public_key();
            let pk3 = ed25519::PrivateKey::from_seed(3).public_key();

            let mut manager = oracle.manager();
            manager
                .track(
                    0,
                    TrackedPeers::new(
                        Set::try_from([pk1.clone(), pk2.clone()]).unwrap(),
                        Set::try_from([pk2.clone(), pk3.clone()]).unwrap(),
                    ),
                )
                .await;

            let mut updates = manager.subscribe().await;
            let update = updates.recv().await.unwrap();
            assert_eq!(update.index, 0);
            assert!(update.latest.primary.position(&pk2).is_some());
            assert!(
                update.latest.secondary.position(&pk2).is_none(),
                "overlap peer must not appear in latest.secondary"
            );
            assert!(update.latest.secondary.position(&pk3).is_some());
            assert!(update.all.primary.position(&pk2).is_some());
            assert!(
                update.all.secondary.position(&pk2).is_none(),
                "aggregate secondary must not list peers who are primary"
            );
            assert!(update.all.secondary.position(&pk3).is_some());

            let link = ingress::Link {
                latency: Duration::from_millis(1),
                jitter: Duration::ZERO,
                success_rate: 1.0,
            };
            for (a, b) in [(&pk1, &pk2), (&pk1, &pk3), (&pk2, &pk3)] {
                oracle
                    .add_link(a.clone(), b.clone(), link.clone())
                    .await
                    .unwrap();
            }

            let (mut sender1, _) = oracle
                .control(pk1.clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();
            let (_, mut recv2) = oracle
                .control(pk2.clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();
            let (_, mut recv3) = oracle
                .control(pk3.clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();

            let msg = vec![42u8; 10];
            let sent_to = sender1
                .send(Recipients::All, msg.clone(), true)
                .await
                .unwrap();

            let pk2_count = sent_to.iter().filter(|pk| *pk == &pk2).count();
            assert_eq!(pk2_count, 1, "pk2 received duplicate sends");
            assert!(sent_to.iter().any(|pk| pk == &pk3));

            context.sleep(Duration::from_millis(10)).await;
            let (from2, data2) = recv2.recv().await.unwrap();
            assert_eq!(from2, pk1);
            assert_eq!(data2, msg.as_slice());
            let (from3, data3) = recv3.recv().await.unwrap();
            assert_eq!(from3, pk1);
            assert_eq!(data3, msg.as_slice());
            assert!(recv2.recv().now_or_never().is_none());
        });
    }

    /// A peer can be demoted from primary to secondary across tracked peer set indices.
    /// After the old primary-containing set is evicted, the peer is purely secondary.
    #[test]
    fn test_demotion_from_primary_to_secondary() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                max_size: 1024,
                disconnect_on_block: true,
                tracked_peer_sets: NZUsize!(2),
            };
            let (network, oracle) = Network::new(context.child("network"), cfg);
            network.start();

            let pk_x = ed25519::PrivateKey::from_seed(1).public_key();
            let pk_y = ed25519::PrivateKey::from_seed(2).public_key();

            let mut manager = oracle.manager();
            let mut sub = manager.subscribe().await;

            // Index 0: X is primary, Y is secondary.
            manager
                .track(
                    0,
                    TrackedPeers::new(
                        Set::try_from([pk_x.clone()]).unwrap(),
                        Set::try_from([pk_y.clone()]).unwrap(),
                    ),
                )
                .await;

            let update = sub.recv().await.unwrap();
            assert!(update.all.primary.position(&pk_x).is_some());
            assert!(update.all.secondary.position(&pk_y).is_some());

            // Index 1: X is demoted to secondary, Y is promoted to primary.
            manager
                .track(
                    1,
                    TrackedPeers::new(
                        Set::try_from([pk_y.clone()]).unwrap(),
                        Set::try_from([pk_x.clone()]).unwrap(),
                    ),
                )
                .await;

            // Both indices retained: both peers are primary somewhere -> aggregate primary.
            let update = sub.recv().await.unwrap();
            assert!(update.all.primary.position(&pk_x).is_some());
            assert!(update.all.primary.position(&pk_y).is_some());
            assert!(update.all.secondary.is_empty());

            // Index 2: same as index 1. Evicts index 0.
            manager
                .track(
                    2,
                    TrackedPeers::new(
                        Set::try_from([pk_y.clone()]).unwrap(),
                        Set::try_from([pk_x.clone()]).unwrap(),
                    ),
                )
                .await;

            // Index 0 evicted. X is now purely secondary.
            let update = sub.recv().await.unwrap();
            assert!(update.all.primary.position(&pk_y).is_some());
            assert!(update.all.secondary.position(&pk_x).is_some());
            assert!(update.all.primary.position(&pk_x).is_none());
        });
    }

    /// After advancing tracked peer sets, secondaries from an older snapshot remain addressable until evicted from history:
    /// a new primary can still reach them, while a newer-only primary does not receive messages intended for that tracked secondary view.
    #[test]
    fn test_secondary_sets_remain_until_eviction() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                max_size: MAX_MESSAGE_SIZE,
                disconnect_on_block: true,
                tracked_peer_sets: NZUsize!(2),
            };
            let (network, oracle) = Network::new(context.child("network"), cfg);
            network.start();

            let primary_0 = ed25519::PrivateKey::from_seed(1).public_key();
            let primary_1 = ed25519::PrivateKey::from_seed(2).public_key();
            let primary_2 = ed25519::PrivateKey::from_seed(3).public_key();
            let secondary_0 = ed25519::PrivateKey::from_seed(4).public_key();
            let secondary_1 = ed25519::PrivateKey::from_seed(5).public_key();

            let mut manager = oracle.manager();
            manager
                .track(
                    0,
                    TrackedPeers::new(
                        Set::try_from([primary_0.clone()]).unwrap(),
                        Set::try_from([secondary_0.clone()]).unwrap(),
                    ),
                )
                .await;
            manager
                .track(
                    1,
                    TrackedPeers::new(
                        Set::try_from([primary_1.clone()]).unwrap(),
                        Set::try_from([secondary_1.clone()]).unwrap(),
                    ),
                )
                .await;

            let link = ingress::Link {
                latency: Duration::from_millis(1),
                jitter: Duration::ZERO,
                success_rate: 1.0,
            };
            oracle
                .add_link(primary_1.clone(), secondary_0.clone(), link.clone())
                .await
                .unwrap();
            oracle
                .add_link(primary_1.clone(), secondary_1.clone(), link.clone())
                .await
                .unwrap();

            let (mut sender_1, _) = oracle
                .control(primary_1.clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();
            let (_, mut receiver_0) = oracle
                .control(secondary_0.clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();
            let (_, mut receiver_1) = oracle
                .control(secondary_1.clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();

            let msg_1 = vec![1u8; 8];
            sender_1
                .send(
                    Recipients::Some(vec![secondary_0.clone(), secondary_1.clone()]),
                    msg_1.clone(),
                    true,
                )
                .await
                .unwrap();
            assert_eq!(receiver_0.recv().await.unwrap().1, msg_1.as_slice());
            assert_eq!(receiver_1.recv().await.unwrap().1, msg_1.as_slice());

            crate::Manager::track(
                &mut manager,
                2,
                TrackedPeers::primary([primary_2.clone()].try_into().unwrap()),
            )
            .await;
            oracle
                .add_link(primary_2.clone(), secondary_0.clone(), link.clone())
                .await
                .unwrap();
            oracle
                .add_link(primary_2.clone(), secondary_1.clone(), link)
                .await
                .unwrap();

            let (mut sender_2, _) = oracle
                .control(primary_2)
                .register(0, TEST_QUOTA)
                .await
                .unwrap();

            let msg_2 = vec![2u8; 8];
            sender_2
                .send(
                    Recipients::Some(vec![secondary_0.clone(), secondary_1.clone()]),
                    msg_2.clone(),
                    true,
                )
                .await
                .unwrap();
            assert!(receiver_0.recv().now_or_never().is_none());
            assert_eq!(receiver_1.recv().await.unwrap().1, msg_2.as_slice());
        });
    }
}
