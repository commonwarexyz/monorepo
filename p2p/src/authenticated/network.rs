//! Implementation of an `authenticated` network.

use super::{
    actors::{dialer, listener, router, spawner, tracker},
    channels::{self, Channels},
    config::Config,
};
use crate::Channel;
use commonware_cryptography::Scheme;
use commonware_macros::select;
use commonware_runtime::{
    Clock, Handle, Listener, Metrics, Network as RNetwork, Sink, Spawner, Stream,
};
use commonware_stream::public_key;
use commonware_utils::union;
use governor::{clock::ReasonablyRealtime, Quota};
use rand::{CryptoRng, Rng};
use std::marker::PhantomData;
use tracing::{debug, info, warn};

// The maximum overhead of encoding a `message: Bytes` into a protobuf `message Message`
// Should be at most 18 bytes for messages under 4GB, but we add a bit of padding.
//
// The byte overhead is calculated as follows:
// - 1  Data field number
// - 5* Data length varint
// - 1  Channel field number
// - 5  Channel value varint
// - 1  Message field number
// - 5* Message length varint
//
// (*) assumes that the length is no more than 4GB
const PROTOBUF_OVERHEAD: usize = 64;

/// Unique suffix for all messages signed by the tracker.
const TRACKER_SUFFIX: &[u8] = b"_TRACKER";

/// Unique suffix for all messages signed in a stream.
const STREAM_SUFFIX: &[u8] = b"_STREAM";

/// Implementation of an `authenticated` network.
pub struct Network<
    Si: Sink,
    St: Stream,
    L: Listener<Si, St>,
    E: Spawner + Clock + ReasonablyRealtime + Rng + CryptoRng + RNetwork<L, Si, St> + Metrics,
    C: Scheme,
> {
    runtime: E,
    cfg: Config<C>,

    channels: Channels<C::PublicKey>,
    tracker: tracker::Actor<E, C>,
    tracker_mailbox: tracker::Mailbox<E, C::PublicKey>,
    router: router::Actor<E, C::PublicKey>,
    router_mailbox: router::Mailbox<C::PublicKey>,

    _phantom_si: PhantomData<Si>,
    _phantom_st: PhantomData<St>,
    _phantom_l: PhantomData<L>,
}

impl<
        Si: Sink,
        St: Stream,
        L: Listener<Si, St>,
        E: Spawner + Clock + ReasonablyRealtime + Rng + CryptoRng + RNetwork<L, Si, St> + Metrics,
        C: Scheme,
    > Network<Si, St, L, E, C>
{
    /// Create a new instance of an `authenticated` network.
    ///
    /// # Parameters
    ///
    /// * `cfg` - Configuration for the network.
    ///
    /// # Returns
    ///
    /// * A tuple containing the network instance and the oracle that
    ///   can be used by a developer to configure which peers are authorized.
    pub fn new(runtime: E, cfg: Config<C>) -> (Self, tracker::Oracle<E, C::PublicKey>) {
        let (tracker, tracker_mailbox, oracle) = tracker::Actor::new(
            runtime.clone().with_label("tracker"),
            tracker::Config {
                crypto: cfg.crypto.clone(),
                namespace: union(&cfg.namespace, TRACKER_SUFFIX),
                address: cfg.dialable,
                bootstrappers: cfg.bootstrappers.clone(),
                allow_private_ips: cfg.allow_private_ips,
                mailbox_size: cfg.mailbox_size,
                synchrony_bound: cfg.synchrony_bound,
                tracked_peer_sets: cfg.tracked_peer_sets,
                allowed_connection_rate_per_peer: cfg.allowed_connection_rate_per_peer,
                peer_gossip_max_count: cfg.peer_gossip_max_count,
            },
        );
        let (router, router_mailbox, messenger) = router::Actor::new(
            runtime.clone().with_label("router"),
            router::Config {
                mailbox_size: cfg.mailbox_size,
            },
        );
        let channels = Channels::new(messenger, cfg.max_message_size);

        (
            Self {
                runtime,
                cfg,

                channels,
                tracker,
                tracker_mailbox,
                router,
                router_mailbox,

                _phantom_si: PhantomData,
                _phantom_st: PhantomData,
                _phantom_l: PhantomData,
            },
            oracle,
        )
    }

    /// Register a new channel over the network.
    ///
    /// # Parameters
    ///
    /// * `channel` - Unique identifier for the channel.
    /// * `rate` - Rate at which messages can be received over the channel.
    /// * `backlog` - Maximum number of messages that can be queued on the channel before blocking.
    /// * `compression` - Optional compression level (using `zstd`) to use for messages on the channel.
    ///
    /// # Returns
    ///
    /// * A tuple containing the sender and receiver for the channel (how to communicate
    ///   with external peers on the network). It is safe to close either the sender or receiver
    ///   without impacting the ability to process messages on other channels.
    pub fn register(
        &mut self,
        channel: Channel,
        rate: Quota,
        backlog: usize,
        compression: Option<i32>,
    ) -> (
        channels::Sender<C::PublicKey>,
        channels::Receiver<C::PublicKey>,
    ) {
        self.channels.register(channel, rate, backlog, compression)
    }

    pub async fn start(self) -> Handle<()> {
        self.runtime.clone().spawn(|_| self.run())
    }

    /// Starts the network.
    ///
    /// After the network is started, it is not possible to add more channels.
    async fn run(self) {
        // Start tracker
        let mut tracker_task = self.tracker.start();

        // Start router
        let mut router_task = self.router.start(self.channels);

        // Start spawner
        let (spawner, spawner_mailbox) = spawner::Actor::new(
            self.runtime.clone().with_label("spawner"),
            spawner::Config {
                mailbox_size: self.cfg.mailbox_size,
                gossip_bit_vec_frequency: self.cfg.gossip_bit_vec_frequency,
                allowed_bit_vec_rate: self.cfg.allowed_bit_vec_rate,
                allowed_peers_rate: self.cfg.allowed_peers_rate,
            },
        );
        let mut spawner_task =
            spawner.start(self.tracker_mailbox.clone(), self.router_mailbox.clone());

        // Start listener
        let stream_cfg = public_key::Config {
            crypto: self.cfg.crypto,
            namespace: union(&self.cfg.namespace, STREAM_SUFFIX),
            max_message_size: self.cfg.max_message_size + PROTOBUF_OVERHEAD,
            synchrony_bound: self.cfg.synchrony_bound,
            max_handshake_age: self.cfg.max_handshake_age,
            handshake_timeout: self.cfg.handshake_timeout,
        };
        let listener = listener::Actor::new(
            self.runtime.clone().with_label("listener"),
            listener::Config {
                address: self.cfg.listen,
                stream_cfg: stream_cfg.clone(),
                allowed_incoming_connectioned_rate: self.cfg.allowed_incoming_connection_rate,
            },
        );
        let mut listener_task =
            listener.start(self.tracker_mailbox.clone(), spawner_mailbox.clone());

        // Start dialer
        let dialer = dialer::Actor::new(
            self.runtime.clone().with_label("dialer"),
            dialer::Config {
                stream_cfg,
                dial_frequency: self.cfg.dial_frequency,
                dial_rate: self.cfg.dial_rate,
            },
        );
        let mut dialer_task = dialer.start(self.tracker_mailbox, spawner_mailbox);

        // Wait for first actor to exit
        info!("network started");
        let err = select! {
            tracker = &mut tracker_task => {
                debug!("tracker exited");
                tracker
            },
            router = &mut router_task => {
                debug!("router exited");
                router
            },
            spawner = &mut spawner_task => {
                debug!("spawner exited");
                spawner
            },
            listener = &mut listener_task => {
                debug!("listener exited");
                listener
            },
            dialer = &mut dialer_task => {
                debug!("dialer exited");
                dialer
            },
        }
        .unwrap_err();

        // Ensure all tasks close
        tracker_task.abort();
        router_task.abort();
        spawner_task.abort();
        listener_task.abort();
        dialer_task.abort();

        // Log error
        warn!(error=?err, "network shutdown")
    }
}
