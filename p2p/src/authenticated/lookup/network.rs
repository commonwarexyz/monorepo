//! Implementation of an `authenticated` network.

use super::{
    actors::{dialer, listener, router, spawner, tracker},
    channels::{self, Channels},
    config::Config,
    types,
};
use crate::Channel;
use commonware_cryptography::Signer;
use commonware_macros::select;
use commonware_runtime::{Clock, Handle, Metrics, Network as RNetwork, Spawner};
use commonware_stream::public_key;
use commonware_utils::union;
use governor::{clock::ReasonablyRealtime, Quota};
use rand::{CryptoRng, Rng};
use tracing::{debug, info, warn};

/// Unique suffix for all messages signed in a stream.
const STREAM_SUFFIX: &[u8] = b"_STREAM";

/// Implementation of an `authenticated` network.
pub struct Network<
    E: Spawner + Clock + ReasonablyRealtime + Rng + CryptoRng + RNetwork + Metrics,
    C: Signer,
> {
    context: E,
    cfg: Config<C>,

    channels: Channels<C::PublicKey>,
    tracker: tracker::Actor<E, C>,
    tracker_mailbox: tracker::Mailbox<E, C::PublicKey>,
    router: router::Actor<E, C::PublicKey>,
    router_mailbox: router::Mailbox<C::PublicKey>,
}

/// Guard that aborts all tasks when dropped.
/// This ensures that all the network's sub-tasks stop when the network stops.
struct TaskGuard {
    tracker_task: Handle<()>,
    router_task: Handle<()>,
    spawner_task: Handle<()>,
    listener_task: Handle<()>,
    dialer_task: Handle<()>,
}

impl Drop for TaskGuard {
    fn drop(&mut self) {
        self.tracker_task.abort();
        self.router_task.abort();
        self.spawner_task.abort();
        self.listener_task.abort();
        self.dialer_task.abort();
    }
}

impl<E: Spawner + Clock + ReasonablyRealtime + Rng + CryptoRng + RNetwork + Metrics, C: Signer>
    Network<E, C>
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
    pub fn new(context: E, cfg: Config<C>) -> (Self, tracker::Oracle<E, C::PublicKey>) {
        let (tracker, tracker_mailbox, oracle) = tracker::Actor::new(
            context.with_label("tracker"),
            tracker::Config {
                crypto: cfg.crypto.clone(),
                address: cfg.dialable,
                bootstrappers: cfg.bootstrappers.clone(),
                mailbox_size: cfg.mailbox_size,
                tracked_peer_sets: cfg.tracked_peer_sets,
                allowed_connection_rate_per_peer: cfg.allowed_connection_rate_per_peer,
                max_peer_set_size: cfg.max_peer_set_size,
            },
        );
        let (router, router_mailbox, messenger) = router::Actor::new(
            context.with_label("router"),
            router::Config {
                mailbox_size: cfg.mailbox_size,
            },
        );
        let channels = Channels::new(messenger, cfg.max_message_size);

        (
            Self {
                context,
                cfg,

                channels,
                tracker,
                tracker_mailbox,
                router,
                router_mailbox,
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

    /// Starts the network.
    ///
    /// After the network is started, it is not possible to add more channels.
    pub fn start(mut self) -> Handle<()> {
        self.context.spawn_ref()(self.run())
    }

    async fn run(self) {
        // Start tracker
        let tracker_task = self.tracker.start();

        // Start router
        let router_task = self.router.start(self.channels);

        // Start spawner
        let (spawner, spawner_mailbox) = spawner::Actor::new(
            self.context.with_label("spawner"),
            spawner::Config {
                mailbox_size: self.cfg.mailbox_size,
                ping_frequency: self.cfg.ping_frequency,
            },
        );
        let spawner_task = spawner.start(self.tracker_mailbox.clone(), self.router_mailbox.clone());

        // Start listener
        let stream_cfg = public_key::Config {
            crypto: self.cfg.crypto,
            namespace: union(&self.cfg.namespace, STREAM_SUFFIX),
            max_message_size: self.cfg.max_message_size + types::MAX_PAYLOAD_DATA_OVERHEAD,
            synchrony_bound: self.cfg.synchrony_bound,
            max_handshake_age: self.cfg.max_handshake_age,
            handshake_timeout: self.cfg.handshake_timeout,
        };
        let listener = listener::Actor::new(
            self.context.with_label("listener"),
            listener::Config {
                address: self.cfg.listen,
                stream_cfg: stream_cfg.clone(),
                allowed_incoming_connection_rate: self.cfg.allowed_incoming_connection_rate,
            },
        );
        let listener_task = listener.start(self.tracker_mailbox.clone(), spawner_mailbox.clone());

        // Start dialer
        let dialer = dialer::Actor::new(
            self.context.with_label("dialer"),
            dialer::Config {
                stream_cfg,
                dial_frequency: self.cfg.dial_frequency,
                query_frequency: self.cfg.query_frequency,
            },
        );
        let dialer_task = dialer.start(self.tracker_mailbox, spawner_mailbox);

        let mut _guard = TaskGuard {
            tracker_task,
            router_task,
            spawner_task,
            listener_task,
            dialer_task,
        };

        // Wait for first actor to exit
        info!("network started");
        let err = select! {
            tracker = &mut _guard.tracker_task => {
                debug!("tracker exited");
                tracker
            },
            router = &mut _guard.router_task => {
                debug!("router exited");
                router
            },
            spawner = &mut _guard.spawner_task => {
                debug!("spawner exited");
                spawner
            },
            listener = &mut _guard.listener_task => {
                debug!("listener exited");
                listener
            },
            dialer = &mut _guard.dialer_task => {
                debug!("dialer exited");
                dialer
            },
        }
        .unwrap_err();
        debug!("network shutdown started");

        // Log error
        drop(_guard); // Abort all tasks
        warn!(error=?err, "network shutdown");
    }
}
