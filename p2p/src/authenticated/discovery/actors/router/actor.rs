use super::{
    ingress::{Message, Messenger},
    Config,
};
use crate::{
    authenticated::{
        data::EncodedData,
        discovery::metrics,
        relay::Relay,
        Mailbox,
    },
    Recipients,
};
use commonware_cryptography::PublicKey;
use commonware_macros::select_loop;
use commonware_runtime::{
    spawn_cell,
    telemetry::metrics::{CounterFamily, MetricsExt as _},
    BufferPooler, ContextCell, Handle, Metrics, Spawner,
};
use commonware_utils::{
    channel::{actor::ActorInbox, ring},
    NZUsize,
};
use futures::Sink;
use std::{collections::BTreeMap, pin::Pin};
use tracing::debug;

/// Router actor that manages peer connections and routing messages.
pub struct Actor<E: Spawner + BufferPooler + Metrics, P: PublicKey> {
    context: ContextCell<E>,

    control: ActorInbox<Message<P>>,
    connections: BTreeMap<P, Relay<EncodedData>>,
    open_subscriptions: Vec<ring::Sender<Vec<P>>>,

    messages_dropped: CounterFamily<metrics::Message<P>>,
}

impl<E: Spawner + BufferPooler + Metrics, P: PublicKey> Actor<E, P> {
    /// Returns a new [Actor] along with a [Mailbox] and [Messenger]
    /// that can be used to send messages to the router.
    pub fn new(context: E, cfg: Config) -> (Self, Mailbox<Message<P>>, Messenger<P>) {
        // Create mailbox
        let (control_sender, control_receiver) = Mailbox::new(cfg.mailbox_size);
        let pool = context.network_buffer_pool().clone();

        // Create metrics
        let messages_dropped = context.family("messages_dropped", "messages dropped");

        // Create actor
        (
            Self {
                context: ContextCell::new(context),
                control: control_receiver,
                connections: BTreeMap::new(),
                open_subscriptions: Vec::new(),
                messages_dropped,
            },
            control_sender.clone(),
            Messenger::new(pool, control_sender),
        )
    }

    /// Sends pre-encoded data to the given `recipient`.
    fn send(&mut self, recipient: P, encoded: EncodedData, priority: bool, sent: &mut Vec<P>) {
        let channel = encoded.channel;
        if let Some(relay) = self.connections.get_mut(&recipient) {
            if relay.send(encoded, priority).accepted() {
                sent.push(recipient);
            } else {
                self.messages_dropped
                    .get_or_create(&metrics::Message::new_data(&recipient, channel))
                    .inc();
            }
        } else {
            self.messages_dropped
                .get_or_create(&metrics::Message::new_data(&recipient, channel))
                .inc();
        }
    }

    /// Starts a new task that runs the router [Actor].
    /// Returns a [Handle] that can be used to await the completion of the task,
    /// which will run until its `control` receiver is closed.
    pub fn start(mut self) -> Handle<()> {
        spawn_cell!(self.context, self.run())
    }

    /// Runs the [Actor] event loop, processing incoming messages control messages
    /// ([Message::Ready], [Message::Release]) and content messages ([Message::Content]).
    /// Returns when the `control` channel is closed.
    async fn run(mut self) {
        select_loop! {
            self.context,
            on_stopped => {
                debug!("context shutdown, stopping router");
            },
            Some(msg) = self.control.recv() else {
                debug!("mailbox closed, stopping router");
                break;
            } => {
                match msg {
                    Message::Ready {
                        peer,
                        relay,
                    } => {
                        debug!(?peer, "peer ready");
                        self.connections.insert(peer, relay);
                        self.notify_subscribers();
                    }
                    Message::Release { peer } => {
                        debug!(?peer, "peer released");
                        self.connections.remove(&peer);
                        self.notify_subscribers();
                    }
                    Message::Content {
                        recipients,
                        encoded,
                        priority,
                        success,
                    } => {
                        let mut sent = Vec::new();
                        let channel = encoded.channel;
                        match recipients {
                            Recipients::One(recipient) => {
                                self.send(recipient, encoded, priority, &mut sent);
                            }
                            Recipients::Some(recipients) => {
                                for recipient in recipients {
                                    self.send(recipient, encoded.clone(), priority, &mut sent);
                                }
                            }
                            Recipients::All => {
                                // Send to all connected peers
                                for (recipient, relay) in self.connections.iter_mut() {
                                    if relay.send(encoded.clone(), priority).accepted() {
                                        sent.push(recipient.clone());
                                    } else {
                                        self.messages_dropped
                                            .get_or_create(&metrics::Message::new_data(
                                                recipient, channel,
                                            ))
                                            .inc();
                                    }
                                }
                            }
                        }

                        // Communicate success back to sender (if still alive)
                        if let Some(success) = success {
                            let _ = success.send(sent);
                        }
                    }
                    Message::SubscribePeers { response } => {
                        let (mut sender, receiver) = ring::channel::<Vec<P>>(NZUsize!(1));

                        // Send existing peers immediately
                        let peers = self.connections.keys().cloned().collect();
                        let _ = Pin::new(&mut sender).start_send(peers);

                        self.open_subscriptions.push(sender);
                        let _ = response.send(receiver);
                    }
                }
            },
        }
    }

    /// Notifies all open peer subscriptions with the current list of connected peers.
    fn notify_subscribers(&mut self) {
        let peers: Vec<P> = self.connections.keys().cloned().collect();
        let mut keep = Vec::with_capacity(self.open_subscriptions.len());

        for mut subscriber in self.open_subscriptions.drain(..) {
            if Pin::new(&mut subscriber).start_send(peers.clone()).is_ok() {
                keep.push(subscriber);
            }
        }
        self.open_subscriptions = keep;
    }
}
