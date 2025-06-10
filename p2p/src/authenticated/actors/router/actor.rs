use super::{
    ingress::{Mailbox, Message, Messenger},
    Config,
};
use crate::{
    authenticated::{actors::peer, channels::Channels, metrics},
    Channel, Recipients,
};
use bytes::Bytes;
use commonware_cryptography::PublicKey;
use commonware_runtime::{Handle, Metrics, Spawner};
use futures::{channel::mpsc, StreamExt};
use prometheus_client::metrics::{counter::Counter, family::Family};
use std::collections::BTreeMap;
use tracing::debug;

/// Router actor that manages peer connections and routing messages.
pub struct Actor<E: Spawner + Metrics, P: PublicKey> {
    context: E,

    control_rx: mpsc::Receiver<Message<P>>,
    connections: BTreeMap<P, peer::Relay>,

    messages_dropped: Family<metrics::Message, Counter>,
}

impl<E: Spawner + Metrics, P: PublicKey> Actor<E, P> {
    /// Returns a new [Actor] along with a [Mailbox] and [Messenger]
    /// that can be used to send messages to the router.
    pub fn new(context: E, cfg: Config) -> (Self, Mailbox<P>, Messenger<P>) {
        // Create mailbox
        let (control_tx, control_rx) = mpsc::channel(cfg.mailbox_size);

        // Create metrics
        let messages_dropped = Family::<metrics::Message, Counter>::default();
        context.register(
            "messages_dropped",
            "messages dropped",
            messages_dropped.clone(),
        );

        // Create actor
        (
            Self {
                context,
                control_rx,
                connections: BTreeMap::new(),
                messages_dropped,
            },
            Mailbox::new(control_tx.clone()),
            Messenger::new(control_tx),
        )
    }

    /// Sends a message to the given `peer`.
    async fn send(
        &mut self,
        peer: &P,
        channel: Channel,
        message: Bytes,
        priority: bool,
        sent: &mut Vec<P>,
    ) {
        if let Some(messenger) = self.connections.get_mut(peer) {
            if messenger
                .content(channel, message.clone(), priority)
                .await
                .is_ok()
            {
                sent.push(peer.clone());
            } else {
                self.messages_dropped
                    .get_or_create(&metrics::Message::new_data(peer, channel))
                    .inc();
            }
        } else {
            self.messages_dropped
                .get_or_create(&metrics::Message::new_data(peer, channel))
                .inc();
        }
    }

    /// Starts a new task that runs the router [Actor].
    /// Returns a [Handle] that can be used to await the completion of the task,
    /// which will run until its `control_rx` receiver is closed.
    pub fn start(mut self, channels: Channels<P>) -> Handle<()> {
        self.context.spawn_ref()(self.run(channels))
    }

    /// Runs the [Actor] event loop, processing incoming messages control messages
    /// ([Message::Ready], [Message::Release]) and content messages ([Message::Content]).
    /// Returns when the `control_rx` channel is closed.
    async fn run(mut self, channels: Channels<P>) {
        while let Some(msg) = self.control_rx.next().await {
            match msg {
                Message::Ready {
                    peer,
                    relay,
                    channels_tx,
                } => {
                    debug!(?peer, "peer ready");
                    self.connections.insert(peer, relay);
                    // Send the channels to the peer
                    let _ = channels_tx.send(channels.clone());
                }
                Message::Release { peer } => {
                    debug!(?peer, "peer released");
                    self.connections.remove(&peer);
                }
                Message::Content {
                    recipients,
                    channel,
                    message,
                    priority,
                    sent_tx: success,
                } => {
                    let mut sent = Vec::new();
                    match recipients {
                        Recipients::One(recipient) => {
                            self.send(&recipient, channel, message, priority, &mut sent)
                                .await;
                        }
                        Recipients::Some(recipients) => {
                            for recipient in recipients {
                                self.send(
                                    &recipient,
                                    channel,
                                    message.clone(),
                                    priority,
                                    &mut sent,
                                )
                                .await;
                            }
                        }
                        Recipients::All => {
                            // Send to all connected peers
                            for (recipient, messenger) in self.connections.iter_mut() {
                                if messenger
                                    .content(channel, message.clone(), priority)
                                    .await
                                    .is_ok()
                                {
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
                    let _ = success.send(sent);
                }
            }
        }
        debug!("router shutdown");
    }
}
