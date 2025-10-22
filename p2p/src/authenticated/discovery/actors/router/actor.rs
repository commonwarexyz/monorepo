use super::{
    ingress::{Message, Messenger},
    Config,
};
use crate::{
    authenticated::{
        data::Data,
        discovery::{channels::Channels, metrics},
        relay::Relay,
        Mailbox,
    },
    Channel, Recipients,
};
use bytes::Bytes;
use commonware_cryptography::PublicKey;
use commonware_runtime::{spawn_cell, ContextCell, Handle, Metrics, Spawner};
use futures::{channel::mpsc, StreamExt};
use prometheus_client::metrics::{counter::Counter, family::Family};
use std::collections::BTreeMap;
use tracing::debug;

/// Router actor that manages peer connections and routing messages.
pub struct Actor<E: Spawner + Metrics, P: PublicKey> {
    context: ContextCell<E>,

    control: mpsc::Receiver<Message<P>>,
    connections: BTreeMap<P, Relay<Data>>,

    messages_dropped: Family<metrics::Message, Counter>,
}

impl<E: Spawner + Metrics, P: PublicKey> Actor<E, P> {
    /// Returns a new [Actor] along with a [Mailbox] and [Messenger]
    /// that can be used to send messages to the router.
    pub fn new(context: E, cfg: Config) -> (Self, Mailbox<Message<P>>, Messenger<P>) {
        // Create mailbox
        let (control_sender, control_receiver) = Mailbox::new(cfg.mailbox_size);

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
                context: ContextCell::new(context),
                control: control_receiver,
                connections: BTreeMap::new(),
                messages_dropped,
            },
            control_sender.clone(),
            Messenger::new(control_sender),
        )
    }

    /// Sends a message to the given `recipient`.
    async fn send(
        &mut self,
        recipient: &P,
        channel: Channel,
        message: Bytes,
        priority: bool,
        sent: &mut Vec<P>,
    ) {
        if let Some(messenger) = self.connections.get_mut(recipient) {
            if messenger
                .send(Data { channel, message }, priority)
                .await
                .is_ok()
            {
                sent.push(recipient.clone());
            } else {
                self.messages_dropped
                    .get_or_create(&metrics::Message::new_data(recipient, channel))
                    .inc();
            }
        } else {
            self.messages_dropped
                .get_or_create(&metrics::Message::new_data(recipient, channel))
                .inc();
        }
    }

    /// Starts a new task that runs the router [Actor].
    /// Returns a [Handle] that can be used to await the completion of the task,
    /// which will run until its `control` receiver is closed.
    pub fn start(mut self, routing: Channels<P>) -> Handle<()> {
        spawn_cell!(self.context, self.run(routing).await)
    }

    /// Runs the [Actor] event loop, processing incoming messages control messages
    /// ([Message::Ready], [Message::Release]) and content messages ([Message::Content]).
    /// Returns when the `control` channel is closed.
    async fn run(mut self, routing: Channels<P>) {
        while let Some(msg) = self.control.next().await {
            match msg {
                Message::Ready {
                    peer,
                    relay,
                    channels,
                } => {
                    debug!(?peer, "peer ready");
                    self.connections.insert(peer, relay);
                    let _ = channels.send(routing.clone());
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
                    success,
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
                                    .send(
                                        Data {
                                            channel,
                                            message: message.clone(),
                                        },
                                        priority,
                                    )
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
