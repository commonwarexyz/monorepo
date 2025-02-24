use super::{
    ingress::{Mailbox, Message, Messenger},
    Config,
};
use crate::{
    authenticated::{actors::peer, channels::Channels, metrics},
    Channel, Recipients,
};
use bytes::Bytes;
use commonware_runtime::{Handle, Metrics, Spawner};
use commonware_utils::Array;
use futures::{channel::mpsc, StreamExt};
use prometheus_client::metrics::{counter::Counter, family::Family};
use std::collections::BTreeMap;
use tracing::debug;

pub struct Actor<E: Spawner + Metrics, P: Array> {
    runtime: E,

    control: mpsc::Receiver<Message<P>>,
    connections: BTreeMap<P, peer::Relay>,

    messages_dropped: Family<metrics::Message, Counter>,
}

impl<E: Spawner + Metrics, P: Array> Actor<E, P> {
    pub fn new(runtime: E, cfg: Config) -> (Self, Mailbox<P>, Messenger<P>) {
        // Create mailbox
        let (control_sender, control_receiver) = mpsc::channel(cfg.mailbox_size);

        // Create metrics
        let messages_dropped = Family::<metrics::Message, Counter>::default();
        runtime.register(
            "messages_dropped",
            "messages dropped",
            messages_dropped.clone(),
        );

        // Create actor
        (
            Self {
                runtime,
                control: control_receiver,
                connections: BTreeMap::new(),
                messages_dropped,
            },
            Mailbox::new(control_sender.clone()),
            Messenger::new(control_sender),
        )
    }

    async fn send_to_recipient(
        &mut self,
        recipient: &P,
        channel: Channel,
        message: Bytes,
        priority: bool,
        sent: &mut Vec<P>,
    ) {
        if let Some(messenger) = self.connections.get_mut(recipient) {
            if messenger
                .content(channel, message.clone(), priority)
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

    pub fn start(self, routing: Channels<P>) -> Handle<()> {
        self.runtime.clone().spawn(|_| self.run(routing))
    }

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
                            self.send_to_recipient(
                                &recipient, channel, message, priority, &mut sent,
                            )
                            .await;
                        }
                        Recipients::Some(recipients) => {
                            for recipient in recipients {
                                self.send_to_recipient(
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
