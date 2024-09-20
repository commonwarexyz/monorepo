use super::{
    ingress::{Mailbox, Message, Messenger},
    Config,
};
use crate::{
    authenticated::{actors::peer, channels::Channels, metrics},
    Recipients,
};
use bytes::Bytes;
use commonware_cryptography::{utils::hex, PublicKey};
use futures::{channel::mpsc, StreamExt};
use prometheus_client::metrics::{counter::Counter, family::Family};
use std::collections::HashMap;
use tracing::debug;

pub struct Actor {
    control: mpsc::Receiver<Message>,
    connections: HashMap<PublicKey, peer::Relay>,

    messages_dropped: Family<metrics::Message, Counter>,
}

impl Actor {
    pub fn new(cfg: Config) -> (Self, Mailbox, Messenger) {
        let (control_sender, control_receiver) = mpsc::channel(cfg.mailbox_size);

        // Create metrics
        let messages_dropped = Family::<metrics::Message, Counter>::default();
        {
            let mut registry = cfg.registry.lock().unwrap();
            registry.register(
                "messages_dropped",
                "messages dropped",
                messages_dropped.clone(),
            );
        }

        (
            Self {
                control: control_receiver,
                connections: HashMap::new(),
                messages_dropped,
            },
            Mailbox::new(control_sender.clone()),
            Messenger::new(control_sender),
        )
    }

    async fn send_to_recipient(
        &mut self,
        recipient: &PublicKey,
        channel: u32,
        message: Bytes,
        priority: bool,
        sent: &mut Vec<PublicKey>,
    ) {
        if let Some(messenger) = self.connections.get_mut(recipient) {
            if messenger
                .content(channel, message.clone(), priority)
                .await
                .is_ok()
            {
                return;
            } else {
                self.messages_dropped
                    .get_or_create(&metrics::Message::new_chunk(recipient, channel))
                    .inc();
            }
            sent.push(recipient.clone());
        } else {
            self.messages_dropped
                .get_or_create(&metrics::Message::new_chunk(recipient, channel))
                .inc();
        }
    }

    pub async fn run(mut self, routing: Channels) {
        while let Some(msg) = self.control.next().await {
            match msg {
                Message::Ready {
                    peer,
                    relay,
                    channels,
                } => {
                    debug!(peer = hex(&peer), "peer ready");
                    self.connections.insert(peer, relay);
                    let _ = channels.send(routing.clone());
                }
                Message::Release { peer } => {
                    debug!(peer = hex(&peer), "peer released");
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
                            for (recipient, messenger) in self.connections.iter_mut() {
                                if messenger
                                    .content(channel, message.clone(), priority)
                                    .await
                                    .is_ok()
                                {
                                    return;
                                } else {
                                    self.messages_dropped
                                        .get_or_create(&metrics::Message::new_chunk(
                                            recipient, channel,
                                        ))
                                        .inc();
                                }
                                sent.push(recipient.clone());
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
