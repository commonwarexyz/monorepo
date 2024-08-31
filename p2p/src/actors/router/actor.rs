use super::{
    ingress::{Mailbox, Message, Messenger},
    Config,
};
use crate::{
    actors::peer::{self, Relay},
    channels::Channels,
    metrics,
};
use bytes::Bytes;
use commonware_cryptography::{utils::hex, PublicKey};
use prometheus_client::metrics::{counter::Counter, family::Family};
use std::collections::HashMap;
use tokio::sync::mpsc;
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

    async fn send_message(
        &self,
        messenger: &Relay,
        recipient: &PublicKey,
        channel: u32,
        message: Bytes,
        priority: bool,
    ) {
        if messenger
            .content(channel, message.clone(), priority)
            .await
            .is_ok()
        {
            return;
        }
        self.messages_dropped
            .get_or_create(&metrics::Message::new_chunk(recipient, channel))
            .inc();
    }

    pub async fn run(mut self, routing: Channels) {
        while let Some(msg) = self.control.recv().await {
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
                    if let Some(recipients) = recipients {
                        for recipient in recipients {
                            let messenger = match self.connections.get(&recipient) {
                                Some(messenger) => messenger,
                                None => {
                                    self.messages_dropped
                                        .get_or_create(&metrics::Message::new_chunk(
                                            &recipient, channel,
                                        ))
                                        .inc();
                                    continue;
                                }
                            };
                            self.send_message(
                                messenger,
                                &recipient,
                                channel,
                                message.clone(),
                                priority,
                            )
                            .await;
                            sent.push(recipient);
                        }
                    } else {
                        for (recipient, messenger) in self.connections.iter() {
                            self.send_message(
                                messenger,
                                recipient,
                                channel,
                                message.clone(),
                                priority,
                            )
                            .await;
                            sent.push(recipient.clone());
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
