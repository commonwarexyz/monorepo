use super::{
    ingress::{Mailbox, Message, Messenger},
    Config,
};
use crate::{actors::peer, channels::Channels, crypto::PublicKey, metrics};
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

    pub async fn run(mut self, routing: Channels) {
        while let Some(msg) = self.control.recv().await {
            match msg {
                Message::Ready {
                    peer,
                    relay,
                    channels,
                } => {
                    debug!(peer = hex::encode(&peer), "peer ready");
                    self.connections.insert(peer, relay);
                    let _ = channels.send(routing.clone());
                }
                Message::Release { peer } => {
                    debug!(peer = hex::encode(&peer), "peer released");
                    self.connections.remove(&peer);
                }
                Message::Content {
                    recipients,
                    channel,
                    message,
                    priority,
                } => {
                    if let Some(recipients) = recipients {
                        for recipient in recipients {
                            if let Some(messenger) = self.connections.get(&recipient) {
                                match messenger.content(channel, message.clone(), priority).await {
                                    Ok(()) => {
                                        continue;
                                    }
                                    Err(_) => {
                                        self.messages_dropped
                                            .get_or_create(&metrics::Message::new_chunk(
                                                &recipient, channel,
                                            ))
                                            .inc();
                                    }
                                }
                            } else {
                                self.messages_dropped
                                    .get_or_create(&metrics::Message::new_chunk(
                                        &recipient, channel,
                                    ))
                                    .inc();
                            }
                        }
                    } else {
                        for (peer, messenger) in self.connections.iter() {
                            match messenger.content(channel, message.clone(), priority).await {
                                Ok(()) => {
                                    continue;
                                }
                                Err(_) => {
                                    self.messages_dropped
                                        .get_or_create(&metrics::Message::new_chunk(peer, channel))
                                        .inc();
                                }
                            }
                        }
                    }
                }
            }
        }
        debug!("router shutdown");
    }
}
