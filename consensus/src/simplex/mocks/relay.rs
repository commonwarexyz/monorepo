use bytes::Bytes;
use commonware_cryptography::{Hasher, PublicKey};
use futures::{channel::mpsc, SinkExt};
use std::{collections::BTreeMap, sync::Mutex};

/// Relay is a mock for distributing artifacts between applications.
pub struct Relay<H: Hasher> {
    recipients: Mutex<BTreeMap<PublicKey, mpsc::UnboundedSender<(H::Digest, Bytes)>>>,
}

impl<H: Hasher> Relay<H> {
    pub fn new() -> Self {
        Self {
            recipients: Mutex::new(BTreeMap::new()),
        }
    }

    pub fn register(&self, public_key: PublicKey) -> mpsc::UnboundedReceiver<(H::Digest, Bytes)> {
        let (sender, receiver) = mpsc::unbounded();
        if self
            .recipients
            .lock()
            .unwrap()
            .insert(public_key, sender)
            .is_some()
        {
            panic!("duplicate registrant");
        }
        receiver
    }

    pub async fn broadcast(&self, sender: &PublicKey, payload: (H::Digest, Bytes)) {
        let channels = {
            let mut channels = Vec::new();
            let recipients = self.recipients.lock().unwrap();
            for (public_key, channel) in recipients.iter() {
                if public_key == sender {
                    continue;
                }
                channels.push(channel.clone());
            }
            channels
        };
        for mut channel in channels {
            channel
                .send((payload.0.clone(), payload.1.clone()))
                .await
                .expect("Failed to send");
        }
    }
}

impl<H: Hasher> Default for Relay<H> {
    fn default() -> Self {
        Self::new()
    }
}
