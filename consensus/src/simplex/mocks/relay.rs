//! Simple in-memory broadcast relay for mock applications; not a network.

use bytes::Bytes;
use commonware_cryptography::{Digest, PublicKey};
use futures::{channel::mpsc, SinkExt};
use std::{collections::BTreeMap, sync::Mutex};

/// Relay is a mock for distributing artifacts between applications.
pub struct Relay<D: Digest, P: PublicKey> {
    recipients: Mutex<BTreeMap<P, mpsc::UnboundedSender<(D, Bytes)>>>,
    payloads: Mutex<BTreeMap<D, Bytes>>,
}

impl<D: Digest, P: PublicKey> Relay<D, P> {
    /// Creates a new relay.
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            recipients: Mutex::new(BTreeMap::new()),
            payloads: Mutex::new(BTreeMap::new()),
        }
    }

    /// Deregisters all recipients without clearing the payloads.
    pub fn deregister_all(&self) {
        let mut recipients = self.recipients.lock().unwrap();
        recipients.clear();
    }

    /// Registers a new recipient that receives all broadcasts.
    pub fn register(&self, public_key: P) -> mpsc::UnboundedReceiver<(D, Bytes)> {
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

    /// Broadcasts a payload to all registered recipients.
    pub async fn broadcast(&self, sender: &P, (payload, data): (D, Bytes)) {
        // Record payload for future use
        self.payloads.lock().unwrap().insert(payload, data.clone());

        // Send to all recipients
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
                .send((payload, data.clone()))
                .await
                .expect("Failed to send");
        }
    }

    /// Requests that a payload is sent to a public key.
    pub async fn request(&self, payload: D, public_key: P) {
        let Some(data) = self.payloads.lock().unwrap().get(&payload).cloned() else {
            return;
        };
        let mut sender = self
            .recipients
            .lock()
            .unwrap()
            .get(&public_key)
            .expect("unregistered recipient")
            .clone();
        sender.send((payload, data)).await.expect("Failed to send");
    }
}

impl<D: Digest, P: PublicKey> Default for Relay<D, P> {
    fn default() -> Self {
        Self::new()
    }
}
