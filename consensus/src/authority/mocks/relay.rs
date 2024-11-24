use bytes::Bytes;
use commonware_cryptography::{Digest, PublicKey};
use futures::{channel::mpsc, SinkExt};
use std::collections::BTreeMap;

/// Relay is a mock for distributing artifacts between applications.
pub struct Relay {
    recipients: BTreeMap<PublicKey, mpsc::UnboundedSender<(Digest, Bytes)>>,
}

impl Relay {
    pub fn new() -> Self {
        Self {
            recipients: BTreeMap::new(),
        }
    }

    pub fn register(&mut self, public_key: PublicKey) -> mpsc::UnboundedReceiver<(Digest, Bytes)> {
        let (sender, receiver) = mpsc::unbounded();
        if self.recipients.insert(public_key, sender).is_some() {
            panic!("duplicate registrant");
        }
        receiver
    }

    pub fn broadcast(&mut self, sender: PublicKey, payload: (Digest, Bytes)) {
        for (public_key, channel) in self.recipients.iter_mut() {
            if public_key == &sender {
                continue;
            }
            channel.send((payload.0.clone(), payload.1.clone()));
        }
    }
}
