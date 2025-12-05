//! Simple in-memory broadcast relay for mock applications; not a network.

use bytes::Bytes;
use commonware_cryptography::{Digest, PublicKey};
use futures::{channel::mpsc, SinkExt};
use std::{
    collections::{btree_map::Entry, BTreeMap},
    sync::Mutex,
};
use tracing::{error, warn};

/// Relay is a mock for distributing artifacts between applications.
pub struct Relay<D: Digest, P: PublicKey> {
    #[allow(clippy::type_complexity)]
    recipients: Mutex<BTreeMap<P, Vec<mpsc::UnboundedSender<(D, Bytes)>>>>,
}

impl<D: Digest, P: PublicKey> Relay<D, P> {
    #[allow(clippy::new_without_default)]
    pub const fn new() -> Self {
        Self {
            recipients: Mutex::new(BTreeMap::new()),
        }
    }

    pub fn register(&self, public_key: P) -> mpsc::UnboundedReceiver<(D, Bytes)> {
        let (sender, receiver) = mpsc::unbounded();
        {
            let mut recipients = self.recipients.lock().unwrap();
            match recipients.entry(public_key.clone()) {
                Entry::Vacant(vacant) => {
                    vacant.insert(vec![sender]);
                }
                Entry::Occupied(mut occupied) => {
                    warn!(?public_key, "duplicate registration");
                    occupied.get_mut().push(sender);
                }
            }
        }
        receiver
    }

    pub async fn broadcast(&self, sender: &P, payload: (D, Bytes)) {
        let channels = {
            let mut channels = Vec::new();
            let recipients = self.recipients.lock().unwrap();
            for (public_key, channel) in recipients.iter() {
                if public_key == sender {
                    continue;
                }
                channels.push((public_key.clone(), channel.clone()));
            }
            channels
        };
        for (recipient, listeners) in channels {
            for mut listener in listeners {
                if let Err(e) = listener.send((payload.0, payload.1.clone())).await {
                    error!(?e, ?recipient, "failed to send message to recipient");
                }
            }
        }
    }
}

impl<D: Digest, P: PublicKey> Default for Relay<D, P> {
    fn default() -> Self {
        Self::new()
    }
}
