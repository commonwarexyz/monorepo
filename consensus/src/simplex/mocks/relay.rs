use bytes::Bytes;
use commonware_cryptography::FormattedArray;
use futures::{channel::mpsc, SinkExt};
use std::{collections::BTreeMap, sync::Mutex};

/// Relay is a mock for distributing artifacts between applications.
pub struct Relay<D: FormattedArray, P: FormattedArray> {
    recipients: Mutex<BTreeMap<P, mpsc::UnboundedSender<(D, Bytes)>>>,
}

impl<D: FormattedArray, P: FormattedArray> Relay<D, P> {
    pub fn new() -> Self {
        Self {
            recipients: Mutex::new(BTreeMap::new()),
        }
    }

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

    pub async fn broadcast(&self, sender: &P, payload: (D, Bytes)) {
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

impl<D: FormattedArray, P: FormattedArray> Default for Relay<D, P> {
    fn default() -> Self {
        Self::new()
    }
}
