use crate::{Hash, Height, Payload};
use bytes::Bytes;
use commonware_cryptography::PublicKey;
use commonware_utils::{hash, hex};
use futures::{channel::mpsc, SinkExt};
use std::collections::HashMap;

pub enum Progress {
    Notarized(Height),
    Finalized(Height),
}

pub struct Application {
    participant: PublicKey,

    verified: HashMap<Hash, Height>,
    finalized: HashMap<Hash, Height>,

    progress: mpsc::UnboundedSender<(PublicKey, Progress)>,
}

impl Application {
    pub fn new(
        participant: PublicKey,
        sender: mpsc::UnboundedSender<(PublicKey, Progress)>,
    ) -> Self {
        Self {
            participant,
            verified: HashMap::new(),
            finalized: HashMap::new(),
            progress: sender,
        }
    }

    fn verify_payload(height: Height, payload: &Payload) {
        if payload.len() != 32 + 8 {
            panic!("invalid payload length");
        }
        let parsed_height = Height::from_be_bytes(payload[32..].try_into().unwrap());
        if parsed_height != height {
            panic!("invalid height");
        }
    }
}

impl crate::Application for Application {
    fn genesis(&mut self) -> (Hash, Payload) {
        let payload = Bytes::from("genesis");
        let hash = hash(&payload);
        self.verified.insert(hash.clone(), 0);
        self.finalized.insert(hash.clone(), 0);
        (hash, payload)
    }

    async fn propose(&mut self, parent: Hash, height: Height) -> Option<Payload> {
        let parent = self.verified.get(&parent).expect("parent not verified");
        if parent + 1 != height {
            panic!("invalid height");
        }
        let mut payload = Vec::new();
        payload.extend_from_slice(&self.participant);
        payload.extend_from_slice(&height.to_be_bytes());
        Some(Bytes::from(payload))
    }

    fn parse(&self, _parent: Hash, height: Height, payload: Payload) -> Option<Hash> {
        Self::verify_payload(height, &payload);
        Some(hash(&payload))
    }

    async fn verify(&mut self, parent: Hash, height: Height, payload: Payload, hash: Hash) -> bool {
        if let Some(height) = self.verified.get(&hash) {
            panic!("hash already verified: {}:{:?}", height, hex(&hash));
        }
        Self::verify_payload(height, &payload);
        let parent = match self.verified.get(&parent) {
            Some(parent) => parent,
            None => {
                panic!(
                    "[{:?}] parent {:?} of {}, not verified",
                    hex(&self.participant),
                    hex(&parent),
                    height
                );
            }
        };
        if parent + 1 != height {
            panic!("invalid height");
        }
        self.verified.insert(hash.clone(), height);
        true
    }

    async fn notarized(&mut self, hash: Hash) {
        let height = self.verified.get(&hash).expect("hash not verified");
        if self.finalized.contains_key(&hash) {
            panic!("hash already finalized");
        }
        self.progress
            .send((self.participant.clone(), Progress::Notarized(*height)))
            .await
            .unwrap();
    }

    async fn finalized(&mut self, hash: Hash) {
        if let Some(height) = self.finalized.get(&hash) {
            panic!("hash already finalized: {}:{:?}", height, hex(&hash));
        }
        let height = self.verified.get(&hash).expect("hash not verified");
        self.finalized.insert(hash, *height);
        self.progress
            .send((self.participant.clone(), Progress::Finalized(*height)))
            .await
            .unwrap();
    }
}
