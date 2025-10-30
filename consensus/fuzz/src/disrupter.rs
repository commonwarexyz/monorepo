#![allow(dead_code)]

use crate::types::Message;
use arbitrary::{Arbitrary, Unstructured};
use bytes::Bytes;
use commonware_codec::{Encode, Read};
use commonware_consensus::{
    simplex::{
        mocks::reporter::Reporter,
        signing_scheme::Scheme,
        types::{Finalize, Notarize, Nullify, Proposal, Voter},
    },
    types::Round,
    Epochable, Viewable,
};
use commonware_cryptography::{
    ed25519::{PrivateKey, PublicKey},
    sha256::Digest as Sha256Digest,
    Digest, Signer as _,
};
use commonware_macros::select;
use commonware_p2p::{Receiver, Recipients, Sender};
use commonware_runtime::{Clock, Handle, Spawner};
use futures_timer::Delay;
use rand::{rngs::StdRng, CryptoRng, Rng, RngCore, SeedableRng};
use std::time::Duration;
use commonware_consensus::simplex::types::OrderedExt;

pub const DEFAULT_TIMEOUT: Duration = Duration::from_millis(500);

#[derive(Debug, Clone, Arbitrary)]
pub enum Mutation {
    Payload,
    View,
    Parent,
    All,
}

/// A disrupter node that intentionally disrupts consensus protocol execution
/// by sending malformed messages, mutating valid messages, and exhibiting
/// Byzantine behavior. Used for testing protocol resilience and fault tolerance.
///
/// The disrupter acts **randomly** rather than implementing sophisticated attacks:
/// - Mutates proposal payloads, views, and parent references randomly
/// - Mirrors received messages back to the network
/// - Sends malformed/random byte sequences
/// - Signs messages with incorrect data
///
/// This simulates basic adversarial or faulty nodes in a distributed consensus
/// system without coordinated or targeted attack strategies.
pub struct Disrupter<E: Clock + Spawner + Rng + CryptoRng, S: Scheme, D: Digest> {
    context: E,
    private_key: PrivateKey,
    scheme: S,
    reporter: Reporter<E, PublicKey, S, D>,
    namespace: Vec<u8>,
    rng: StdRng,
    view: u64,
    epoch: u64,
    last_finalized: u64,
    last_nullified: u64,
    last_notarized: u64,
}

impl<E: Clock + Spawner + Rng + CryptoRng, S: Scheme, D: Digest> Disrupter<E, S, D>
where
    <S::Certificate as Read>::Cfg: Default,
{
    pub fn new(
        context: E,
        private_key: PrivateKey,
        scheme: S,
        reporter: Reporter<E, PublicKey, S, D>,
        namespace: Vec<u8>,
        seed: u64,
    ) -> Self {
        Self {
            epoch: 333,
            view: 0,
            last_finalized: 0,
            last_nullified: 0,
            last_notarized: 0,
            context,
            private_key,
            scheme,
            reporter,
            namespace,
            rng: StdRng::seed_from_u64(seed),
        }
    }

    fn get_mutation(&mut self) -> Mutation {
        let mut buf = [0u8; 8];
        self.rng.fill_bytes(&mut buf);
        Mutation::arbitrary(&mut Unstructured::new(&buf)).unwrap_or(Mutation::All)
    }

    fn random_message(&mut self) -> Message {
        let mut buf = [0u8; 8];
        self.rng.fill_bytes(&mut buf);
        Message::arbitrary(&mut Unstructured::new(&buf)).unwrap_or(Message::Random)
    }

    fn random_view(&mut self, current_view: u64) -> u64 {
        let lf = self.last_finalized;
        let lnz = self.last_notarized;
        let lnf = self.last_nullified;

        match self.rng.gen_range(0..7) {
            // 0) Too old (pre-finalized) — should be filtered.
            0 => {
                if lf == 0 {
                    0
                } else {
                    let lo = 0u64;
                    let hi = lf.saturating_sub(1);
                    if lo >= hi {
                        lo
                    } else {
                        self.rng.gen_range(lo..=hi)
                    }
                }
            }

            // 1) Active past: [last_finalized, current_view]
            1 => {
                let lo = lf.min(current_view);
                let hi = current_view;
                if lo >= hi {
                    lo
                } else {
                    self.rng.gen_range(lo..=hi)
                }
            }

            // 2) Active band: [last_finalized, min(last_notarized, current_view)]
            2 => {
                let lo = lf;
                let hi = lnz.min(current_view).max(lo);
                if lo >= hi {
                    lo
                } else {
                    self.rng.gen_range(lo..=hi)
                }
            }

            // 3) Near future (strictly ahead): [current_view+1, current_view+4]
            3 => {
                let start = current_view.saturating_add(1);
                let end = current_view.saturating_add(4);
                if start >= end {
                    start
                } else {
                    self.rng.gen_range(start..=end)
                }
            }

            // 4) Moderate future: [current_view+5, current_view+10]
            4 => {
                let start = current_view.saturating_add(5);
                let end = current_view.saturating_add(10);
                if start >= end {
                    start
                } else {
                    self.rng.gen_range(start..=end)
                }
            }

            // 5) Nullification-based future:
            // start just after max(current_view, last_nullified), span ~10 views
            5 => {
                let base = current_view.max(lnf);
                let start = base.saturating_add(1);
                let end = base.saturating_add(10);
                if start >= end {
                    start
                } else {
                    self.rng.gen_range(start..=end)
                }
            }

            // 6) Pure random:
            _ => self.rng.next_u64(),
        }
    }

    fn random_parent(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        self.rng.fill_bytes(&mut buf);
        let mut unstructured = Unstructured::new(&buf);
        u64::arbitrary(&mut unstructured).unwrap_or(0)
    }

    fn random_payload(&mut self) -> Sha256Digest {
        Sha256Digest::random(&mut self.rng)
    }

    fn random_bytes(&mut self) -> Vec<u8> {
        let mut buf = [0u8; 8];
        self.rng.fill_bytes(&mut buf);
        let mut unstructured = Unstructured::new(&buf);

        let len = unstructured.int_in_range(0..=1024).unwrap_or(0);
        (0..len)
            .map(|_| u8::arbitrary(&mut unstructured).unwrap_or(0))
            .collect()
    }

    pub fn start(self, voter_network: (impl Sender, impl Receiver)) -> Handle<()> {
        let context = self.context.clone();
        context.spawn(|_| self.run(voter_network))
    }

    async fn run(mut self, voter_network: (impl Sender, impl Receiver)) {
        let (mut sender, mut receiver) = voter_network;

        loop {
            // Send a random message each 10 loop
            if let 0..10 = self.rng.gen_range(0..100) {
                self.send_random_message(&mut sender).await;
            }

            select! {
                result = receiver.recv().fuse() => {
                    match result {
                        Ok((s, msg)) => {
                            self.handle_received_message(&mut sender, s, msg.to_vec())
                                .await;
                        }
                        Err(_) => {
                            self.send_random_message(&mut sender).await;
                        }
                    }
                },

                _ = Delay::new(DEFAULT_TIMEOUT).fuse() => {
                    self.send_random_message(&mut sender).await;
                }
            }
        }
    }

    async fn handle_received_message(
        &mut self,
        sender: &mut impl Sender,
        _sender_id: impl std::fmt::Debug,
        msg: Vec<u8>,
    ) {
        // just mirror the message
        if let 0..10 = self.rng.gen_range(0..100) {
            sender
                .send(Recipients::All, Bytes::from(msg.clone()), true)
                .await
                .unwrap();
        }

        // Parse message
        // Use the default config for the certificate type
        let default_cfg = Default::default();
        let msg = match Voter::<S, Sha256Digest>::read_cfg(&mut msg.as_slice(), &default_cfg) {
            Ok(msg) => msg,
            Err(_) => return, // Skip malformed messages
        };

        self.view = msg.view();
        self.epoch = msg.epoch();

        // Process message based on type
        match msg {
            Voter::Finalization(finalization) => {
                self.last_finalized = finalization.view();
                let malformed_bytes = self.random_bytes();
                sender
                    .send(Recipients::All, malformed_bytes.into(), true)
                    .await
                    .unwrap();
            }
            Voter::Nullification(nullification) => {
                self.last_nullified = nullification.view();
                let malformed_bytes = self.random_bytes();
                sender
                    .send(Recipients::All, malformed_bytes.into(), true)
                    .await
                    .unwrap();
            }
            Voter::Notarization(notarization) => {
                self.last_notarized = notarization.view();
                let malformed_bytes = self.random_bytes();
                sender
                    .send(Recipients::All, malformed_bytes.into(), true)
                    .await
                    .unwrap();
            }
            Voter::Notarize(notarize) => {
                // Notarize random digest
                let mutation = self.get_mutation();
                let mutated_proposal = self.mutate_proposal(&notarize.proposal, mutation);
                let msg = Notarize::sign(&self.scheme, &self.namespace, mutated_proposal);
                if let Some(notarize) = msg {
                    let msg = Voter::<S, Sha256Digest>::Notarize(notarize.clone())
                        .encode()
                        .into();
                    sender.send(Recipients::All, msg, true).await.unwrap();
                }
            }
            Voter::Finalize(finalize) => {
                // Finalize random digest
                let mutation = self.get_mutation();
                let mutated_proposal = self.mutate_proposal(&finalize.proposal, mutation);
                let msg = Finalize::sign(&self.scheme, &self.namespace, mutated_proposal);
                if let Some(finalize) = msg {
                    let msg = Voter::<S, Sha256Digest>::Finalize(finalize).encode().into();
                    sender.send(Recipients::All, msg, true).await.unwrap();
                }
            }
            Voter::Nullify(nullify) => {
                // Nullify random view
                let mutated_view = self.random_view(nullify.view());
                let msg = Nullify::<S>::sign::<Sha256Digest>(
                    &self.scheme,
                    &self.namespace,
                    Round::new(self.epoch, mutated_view),
                );
                if let Some(nullify) = msg {
                    let msg = Voter::<S, Sha256Digest>::Nullify(nullify).encode().into();
                    sender.send(Recipients::All, msg, true).await.unwrap();
                }
            }
        }
    }

    fn mutate_proposal(
        &mut self,
        original: &Proposal<Sha256Digest>,
        strategy: Mutation,
    ) -> Proposal<Sha256Digest> {
        match strategy {
            Mutation::Payload => Proposal::new(
                Round::new(original.epoch(), original.view()),
                original.parent,
                self.random_payload(),
            ),
            Mutation::View => {
                let mutated_view = self.random_view(self.view);
                Proposal::new(
                    Round::new(original.epoch(), mutated_view),
                    original.parent,
                    original.payload,
                )
            }
            Mutation::Parent => {
                let mutated_parent = self.random_parent();
                Proposal::new(
                    Round::new(original.epoch(), original.view()),
                    mutated_parent,
                    original.payload,
                )
            }
            Mutation::All => Proposal::new(
                Round::new(original.epoch(), self.random_view(self.view)),
                self.random_parent(),
                self.random_payload(),
            ),
        }
    }

    async fn send_random_message(&mut self, sender: &mut impl Sender) {
        let real_view = self.view;

        let proposal = Proposal::new(
            Round::new(self.epoch, self.random_view(self.view)),
            self.random_parent(),
            self.random_payload(),
        );

        // Check if we're a participant
        let validator = self.private_key.public_key();
        if self.reporter.participants.index(&validator).is_some() {
            let message = self.random_message();

            match message {
                Message::Notarize => {
                    if let Some(msg) = Notarize::sign(&self.scheme, &self.namespace, proposal) {
                        let encoded_msg = Voter::<S, Sha256Digest>::Notarize(msg).encode().into();
                        let _ = sender.send(Recipients::All, encoded_msg, true).await;
                    }
                }
                Message::Finalize => {
                    if let Some(msg) = Finalize::sign(&self.scheme, &self.namespace, proposal) {
                        let encoded_msg = Voter::<S, Sha256Digest>::Finalize(msg).encode().into();
                        let _ = sender.send(Recipients::All, encoded_msg, true).await;
                    }
                }
                Message::Nullify => {
                    if let Some(msg) = Nullify::<S>::sign::<Sha256Digest>(
                        &self.scheme,
                        &self.namespace,
                        Round::new(self.epoch, real_view),
                    ) {
                        let encoded_msg = Voter::<S, Sha256Digest>::Nullify(msg).encode().into();
                        let _ = sender.send(Recipients::All, encoded_msg, true).await;
                    }
                }
                Message::Random => {
                    let malformed_bytes = self.random_bytes();
                    let _ = sender
                        .send(Recipients::All, malformed_bytes.into(), true)
                        .await;
                }
            }
        } else {
            let malformed_bytes = self.random_bytes();
            let _ = sender
                .send(Recipients::All, malformed_bytes.into(), true)
                .await;
        }
    }
}
