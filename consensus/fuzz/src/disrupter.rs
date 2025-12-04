#![allow(dead_code)]

use crate::{types::Message, FuzzInput};
use arbitrary::{Arbitrary, Unstructured};
use bytes::Bytes;
use commonware_codec::{Encode, Read};
use commonware_consensus::{
    simplex::{
        mocks::reporter::Reporter,
        signing_scheme::Scheme,
        types::{Artifact, Finalize, Notarize, Nullify, Proposal, Vote},
    },
    types::{Epoch, Round, View},
    Epochable, Viewable,
};
use commonware_cryptography::{ed25519::PublicKey, sha256::Digest as Sha256Digest, Digest};
use commonware_macros::select;
use commonware_p2p::{Receiver, Recipients, Sender};
use commonware_runtime::{Clock, Handle, Spawner};
use commonware_utils::set::OrderedQuorum;
use rand::{CryptoRng, Rng};
use std::time::Duration;

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
    validator: PublicKey,
    scheme: S,
    reporter: Reporter<E, PublicKey, S, D>,
    namespace: Vec<u8>,
    fuzz_input: FuzzInput,
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
        validator: PublicKey,
        scheme: S,
        reporter: Reporter<E, PublicKey, S, D>,
        namespace: Vec<u8>,
        fuzz_input: FuzzInput,
    ) -> Self {
        Self {
            epoch: 333,
            view: 0,
            last_finalized: 0,
            last_nullified: 0,
            last_notarized: 0,
            context,
            validator,
            scheme,
            reporter,
            namespace,
            fuzz_input,
        }
    }

    fn get_mutation(&mut self) -> Mutation {
        let buf = self.fuzz_input.get_next_random(8);
        Mutation::arbitrary(&mut Unstructured::new(&buf)).unwrap_or(Mutation::All)
    }

    fn random_message(&mut self) -> Message {
        let buf = self.fuzz_input.get_next_random(8);
        Message::arbitrary(&mut Unstructured::new(&buf)).unwrap_or(Message::Random)
    }

    fn random_view(&mut self, current_view: u64) -> u64 {
        let lf = self.last_finalized;
        let lnz = self.last_notarized;
        let lnf = self.last_nullified;

        let choice = self.fuzz_input.get_next_random(1)[0] % 7;
        match choice {
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
                        lo + (self
                            .fuzz_input
                            .get_next_random(8)
                            .iter()
                            .fold(0u64, |acc, &x| (acc << 8) | x as u64)
                            % (hi - lo + 1))
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
                    lo + (self
                        .fuzz_input
                        .get_next_random(8)
                        .iter()
                        .fold(0u64, |acc, &x| (acc << 8) | x as u64)
                        % (hi - lo + 1))
                }
            }

            // 2) Active band: [last_finalized, min(last_notarized, current_view)]
            2 => {
                let lo = lf;
                let hi = lnz.min(current_view).max(lo);
                if lo >= hi {
                    lo
                } else {
                    lo + (self
                        .fuzz_input
                        .get_next_random(8)
                        .iter()
                        .fold(0u64, |acc, &x| (acc << 8) | x as u64)
                        % (hi - lo + 1))
                }
            }

            // 3) Near future (strictly ahead): [current_view+1, current_view+4]
            3 => {
                let start = current_view.saturating_add(1);
                let end = current_view.saturating_add(4);
                if start >= end {
                    start
                } else {
                    start
                        + (self
                            .fuzz_input
                            .get_next_random(8)
                            .iter()
                            .fold(0u64, |acc, &x| (acc << 8) | x as u64)
                            % (end - start + 1))
                }
            }

            // 4) Moderate future: [current_view+5, current_view+10]
            4 => {
                let start = current_view.saturating_add(5);
                let end = current_view.saturating_add(10);
                if start >= end {
                    start
                } else {
                    start
                        + (self
                            .fuzz_input
                            .get_next_random(8)
                            .iter()
                            .fold(0u64, |acc, &x| (acc << 8) | x as u64)
                            % (end - start + 1))
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
                    start
                        + (self
                            .fuzz_input
                            .get_next_random(8)
                            .iter()
                            .fold(0u64, |acc, &x| (acc << 8) | x as u64)
                            % (end - start + 1))
                }
            }

            // 6) Pure random:
            _ => self
                .fuzz_input
                .get_next_random(8)
                .iter()
                .fold(0u64, |acc, &x| (acc << 8) | x as u64),
        }
    }

    fn random_parent(&mut self) -> u64 {
        let buf = self.fuzz_input.get_next_random(8);
        let mut unstructured = Unstructured::new(&buf);
        u64::arbitrary(&mut unstructured).unwrap_or(0)
    }

    fn random_payload(&mut self) -> Sha256Digest {
        let bytes = self.fuzz_input.get_next_random(32);
        // Convert Vec<u8> to [u8; 32]
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes[..32.min(bytes.len())]);
        Sha256Digest::from(arr)
    }

    fn random_bytes(&mut self) -> Vec<u8> {
        // First get a byte to determine length
        let len_byte = self.fuzz_input.get_next_random(2);
        let len = ((len_byte[0] as usize) << 8 | len_byte[1] as usize) % 1025;

        // Now get the actual random bytes
        self.fuzz_input.get_next_random(len)
    }

    pub fn start(self, voter_network: (impl Sender, impl Receiver)) -> Handle<()> {
        let context = self.context.clone();
        context.spawn(|_| self.run(voter_network))
    }

    async fn run(mut self, voter_network: (impl Sender, impl Receiver)) {
        let (mut sender, mut receiver) = voter_network;

        loop {
            // Send a random message each 10 loop
            if self.fuzz_input.get_next_random(1)[0] % 100 < 10 {
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

                _ = self.context.sleep(DEFAULT_TIMEOUT) => {
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
        if self.fuzz_input.get_next_random(1)[0] % 100 < 10 {
            sender
                .send(Recipients::All, Bytes::from(msg.clone()), true)
                .await
                .unwrap();
        }

        // Parse message
        // Use the default config for the certificate type
        let default_cfg = Default::default();
        let msg = match Artifact::<S, Sha256Digest>::read_cfg(&mut msg.as_slice(), &default_cfg) {
            Ok(msg) => msg,
            Err(_) => return, // Skip malformed messages
        };

        self.view = msg.view().get();
        self.epoch = msg.epoch().get();

        // Process message based on type
        match msg {
            Artifact::Finalization(finalization) => {
                self.last_finalized = finalization.view().get();
                let malformed_bytes = self.random_bytes();
                sender
                    .send(Recipients::All, malformed_bytes.into(), true)
                    .await
                    .unwrap();
            }
            Artifact::Nullification(nullification) => {
                self.last_nullified = nullification.view().get();
                let malformed_bytes = self.random_bytes();
                sender
                    .send(Recipients::All, malformed_bytes.into(), true)
                    .await
                    .unwrap();
            }
            Artifact::Notarization(notarization) => {
                self.last_notarized = notarization.view().get();
                let malformed_bytes = self.random_bytes();
                sender
                    .send(Recipients::All, malformed_bytes.into(), true)
                    .await
                    .unwrap();
            }
            Artifact::Notarize(notarize) => {
                // Notarize random digest
                let mutation = self.get_mutation();
                let mutated_proposal = self.mutate_proposal(&notarize.proposal, mutation);
                let msg = Notarize::sign(&self.scheme, &self.namespace, mutated_proposal);
                if let Some(notarize) = msg {
                    let msg = Vote::<S, Sha256Digest>::Notarize(notarize.clone())
                        .encode()
                        .into();
                    sender.send(Recipients::All, msg, true).await.unwrap();
                }
            }
            Artifact::Finalize(finalize) => {
                // Finalize random digest
                let mutation = self.get_mutation();
                let mutated_proposal = self.mutate_proposal(&finalize.proposal, mutation);
                let msg = Finalize::sign(&self.scheme, &self.namespace, mutated_proposal);
                if let Some(finalize) = msg {
                    let msg = Vote::<S, Sha256Digest>::Finalize(finalize).encode().into();
                    sender.send(Recipients::All, msg, true).await.unwrap();
                }
            }
            Artifact::Nullify(nullify) => {
                // Nullify random view
                let mutated_view = self.random_view(nullify.view().get());
                let msg = Nullify::<S>::sign::<Sha256Digest>(
                    &self.scheme,
                    &self.namespace,
                    Round::new(Epoch::new(self.epoch), View::new(mutated_view)),
                );
                if let Some(nullify) = msg {
                    let msg = Vote::<S, Sha256Digest>::Nullify(nullify).encode().into();
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
                    Round::new(original.epoch(), View::new(mutated_view)),
                    original.parent,
                    original.payload,
                )
            }
            Mutation::Parent => {
                let mutated_parent = self.random_parent();
                Proposal::new(
                    Round::new(original.epoch(), original.view()),
                    View::new(mutated_parent),
                    original.payload,
                )
            }
            Mutation::All => Proposal::new(
                Round::new(original.epoch(), View::new(self.random_view(self.view))),
                View::new(self.random_parent()),
                self.random_payload(),
            ),
        }
    }

    async fn send_random_message(&mut self, sender: &mut impl Sender) {
        let real_view = self.view;

        let proposal = Proposal::new(
            Round::new(
                Epoch::new(self.epoch),
                View::new(self.random_view(self.view)),
            ),
            View::new(self.random_parent()),
            self.random_payload(),
        );

        // Check if we're a participant
        if self.reporter.participants.index(&self.validator).is_some() {
            let message = self.random_message();

            match message {
                Message::Notarize => {
                    if let Some(msg) = Notarize::sign(&self.scheme, &self.namespace, proposal) {
                        let encoded_msg = Vote::<S, Sha256Digest>::Notarize(msg).encode().into();
                        let _ = sender.send(Recipients::All, encoded_msg, true).await;
                    }
                }
                Message::Finalize => {
                    if let Some(msg) = Finalize::sign(&self.scheme, &self.namespace, proposal) {
                        let encoded_msg = Vote::<S, Sha256Digest>::Finalize(msg).encode().into();
                        let _ = sender.send(Recipients::All, encoded_msg, true).await;
                    }
                }
                Message::Nullify => {
                    if let Some(msg) = Nullify::<S>::sign::<Sha256Digest>(
                        &self.scheme,
                        &self.namespace,
                        Round::new(Epoch::new(self.epoch), View::new(real_view)),
                    ) {
                        let encoded_msg = Vote::<S, Sha256Digest>::Nullify(msg).encode().into();
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
