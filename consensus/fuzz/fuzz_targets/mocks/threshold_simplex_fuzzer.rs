#![allow(dead_code)]

use crate::mocks::{FuzzInput, Message, Mutation, DEFAULT_TIMEOUT};
use arbitrary::{Arbitrary, Unstructured};
use bytes::Bytes;
use commonware_codec::{Decode, Encode};
use commonware_consensus::{
    threshold_simplex::{
        mocks::supervisor::Supervisor,
        types::{Finalize, Notarize, Nullify, Proposal, Voter},
    },
    types::Round,
    Viewable,
};
use commonware_cryptography::{
    bls12381::primitives::{group::Share, variant::Variant},
    ed25519::{PrivateKey, PublicKey},
    sha256::Digest as Sha256Digest,
    Digest,
};
use commonware_macros::select;
use commonware_p2p::{Receiver, Recipients, Sender};
use commonware_runtime::{Clock, Handle, Spawner};
use futures_timer::Delay;
use rand::{rngs::StdRng, Rng, RngCore, SeedableRng};

pub struct ThresholdFuzzer<E: Clock + Spawner, V: Variant> {
    context: E,
    crypto: PrivateKey,
    share: Share,
    supervisor: Supervisor<PublicKey, V, Sha256Digest>,
    namespace: Vec<u8>,
    rng: StdRng,
    view: u64,
}

impl<E: Clock + Spawner, V: Variant> ThresholdFuzzer<E, V> {
    pub fn new(
        context: E,
        crypto: PrivateKey,
        share: Share,
        supervisor: Supervisor<PublicKey, V, Sha256Digest>,
        namespace: Vec<u8>,
        input: FuzzInput,
    ) -> Self {
        Self {
            view: 0,
            context,
            crypto,
            share,
            supervisor,
            namespace,
            rng: StdRng::seed_from_u64(input.seed),
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
        let mut buf = [0u8; 8];
        self.rng.fill_bytes(&mut buf);
        let mut unstructured = Unstructured::new(&buf);

        let min = current_view.saturating_sub(2);
        let max = current_view.saturating_add(2);
        unstructured.int_in_range(min..=max).unwrap_or(0)
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

    pub fn start(mut self, pending_network: (impl Sender, impl Receiver)) -> Handle<()> {
        self.context.spawn_ref()(self.run(pending_network))
    }

    async fn run(mut self, pending_network: (impl Sender, impl Receiver)) {
        let (mut sender, mut receiver) = pending_network;

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
        if let 0..50 = self.rng.gen_range(0..100) {
            sender
                .send(Recipients::All, Bytes::from(msg.clone()), true)
                .await
                .unwrap();
        }

        // Parse message
        let msg = match Voter::<V, Sha256Digest>::decode_cfg(msg.as_slice(), &()) {
            Ok(msg) => msg,
            Err(_) => return, // Skip malformed messages
        };

        // Store view.
        self.view = msg.view();
        // Process message based on type
        match msg {
            Voter::Notarize(notarize) => {
                // Notarize random digest
                let mutation = self.get_mutation();
                let mutated_proposal = self.mutate_proposal(&notarize.proposal, mutation);
                let msg = Notarize::sign(&self.namespace, &self.share, mutated_proposal);
                let msg = Voter::<V, Sha256Digest>::Notarize(msg).encode().into();
                sender.send(Recipients::All, msg, true).await.unwrap();
            }
            Voter::Finalize(finalize) => {
                // Finalize random digest
                let mutation = self.get_mutation();
                let mutated_proposal = self.mutate_proposal(&finalize.proposal, mutation);
                let msg = Finalize::sign(&self.namespace, &self.share, mutated_proposal);
                let msg = Voter::<V, Sha256Digest>::Finalize(msg).encode().into();
                sender.send(Recipients::All, msg, true).await.unwrap();
            }
            Voter::Nullify(nullify) => {
                // Nullify random view
                let mutated_view = self.random_view(nullify.view());
                let msg = Nullify::sign(&self.namespace, &self.share, Round::new(0, mutated_view));

                let msg = Voter::<V, Sha256Digest>::Nullify(msg).encode().into();
                sender.send(Recipients::All, msg, true).await.unwrap();
            }
            _ => {
                // Send random message
                let malformed_bytes = self.random_bytes();
                sender
                    .send(Recipients::All, malformed_bytes.into(), true)
                    .await
                    .unwrap();
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
                Round::new(0, original.view()),
                original.parent,
                self.random_payload(),
            ),
            Mutation::View => {
                let mutated_view = self.random_view(self.view);
                Proposal::new(
                    Round::new(0, mutated_view),
                    original.parent,
                    original.payload,
                )
            }
            Mutation::Parent => {
                let mutated_parent = self.random_parent();
                Proposal::new(
                    Round::new(0, original.view()),
                    mutated_parent,
                    original.payload,
                )
            }
            Mutation::All => Proposal::new(
                Round::new(0, self.random_view(self.view)),
                self.random_parent(),
                self.random_payload(),
            ),
        }
    }

    async fn send_random_message(&mut self, sender: &mut impl Sender) {
        let proposal = Proposal::new(
            Round::new(0, self.random_view(self.view)),
            self.random_parent(),
            self.random_payload(),
        );

        let message = self.random_message();

        match message {
            Message::Notarize => {
                let msg = Notarize::sign(&self.namespace, &self.share, proposal);
                let encoded_msg = Voter::<V, Sha256Digest>::Notarize(msg).encode().into();
                let _ = sender.send(Recipients::All, encoded_msg, true).await;
            }
            Message::Finalize => {
                let msg = Finalize::sign(&self.namespace, &self.share, proposal);
                let encoded_msg = Voter::<V, Sha256Digest>::Finalize(msg).encode().into();
                let _ = sender.send(Recipients::All, encoded_msg, true).await;
            }
            Message::Nullify => {
                let msg = Nullify::sign(&self.namespace, &self.share, Round::new(0, self.view));
                let encoded_msg = Voter::<V, Sha256Digest>::Nullify(msg).encode().into();
                let _ = sender.send(Recipients::All, encoded_msg, true).await;
            }
            Message::Random => {
                let malformed_bytes = self.random_bytes();
                let _ = sender
                    .send(Recipients::All, malformed_bytes.into(), true)
                    .await;
            }
        }
    }
}
