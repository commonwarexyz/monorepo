use arbitrary::{Arbitrary, Unstructured};
use commonware_codec::{Decode, Encode};
use commonware_consensus::{
    simplex::{
        mocks::supervisor::Supervisor,
        types::{Finalize, Notarize, Nullify, Proposal, Voter},
    },
    Supervisor as SupervisorTrait, Viewable,
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
use rand::{rngs::StdRng, RngCore, SeedableRng};
use std::time::Duration;

// The number of steps the fuzzing actor can do before it stops.
const MAX_STEPS: usize = 100;
const DEFAULT_TIMEOUT: Duration = Duration::from_millis(100);

#[derive(Debug, Clone, Arbitrary)]
pub enum Mutation {
    Payload,
    View,
    Parent,
    All,
}

#[derive(Debug, Clone, Arbitrary)]
pub enum Message {
    Notarize,
    Nullify,
    Finalize,
    Random,
}

#[derive(Debug, Arbitrary)]
pub struct FuzzInput {
    pub seed: u64,
    pub mutations: Vec<Mutation>,
    pub views: Vec<u64>,
    pub parents: Vec<u64>,
    pub malformed_bytes: Vec<Vec<u8>>,
}
pub struct Fuzzer<E: Clock + Spawner> {
    context: E,
    crypto: PrivateKey,
    supervisor: Supervisor<PublicKey, Sha256Digest>,
    namespace: Vec<u8>,
    rng: StdRng,
    mutations: Vec<Mutation>,
    views: Vec<u64>,
    parents: Vec<u64>,
    malformed_bytes: Vec<Vec<u8>>,
    mutation_idx: usize,
    view: u64,
}

impl<E: Clock + Spawner> Fuzzer<E> {
    pub fn new(
        context: E,
        crypto: PrivateKey,
        supervisor: Supervisor<PublicKey, Sha256Digest>,
        namespace: Vec<u8>,
        input: FuzzInput,
    ) -> Self {
        Self {
            view: 0,
            context,
            crypto,
            supervisor,
            namespace,
            rng: StdRng::seed_from_u64(input.seed),
            mutations: input.mutations,
            views: input.views,
            parents: input.parents,
            malformed_bytes: input.malformed_bytes,
            mutation_idx: 0,
        }
    }

    fn get_next_mutation(&mut self) -> Option<&Mutation> {
        if self.mutation_idx < self.mutations.len() {
            let mutation = &self.mutations[self.mutation_idx];
            self.mutation_idx += 1;
            Some(mutation)
        } else {
            None
        }
    }

    fn get_view(&mut self) -> u64 {
        self.views
            .get(self.mutation_idx % self.views.len().max(1))
            .copied()
            .unwrap_or(0)
    }

    fn get_parent(&mut self) -> u64 {
        self.parents
            .get(self.mutation_idx % self.parents.len().max(1))
            .copied()
            .unwrap_or(0)
    }

    fn get_payload(&mut self) -> Sha256Digest {
        Sha256Digest::random(&mut self.rng)
    }

    fn get_malformed_bytes(&mut self) -> Vec<u8> {
        self.malformed_bytes
            .get(self.mutation_idx % self.malformed_bytes.len().max(1))
            .cloned()
            .unwrap_or_else(|| vec![0u8; 32])
    }

    pub fn start(mut self, voter_network: (impl Sender, impl Receiver)) -> Handle<()> {
        self.context.spawn_ref()(self.run(voter_network))
    }

    async fn run(mut self, voter_network: (impl Sender, impl Receiver)) {
        let (mut sender, mut receiver) = voter_network;
        let mut steps = 0;

        while steps < MAX_STEPS {
            select! {
                result = receiver.recv().fuse() => {
                    match result {
                        Ok((s, msg)) => {
                            // Received a message - mutate and resend it
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
            steps += 1;
        }
    }

    async fn handle_received_message(
        &mut self,
        sender: &mut impl Sender,
        _sender_id: impl std::fmt::Debug,
        msg: Vec<u8>,
    ) {
        // Parse message
        let msg =
            match Voter::<commonware_cryptography::ed25519::Signature, Sha256Digest>::decode_cfg(
                msg.as_slice(),
                &usize::MAX,
            ) {
                Ok(msg) => msg,
                Err(_) => return, // Skip malformed messages
            };
        // Store view.
        self.view = msg.view();

        // Process message based on type
        match msg {
            Voter::Notarize(notarize) => {
                if let Some(public_key_index) = self
                    .supervisor
                    .is_participant(self.view, &self.crypto.public_key())
                {
                    if let Some(strategy) = self.get_next_mutation().cloned() {
                        let mutated_proposal = self.mutate_proposal(&notarize.proposal, &strategy);
                        let msg = Notarize::sign(
                            &self.namespace,
                            &mut self.crypto,
                            public_key_index,
                            mutated_proposal,
                        );
                        let encoded_msg = Voter::<
                            commonware_cryptography::ed25519::Signature,
                            Sha256Digest,
                        >::Notarize(msg)
                        .encode()
                        .into();
                        let _ = sender.send(Recipients::All, encoded_msg, true).await;
                    } else {
                        let malformed_bytes = self.get_malformed_bytes();
                        let _ = sender
                            .send(Recipients::All, malformed_bytes.into(), true)
                            .await;
                    }
                }
            }
            Voter::Finalize(finalize) => {
                if let Some(public_key_index) = self
                    .supervisor
                    .is_participant(self.view, &self.crypto.public_key())
                {
                    if let Some(strategy) = self.get_next_mutation().cloned() {
                        let mutated_proposal = self.mutate_proposal(&finalize.proposal, &strategy);
                        let msg = Finalize::sign(
                            &self.namespace,
                            &mut self.crypto,
                            public_key_index,
                            mutated_proposal,
                        );
                        let encoded_msg = Voter::<
                            commonware_cryptography::ed25519::Signature,
                            Sha256Digest,
                        >::Finalize(msg)
                        .encode()
                        .into();
                        let _ = sender.send(Recipients::All, encoded_msg, true).await;
                    } else {
                        let malformed_bytes = self.get_malformed_bytes();
                        let _ = sender
                            .send(Recipients::All, malformed_bytes.into(), true)
                            .await;
                    }
                }
            }
            Voter::Nullify(nullify) => {
                if let Some(public_key_index) = self
                    .supervisor
                    .is_participant(nullify.view, &self.crypto.public_key())
                {
                    let view = nullify.view;
                    let msg =
                        Nullify::sign(&self.namespace, &mut self.crypto, public_key_index, view);
                    let encoded = Voter::<commonware_cryptography::ed25519::Signature, Sha256Digest>::Nullify(msg).encode().into();
                    let _ = sender.send(Recipients::All, encoded, true).await;
                }
            }
            _ => {
                let malformed_bytes = self.get_malformed_bytes();
                let _ = sender
                    .send(Recipients::All, malformed_bytes.into(), true)
                    .await;
            }
        }
    }

    fn mutate_proposal(
        &mut self,
        original: &Proposal<Sha256Digest>,
        strategy: &Mutation,
    ) -> Proposal<Sha256Digest> {
        match strategy {
            Mutation::Payload => Proposal::new(original.view, original.parent, self.get_payload()),
            Mutation::View => {
                let mutated_view = self.get_view();
                Proposal::new(mutated_view, original.parent, original.payload)
            }
            Mutation::Parent => {
                let mutated_parent = self.get_parent();
                Proposal::new(original.view, mutated_parent, original.payload)
            }
            Mutation::All => Proposal::new(self.get_view(), self.get_parent(), self.get_payload()),
        }
    }

    async fn send_random_message(&mut self, sender: &mut impl Sender) {
        let real_view = self.view;

        let proposal = Proposal::new(self.get_view(), self.get_parent(), self.get_payload());

        if let Some(public_key_index) = self
            .supervisor
            .is_participant(real_view, &self.crypto.public_key())
        {
            // Use the provided step parameter or generate a random one
            let mut buf = [0u8; 8];
            self.rng.fill_bytes(&mut buf);
            let mut unstructured = Unstructured::new(&buf);

            let message: Message = Message::arbitrary(&mut unstructured).unwrap_or(Message::Random);

            match message {
                Message::Notarize => {
                    let msg = Notarize::sign(
                        &self.namespace,
                        &mut self.crypto,
                        public_key_index,
                        proposal,
                    );
                    let encoded_msg = Voter::<
                        commonware_cryptography::ed25519::Signature,
                        Sha256Digest,
                    >::Notarize(msg)
                    .encode()
                    .into();
                    let _ = sender.send(Recipients::All, encoded_msg, true).await;
                }
                Message::Finalize => {
                    let msg = Finalize::sign(
                        &self.namespace,
                        &mut self.crypto,
                        public_key_index,
                        proposal,
                    );
                    let encoded_msg = Voter::<
                        commonware_cryptography::ed25519::Signature,
                        Sha256Digest,
                    >::Finalize(msg)
                    .encode()
                    .into();
                    let _ = sender.send(Recipients::All, encoded_msg, true).await;
                }
                Message::Nullify => {
                    let msg = Nullify::sign(
                        &self.namespace,
                        &mut self.crypto,
                        public_key_index,
                        real_view,
                    );
                    let encoded_msg = Voter::<
                        commonware_cryptography::ed25519::Signature,
                        Sha256Digest,
                    >::Nullify(msg)
                    .encode()
                    .into();
                    let _ = sender.send(Recipients::All, encoded_msg, true).await;
                }

                Message::Random => {
                    let malformed_bytes = self.get_malformed_bytes();
                    let _ = sender
                        .send(Recipients::All, malformed_bytes.into(), true)
                        .await;
                }
            }
        } else {
            let malformed_bytes = self.get_malformed_bytes();
            let _ = sender
                .send(Recipients::All, malformed_bytes.into(), true)
                .await;
        }
    }
}
