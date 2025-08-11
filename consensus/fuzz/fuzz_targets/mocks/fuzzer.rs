//! Byzantine participant that sends random messages.

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

const DEFAULT_TIMEOUT: Duration = Duration::from_millis(500);

#[derive(Debug, Clone, Arbitrary)]
pub enum PartitionStrategy {
    /// All validators can communicate with all others (full mesh)
    Connected,

    /// Validator 0 acts as byzantine, can talk to itself and both halves
    /// Other validators are split into two partitions that cannot communicate
    TwoPartitionsWithByzantine,

    /// The byzantine validator can send messages to all other validators.
    /// Other validators cannot communicate with each other.
    ManyPartitionsWithByzantine,

    /// No validator can communicate with any other (complete isolation)
    Isolated,

    /// Validator i can send messages to itself or the next validator
    Linear,
}

fn two_partitions_with_byzantine(n: usize, i: usize, j: usize) -> bool {
    if i == 0 || j == 0 {
        return true;
    }

    let mid = n / 2;
    let i_partition = if i <= mid { 1 } else { 2 };
    let j_partition = if j <= mid { 1 } else { 2 };

    i_partition == j_partition
}

fn many_partitions_with_byzantine(_: usize, i: usize, j: usize) -> bool {
    i == 0 || j == 0
}

fn linear(n: usize, i: usize, j: usize) -> bool {
    i + 1 % n == j % n || i == j
}

impl PartitionStrategy {
    pub fn create(&self) -> Option<fn(usize, usize, usize) -> bool> {
        match self {
            PartitionStrategy::Connected => None,
            PartitionStrategy::Isolated => Some(|_n, i, j| i == j),
            PartitionStrategy::TwoPartitionsWithByzantine => Some(two_partitions_with_byzantine),
            PartitionStrategy::ManyPartitionsWithByzantine => Some(many_partitions_with_byzantine),
            PartitionStrategy::Linear => Some(linear),
        }
    }
}

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
    pub seed: u64, // Seed for rng
    #[arbitrary(with = |u: &mut Unstructured| u.int_in_range(32..=3000))]
    pub max_steps: u16, // The number of steps the fuzzing actor can do before it stops.
    pub partition: PartitionStrategy,
}

pub struct Fuzzer<E: Clock + Spawner> {
    context: E,
    crypto: PrivateKey,
    supervisor: Supervisor<PublicKey, Sha256Digest>,
    namespace: Vec<u8>,
    rng: StdRng,
    view: u64,
    max_steps: u16,
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
            max_steps: input.max_steps,
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

    pub fn start(mut self, voter_network: (impl Sender, impl Receiver)) -> Handle<()> {
        self.context.spawn_ref()(self.run(voter_network))
    }

    async fn run(mut self, voter_network: (impl Sender, impl Receiver)) {
        let (mut sender, mut receiver) = voter_network;
        let mut steps = 0;

        while steps < self.max_steps {
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
                // Get our index
                let public_key_index = self
                    .supervisor
                    .is_participant(self.view, &self.crypto.public_key())
                    .unwrap();

                // Notarize random digest
                let mutation = self.get_mutation();
                let mutated_proposal = self.mutate_proposal(&notarize.proposal, mutation);
                let msg = Notarize::sign(
                    &self.namespace,
                    &mut self.crypto,
                    public_key_index,
                    mutated_proposal,
                );
                let msg =
                    Voter::<commonware_cryptography::ed25519::Signature, Sha256Digest>::Notarize(
                        msg,
                    )
                    .encode()
                    .into();
                sender.send(Recipients::All, msg, true).await.unwrap();
            }
            Voter::Finalize(finalize) => {
                // Get our index
                let public_key_index = self
                    .supervisor
                    .is_participant(self.view, &self.crypto.public_key())
                    .unwrap();

                // Finalize random digest
                let mutation = self.get_mutation();
                let mutated_proposal = self.mutate_proposal(&finalize.proposal, mutation);
                let msg = Finalize::sign(
                    &self.namespace,
                    &mut self.crypto,
                    public_key_index,
                    mutated_proposal,
                );
                let msg =
                    Voter::<commonware_cryptography::ed25519::Signature, Sha256Digest>::Finalize(
                        msg,
                    )
                    .encode()
                    .into();
                sender.send(Recipients::All, msg, true).await.unwrap();
            }
            Voter::Nullify(nullify) => {
                // Get our index
                let public_key_index = self
                    .supervisor
                    .is_participant(nullify.view, &self.crypto.public_key())
                    .unwrap();

                // Nullify random view
                let mutated_view = self.random_view(nullify.view);
                let msg = Nullify::sign(
                    &self.namespace,
                    &mut self.crypto,
                    public_key_index,
                    mutated_view,
                );
                let msg =
                    Voter::<commonware_cryptography::ed25519::Signature, Sha256Digest>::Nullify(
                        msg,
                    )
                    .encode()
                    .into();
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
            Mutation::Payload => {
                Proposal::new(original.view, original.parent, self.random_payload())
            }
            Mutation::View => {
                let mutated_view = self.random_view(self.view);
                Proposal::new(mutated_view, original.parent, original.payload)
            }
            Mutation::Parent => {
                let mutated_parent = self.random_parent();
                Proposal::new(original.view, mutated_parent, original.payload)
            }
            Mutation::All => Proposal::new(
                self.random_view(self.view),
                self.random_parent(),
                self.random_payload(),
            ),
        }
    }

    async fn send_random_message(&mut self, sender: &mut impl Sender) {
        let real_view = self.view;

        let proposal = Proposal::new(
            self.random_view(self.view),
            self.random_parent(),
            self.random_payload(),
        );

        if let Some(public_key_index) = self
            .supervisor
            .is_participant(real_view, &self.crypto.public_key())
        {
            let message = self.random_message();

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
