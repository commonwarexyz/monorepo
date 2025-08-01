#![no_main]

mod common;
use arbitrary::{Arbitrary, Unstructured};
use common::{link_validators, register_validators, Action};
use commonware_codec::{Encode, Decode};
use commonware_consensus::{
    simplex::{
        config::Config,
        mocks::{self, supervisor::Supervisor},
        types::{Finalize, Notarize, Nullify, Proposal, Voter},
        Engine,
    },
    Supervisor as SupervisorTrait,
    Viewable,
};
use commonware_cryptography::{
    ed25519::{PrivateKey, PublicKey},
    sha256::Digest as Sha256Digest,
    Digest, PrivateKeyExt as _, Sha256, Signer as _,
};
use commonware_p2p::{
    simulated::{Config as NetworkConfig, Link, Network},
    Receiver, Recipients, Sender,
};
use commonware_runtime::{
    deterministic::{self},
    Clock, Handle, Metrics, Runner, Spawner,
};
use commonware_utils::NZU32;
use governor::Quota;
use libfuzzer_sys::fuzz_target;
use rand::{rngs::StdRng, Rng, SeedableRng};
use std::{collections::BTreeMap, sync::Arc, time::Duration};

// The number of steps the actor can do before it stops.
const MAX_STEPS: usize = 100;

#[derive(Debug, Clone)]
pub enum FuzzStep {
    SendNotarize,
    SendFinalize,
    SendNullify,
    SendNotarization,
    SendFinalization,
    SendNullification,
    SendMalformedBytes,
}

impl<'a> Arbitrary<'a> for FuzzStep {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let val: u8 = u.arbitrary()?;
        Ok(match val % 7 {
            0 => FuzzStep::SendNotarize,
            1 => FuzzStep::SendFinalize,
            2 => FuzzStep::SendNullify,
            3 => FuzzStep::SendNotarization,
            4 => FuzzStep::SendFinalization,
            5 => FuzzStep::SendNullification,
            6 => FuzzStep::SendMalformedBytes,
            _ => unreachable!(),
        })
    }
}

#[derive(Debug, Arbitrary)]
pub struct FuzzInput {
    seed: u64,
    mutations: Vec<FuzzStep>,
    views: Vec<u64>,
    parents: Vec<u64>,
    malformed_bytes: Vec<Vec<u8>>,
    link_latency: f64,
    link_jitter: f64,
    link_success_rate: f64,
}

struct FuzzingActor<E: Clock + Spawner + Rng> {
    context: E,
    crypto: PrivateKey,
    supervisor: Supervisor<PublicKey, Sha256Digest>,
    namespace: Vec<u8>,
    rng: StdRng,
    mutations: Vec<FuzzStep>,
    view_offsets: Vec<u64>,
    parent_offsets: Vec<u64>,
    malformed_bytes: Vec<Vec<u8>>,
    mutation_idx: usize,
}

impl<E: Clock + Spawner + Rng> FuzzingActor<E> {
    fn new(
        context: E,
        crypto: PrivateKey,
        supervisor: Supervisor<PublicKey, Sha256Digest>,
        namespace: Vec<u8>,
        input: FuzzInput,
    ) -> Self {
        Self {
            context,
            crypto,
            supervisor,
            namespace,
            rng: StdRng::seed_from_u64(input.seed),
            mutations: input.mutations,
            view_offsets: input.views,
            parent_offsets: input.parents,
            malformed_bytes: input.malformed_bytes,
            mutation_idx: 0,
        }
    }

    fn get_next_mutation(&mut self) -> Option<&FuzzStep> {
        if self.mutation_idx < self.mutations.len() {
            let mutation = &self.mutations[self.mutation_idx];
            self.mutation_idx += 1;
            Some(mutation)
        } else {
            None
        }
    }

    fn get_view(&mut self) -> u64 {
        self.view_offsets
            .get(self.mutation_idx % self.view_offsets.len().max(1))
            .copied()
            .unwrap_or(0)
    }

    fn get_parent(&mut self) -> u64 {
        self.parent_offsets
            .get(self.mutation_idx % self.parent_offsets.len().max(1))
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
            .unwrap_or_else(|| vec![0u8; 256])
    }

    pub fn start(mut self, voter_network: (impl Sender, impl Receiver)) -> Handle<()> {
        self.context.spawn_ref()(self.run(voter_network))
    }

    async fn run(mut self, voter_network: (impl Sender, impl Receiver)) {
        let (mut sender, mut receiver) = voter_network;
        let mut steps = 0;

        while steps < MAX_STEPS {
            match receiver.recv().await {
                Ok((s, msg)) => {
                    // Received a message - mutate and resend it
                    self.handle_received_message(&mut sender, s, msg.to_vec()).await;
                    steps += 1;
                }
                Err(_) => {
                    // No message received or error - send a random message instead
                    if let Some(mutation) = self.get_next_mutation().cloned() {
                        self.send_random_message(&mut sender, &mutation).await;
                        steps += 1;
                    } else {
                        // No more mutations, wait a bit then break
                        self.context.sleep(Duration::from_millis(1)).await;
                        break;
                    }
                }
            }
            
            // Also randomly send additional messages
            if self.rng.gen_bool(0.2) && steps < MAX_STEPS {
                if let Some(mutation) = self.get_next_mutation().cloned() {
                    self.send_random_message(&mut sender, &mutation).await;
                    steps += 1;
                }
            }
        }
    }

    async fn handle_received_message(&mut self, sender: &mut impl Sender, _sender_id: impl std::fmt::Debug, msg: Vec<u8>) {
        let msg = match Voter::<
            commonware_cryptography::ed25519::Signature,
            Sha256Digest,
        >::decode_cfg(msg.as_slice(), &usize::MAX) {
            Ok(msg) => msg,
            Err(_) => return,
        };

        let view = msg.view();

        match msg {
            Voter::Notarize(notarize) => {
                if let Some(public_key_index) = self
                    .supervisor
                    .is_participant(view, &self.crypto.public_key())
                {
                    // Mutate the proposal (change payload)
                    let mutated_payload = self.get_payload();
                    let mutated_proposal = Proposal::new(view, notarize.proposal.parent, mutated_payload);
                    
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
                }
            }
            Voter::Finalize(finalize) => {
                if let Some(public_key_index) = self
                    .supervisor
                    .is_participant(view, &self.crypto.public_key())
                {
                    // Mutate the proposal (change payload)
                    let mutated_payload = self.get_payload();
                    let mutated_proposal = Proposal::new(view, finalize.proposal.parent, mutated_payload);
                    
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
                }
            }
            _ => {} // Ignore other message types
        }
    }

    async fn send_random_message(&mut self, sender: &mut impl Sender, mutation: &FuzzStep) {
        match mutation {
            FuzzStep::SendNotarize => {
                let view = self.get_view();
                let parent = self.get_parent();
                let payload = self.get_payload();
                let proposal = Proposal::new(view, parent, payload);

                if let Some(public_key_index) = self
                    .supervisor
                    .is_participant(view, &self.crypto.public_key())
                {
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
            }
            FuzzStep::SendFinalize => {
                let view = self.get_view();
                let parent = self.get_parent();
                let payload = self.get_payload();
                let proposal = Proposal::new(view, parent, payload);

                if let Some(public_key_index) = self
                    .supervisor
                    .is_participant(view, &self.crypto.public_key())
                {
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
            }
            FuzzStep::SendNullify => {
                let view = self.get_view();

                if let Some(public_key_index) = self
                    .supervisor
                    .is_participant(view, &self.crypto.public_key())
                {
                    let msg = Nullify::sign(
                        &self.namespace,
                        &mut self.crypto,
                        public_key_index,
                        view,
                    );
                    let encoded_msg = Voter::<
                        commonware_cryptography::ed25519::Signature,
                        Sha256Digest,
                    >::Nullify(msg)
                    .encode()
                    .into();
                    let _ = sender.send(Recipients::All, encoded_msg, true).await;
                }
            }
            FuzzStep::SendMalformedBytes => {
                let malformed_bytes = self.get_malformed_bytes();
                let _ = sender
                    .send(Recipients::All, malformed_bytes.into(), true)
                    .await;
            }
            _ => {} // Ignore unimplemented mutations
        }
    }
}

fn clamp_link_params(input: &FuzzInput) -> (f64, f64, f64) {
    // Clamp link values to specified ranges, handling NaN and infinite values
    let latency = if input.link_latency.is_finite() {
        0.1 + (input.link_latency.abs() % 4.9) // Range: 0.1 - 5.0
    } else {
        0.1
    };

    let jitter = if input.link_jitter.is_finite() {
        0.1 + (input.link_jitter.abs() % 2.9) // Range: 0.1 - 3.0
    } else {
        0.2
    };

    let success_rate = if input.link_success_rate.is_finite() {
        0.1 + (input.link_success_rate.abs() % 0.9) // Range: 0.1 - 1.0
    } else {
        1.0
    };

    (latency, jitter, success_rate)
}

fn fuzzer(input: FuzzInput) {
    // Create context
    let n = 4;
    let namespace = b"consensus_fuzz".to_vec();
    let cfg = deterministic::Config::new()
        .with_seed(input.seed)
        .with_timeout(Some(Duration::from_secs(2))); // Reduced timeout for faster cleanup
    let executor = deterministic::Runner::new(cfg);
    executor.start(|context| async move {
        // Create simulated network
        let (network, mut oracle) = Network::new(
            context.with_label("network"),
            NetworkConfig {
                max_size: 1024 * 1024,
            },
        );

        // Start network
        network.start();

        // Register participants
        let mut schemes = Vec::new();
        let mut validators = Vec::new();
        for i in 0..n {
            let scheme = PrivateKey::from_seed(i as u64);
            let pk = scheme.public_key();
            schemes.push(scheme);
            validators.push(pk);
        }
        validators.sort();
        schemes.sort_by_key(|s| s.public_key());
        let view_validators = BTreeMap::from_iter(vec![(0, validators.clone())]);
        let mut registrations = register_validators(&mut oracle, &validators).await;

        // Link all validators with clamped parameters
        let (latency, jitter, success_rate) = clamp_link_params(&input);
        let link = Link {
            latency,
            jitter,
            success_rate,
        };
        link_validators(&mut oracle, &validators, Action::Link(link), None).await;

        // Create engines
        let relay = Arc::new(mocks::relay::Relay::new());
        let mut supervisors = Vec::new();

        // Start fuzzing actor (first validator)
        let first_scheme = schemes.remove(0);
        let first_validator = first_scheme.public_key();
        let first_context = context.with_label(&format!("validator-{first_validator}"));
        let first_supervisor_config = mocks::supervisor::Config {
            namespace: namespace.clone(),
            participants: view_validators.clone(),
        };
        let first_supervisor = Supervisor::<PublicKey, Sha256Digest>::new(first_supervisor_config);

        let (voter, _) = registrations
            .remove(&first_validator)
            .expect("validator should be registered");
        let actor = FuzzingActor::new(
            first_context.with_label("fuzzing_actor"),
            first_scheme,
            first_supervisor,
            namespace.clone(),
            input,
        );
        actor.start(voter);

        // Start regular consensus engines for the remaining validators
        for scheme in schemes.into_iter() {
            let context = context.with_label(&format!("validator-{}", scheme.public_key()));
            let validator = scheme.public_key();
            let supervisor_config = mocks::supervisor::Config {
                namespace: namespace.clone(),
                participants: view_validators.clone(),
            };
            let supervisor = Supervisor::<PublicKey, Sha256Digest>::new(supervisor_config);

            supervisors.push(supervisor.clone());
            let application_cfg = mocks::application::Config {
                hasher: Sha256::default(),
                relay: relay.clone(),
                participant: validator.clone(),
                propose_latency: (0.01, 0.3),
                verify_latency: (0.01, 0.3),
            };
            let (actor, application) = mocks::application::Application::new(
                context.with_label("application"),
                application_cfg,
            );
            actor.start();

            let cfg = Config {
                crypto: scheme,
                automaton: application.clone(),
                relay: application.clone(),
                reporter: supervisor.clone(),
                partition: validator.to_string(),
                compression: Some(3),
                supervisor,
                mailbox_size: 1024,
                namespace: namespace.clone(),
                leader_timeout: Duration::from_secs(1),
                notarization_timeout: Duration::from_secs(2),
                nullify_retry: Duration::from_secs(3),
                fetch_timeout: Duration::from_secs(1),
                activity_timeout: 5,
                skip_timeout: 3,
                max_fetch_count: 1,
                max_participants: n as usize,
                fetch_rate_per_peer: Quota::per_second(NZU32!(1)),
                fetch_concurrent: 1,
                replay_buffer: 1024 * 1024,
                write_buffer: 1024 * 1024,
            };
            let (voter, resolver) = registrations
                .remove(&validator)
                .expect("validator should be registered");
            let engine = Engine::new(context.with_label("engine"), cfg);
            engine.start(voter, resolver);
        }

        context.sleep(Duration::from_secs(1)).await;

        // Explicit cleanup to prevent memory leaks
        drop(supervisors);
        drop(relay);
        drop(registrations);
        drop(oracle);
    });
}

fuzz_target!(|input: FuzzInput| {
    fuzzer(input);
});
