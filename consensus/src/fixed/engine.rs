use super::{
    actors::{
        orchestrator::{self, Mailbox},
        voter::{self, Voter, VoterMailbox},
    },
    config::Config,
};
use crate::{Application, Hasher};
use commonware_cryptography::Scheme;
use commonware_macros::select;
use commonware_p2p::{Receiver, Sender};
use commonware_runtime::{Clock, Spawner};
use rand::Rng;
use tracing::debug;

pub struct Engine<E: Clock + Rng + Spawner, C: Scheme, H: Hasher, A: Application> {
    runtime: E,

    orchestrator: orchestrator::Orchestrator<E, H, A>,
    orchestrator_mailbox: Mailbox,

    voter: Voter<E, C, H, A>,
    voter_mailbox: VoterMailbox,
}

impl<E: Clock + Rng + Spawner, C: Scheme, H: Hasher, A: Application> Engine<E, C, H, A> {
    pub fn new(runtime: E, mut cfg: Config<C, H, A>) -> Self {
        // Sort the validators at each view
        if cfg.validators.is_empty() {
            panic!("no validators specified");
        }
        for (_, validators) in cfg.validators.iter_mut() {
            if validators.is_empty() {
                panic!("no validators specified");
            }
            validators.sort();
        }

        // Create orchestrator
        let (orchestrator, orchestrator_mailbox) = orchestrator::Orchestrator::new(
            runtime.clone(),
            cfg.hasher.clone(),
            cfg.application.clone(),
            cfg.fetch_timeout,
            cfg.max_fetch_count,
            cfg.max_fetch_size,
        );

        // Create voter
        let (voter, voter_mailbox) = Voter::new(
            runtime.clone(),
            cfg.crypto,
            cfg.hasher,
            cfg.application,
            voter::Config {
                registry: cfg.registry,
                namespace: cfg.namespace,
                leader_timeout: cfg.leader_timeout,
                notarization_timeout: cfg.notarization_timeout,
                null_vote_retry: cfg.null_vote_retry,
            },
        );

        // Return the engine
        Self {
            runtime,

            orchestrator,
            orchestrator_mailbox,

            voter,
            voter_mailbox,
        }
    }

    pub async fn run(
        mut self,
        orchestrator_network: (impl Sender, impl Receiver),
        voter_network: (impl Sender, impl Receiver),
    ) {
        // Start the orchestrator
        let (orchestrator_sender, orchestrator_receiver) = orchestrator_network;
        let orchestrator = self.runtime.spawn("orchestrator", async move {
            self.orchestrator
                .run(
                    &mut self.voter_mailbox,
                    orchestrator_sender,
                    orchestrator_receiver,
                )
                .await;
        });

        // Start the voter
        let (voter_sender, voter_receiver) = voter_network;
        let voter = self.runtime.spawn("voter", async move {
            self.voter
                .run(&mut self.orchestrator_mailbox, voter_sender, voter_receiver)
                .await;
        });

        // Wait for the orchestrator or voter to finish
        select! {
            _ = orchestrator => {
                debug!("orchestrator finished");
            },
            _ = voter => {
                debug!("voter finished");
            },
        }
    }
}
