use super::{
    config::Config,
    orchestrator,
    voter::{self, Voter},
};
use crate::Application;
use commonware_cryptography::Scheme;
use commonware_macros::select;
use commonware_p2p::{Receiver, Sender};
use commonware_runtime::{Clock, Spawner};
use rand::Rng;
use tracing::debug;

pub struct Engine<E: Clock + Rng + Spawner, C: Scheme, A: Application> {
    runtime: E,

    orchestrator: orchestrator::Orchestrator<E, A>,
    voter: Voter<E, C>,
}

impl<E: Clock + Rng + Spawner, C: Scheme, A: Application> Engine<E, C, A> {
    pub fn new(runtime: E, mut cfg: Config<C, A>) -> Self {
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
        let (orchestrator, mailbox) = orchestrator::Orchestrator::new(
            runtime.clone(),
            cfg.application,
            cfg.fetch_timeout,
            cfg.max_fetch_count,
            cfg.max_fetch_size,
            cfg.validators.clone(),
        );

        // Create voter
        let voter = Voter::new(
            runtime.clone(),
            cfg.crypto,
            mailbox,
            voter::Config {
                registry: cfg.registry,
                namespace: cfg.namespace,
                leader_timeout: cfg.leader_timeout,
                notarization_timeout: cfg.notarization_timeout,
                null_vote_retry: cfg.null_vote_retry,
                validators: cfg.validators,
            },
        );

        // Return the engine
        Self {
            runtime,

            orchestrator,
            voter,
        }
    }

    pub async fn run(
        self,
        orchestrator_network: (impl Sender, impl Receiver),
        voter_network: (impl Sender, impl Receiver),
    ) {
        // Start the orchestrator
        let (orchestrator_sender, orchestrator_receiver) = orchestrator_network;
        let orchestrator = self.runtime.spawn("orchestrator", async move {
            self.orchestrator
                .run(orchestrator_sender, orchestrator_receiver)
                .await;
        });

        // Start the voter
        let (voter_sender, voter_receiver) = voter_network;
        let voter = self.runtime.spawn("voter", async move {
            self.voter.run(voter_sender, voter_receiver).await;
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
