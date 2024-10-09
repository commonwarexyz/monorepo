use super::{orchestrator, voter::Voter};
use crate::Application;
use commonware_cryptography::{PublicKey, Scheme};
use commonware_p2p::{Receiver, Sender};
use commonware_runtime::{select, Clock, Spawner};
use rand::Rng;
use tracing::debug;

pub struct Engine<E: Clock + Rng + Spawner, C: Scheme, A: Application> {
    runtime: E,
    crypto: C,

    orchestrator: orchestrator::Orchestrator<E, A>,
    voter: Voter<E, C>,
}

impl<E: Clock + Rng + Spawner, C: Scheme, A: Application> Engine<E, C, A> {
    pub fn new(runtime: E, crypto: C, application: A, mut validators: Vec<PublicKey>) -> Self {
        // Sort the validators
        validators.sort();

        // Create orchestrator
        let (orchestrator, mailbox) =
            orchestrator::Orchestrator::new(runtime.clone(), application, validators.clone());

        // Create voter
        let voter = Voter::new(runtime.clone(), crypto.clone(), mailbox, validators);

        // Return the engine
        Self {
            runtime: runtime.clone(),
            crypto: crypto.clone(),

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
            _orchestrator = orchestrator => {
                debug!("orchestrator finished");
            },
            _voter = voter => {
                debug!("voter finished");
            },
        }
    }
}
