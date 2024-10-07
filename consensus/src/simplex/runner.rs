use super::{engine::Engine, orchestrator::Orchestrator};
use crate::Application;
use commonware_cryptography::{PublicKey, Scheme};
use commonware_p2p::{Receiver, Sender};
use commonware_runtime::{select, Clock, Spawner};
use rand::Rng;
use tracing::debug;

pub struct Runner<E: Spawner + Clock + Rng> {
    runtime: E,

    validators: Vec<PublicKey>,
}

impl<E: Spawner + Clock + Rng> Runner<E> {
    pub fn new(runtime: E, mut validators: Vec<PublicKey>) -> Self {
        validators.sort();
        Self {
            runtime,
            validators,
        }
    }

    pub async fn run(
        &mut self,
        crypto: impl Scheme,
        application: impl Application,
        orchestrator_network: (impl Sender, impl Receiver),
        voter_network: (impl Sender, impl Receiver),
    ) {
        let (orchestrator_sender, orchestrator_receiver) = orchestrator_network;
        let (orchestrator, mailbox) =
            Orchestrator::new(self.runtime.clone(), application, self.validators.clone());
        let orchestrator = self.runtime.spawn("orchestrator", async move {
            orchestrator
                .run(orchestrator_sender, orchestrator_receiver)
                .await;
        });

        let (voter_sender, voter_receiver) = voter_network;
        let engine = Engine::new(
            self.runtime.clone(),
            crypto,
            mailbox,
            self.validators.clone(),
        );
        let engine = self.runtime.spawn("engine", async move {
            engine.run(voter_sender, voter_receiver).await;
        });

        // Wait for the orchestrator and engine to finish
        select! {
            _orchestrator = orchestrator => {
                debug!("Orchestrator finished");
            },
            _engine = engine => {
                debug!("Engine finished");
            },
        }
    }
}
