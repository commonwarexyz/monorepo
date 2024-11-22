use super::{actors::voter, config::Config, Context, View};
use crate::{Automaton, Supervisor};
use commonware_cryptography::{Hasher, Scheme};
use commonware_macros::select;
use commonware_p2p::{Receiver, Sender};
use commonware_runtime::{Clock, Spawner};
use governor::clock::Clock as GClock;
use rand::{CryptoRng, Rng};
use tracing::debug;

pub struct Engine<
    E: Clock + GClock + Rng + CryptoRng + Spawner,
    C: Scheme,
    H: Hasher,
    A: Automaton<Context = Context>,
    S: Supervisor<Seed = (), Index = View>,
> {
    runtime: E,

    voter: voter::Actor<E, C, H, A, S>,
    voter_mailbox: voter::Mailbox,
    // backfiller: backfiller::Actor<E, C, H, A>,
    // backfiller_mailbox: backfiller::Mailbox,
}

impl<
        E: Clock + GClock + Rng + CryptoRng + Spawner,
        C: Scheme,
        H: Hasher,
        A: Automaton<Context = Context>,
        S: Supervisor<Seed = (), Index = View>,
    > Engine<E, C, H, A, S>
{
    pub fn new(runtime: E, mut cfg: Config<C, H, A, S>) -> Self {
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

        // Create voter
        let (voter, voter_mailbox) = voter::Actor::new(
            runtime.clone(),
            voter::Config {
                crypto: cfg.crypto.clone(),
                hasher: cfg.hasher.clone(),
                application: cfg.application,
                supervisor: cfg.supervisor.clone(),
                registry: cfg.registry,
                namespace: cfg.namespace.clone(),
                leader_timeout: cfg.leader_timeout,
                notarization_timeout: cfg.notarization_timeout,
                nullify_retry: cfg.nullify_retry,
                activity_timeout: cfg.activity_timeout,
            },
        );

        // // Create backfiller
        // let (backfiller, backfiller_mailbox) = backfiller::Actor::new(
        //     runtime.clone(),
        //     backfiller::Config {
        //         crypto: cfg.crypto,
        //         hasher: cfg.hasher,
        //         application: cfg.application,
        //         namespace: cfg.namespace,
        //         fetch_timeout: cfg.fetch_timeout,
        //         max_fetch_count: cfg.max_fetch_count,
        //         max_fetch_size: cfg.max_fetch_size,
        //         fetch_rate_per_peer: cfg.fetch_rate_per_peer,
        //     },
        // );

        // Return the engine
        Self {
            runtime,

            voter,
            voter_mailbox,
            // backfiller,
            // backfiller_mailbox,
        }
    }

    pub async fn run(
        self,
        voter_network: (impl Sender, impl Receiver),
        _backfiller_network: (impl Sender, impl Receiver),
    ) {
        // Start the voter
        let (voter_sender, voter_receiver) = voter_network;
        let mut voter = self.runtime.spawn("voter", async move {
            self.voter.run(voter_sender, voter_receiver).await;
        });

        // // Start the backfiller
        // let (backfiller_sender, backfiller_receiver) = backfiller_network;
        // let mut backfiller = self.runtime.spawn("backfiller", async move {
        //     self.backfiller
        //         .run(self.voter_mailbox, backfiller_sender, backfiller_receiver)
        //         .await;
        // });

        // Wait for the resolver or voter to finish
        select! {
            _ = &mut voter => {
                debug!("voter finished");
                // backfiller.abort();
            },
            // _ = &mut backfiller => {
            //     debug!("backfiller finished");
            //     voter.abort();
            // },
        }
    }
}
