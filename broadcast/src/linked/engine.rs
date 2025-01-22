use super::{actors::signer, config::Config, View};
use commonware_consensus::ThresholdSupervisor;
use commonware_cryptography::{
    bls12381::primitives::{group, poly},
    Hasher, Scheme,
};
use commonware_p2p::{Receiver, Sender};
use commonware_runtime::{Clock, Spawner};
use rand::{CryptoRng, Rng};

/// Instance of `threshold-simplex` consensus engine.
pub struct Engine<
    E: Clock + Rng + CryptoRng + Spawner + Send + Sync,
    C: Scheme,
    H: Hasher,
    S: ThresholdSupervisor<
        Seed = group::Signature,
        Index = View,
        Share = group::Share,
        Identity = poly::Public,
    >,
> {
    runtime: E,

    signer: signer::Actor<E, C, H, S>,
    signer_mailbox: signer::Mailbox,
}

impl<
        E: Clock + Rng + CryptoRng + Spawner,
        C: Scheme,
        H: Hasher,
        S: ThresholdSupervisor<
            Seed = group::Signature,
            Index = View,
            Share = group::Share,
            Identity = poly::Public,
        >,
    > Engine<E, C, H, S>
{
    pub fn new(runtime: E, cfg: Config<C, H, S>) -> Self {
        cfg.assert();
        let (signer, signer_mailbox) = signer::Actor::new(
            runtime.clone(),
            signer::Config {
                crypto: cfg.crypto,
                hasher: cfg.hasher,
                supervisor: cfg.supervisor,
                mailbox_size: cfg.mailbox_size,
                namespace: cfg.namespace,
            },
        );
        Self {
            runtime,

            signer,
            signer_mailbox,
        }
    }

    pub async fn run(
        self,
        car_network: (impl Sender, impl Receiver),
        ack_network: (impl Sender, impl Receiver),
        proof_network: (impl Sender, impl Receiver),
        backfill_network: (impl Sender, impl Receiver),
    ) {
        self.runtime.spawn("signer", async move {
            self.signer
                .run(car_network, ack_network, proof_network, backfill_network)
                .await;
        });
    }
}
