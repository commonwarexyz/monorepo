use crate::Application;

use super::{actors::signer, config::Config, Context};
use bytes::Bytes;
use commonware_consensus::{threshold_simplex::View, ThresholdSupervisor};
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
    A: Application<Context = Context, Proof = Bytes>,
    S: ThresholdSupervisor<
        Seed = group::Signature,
        Index = View,
        Share = group::Share,
        Identity = poly::Public,
    >,
> {
    runtime: E,

    signer: signer::Actor<E, C, H, A, S>,
    signer_mailbox: signer::Mailbox,
}

impl<
        E: Clock + Rng + CryptoRng + Spawner,
        C: Scheme,
        H: Hasher,
        A: Application<Context = Context, Proof = Bytes>,
        S: ThresholdSupervisor<
            Seed = group::Signature,
            Index = View,
            Share = group::Share,
            Identity = poly::Public,
        >,
    > Engine<E, C, H, A, S>
{
    pub fn new(runtime: E, cfg: Config<C, H, A, S>) -> Self {
        cfg.assert();
        let (signer, signer_mailbox) = signer::Actor::new(
            runtime.clone(),
            signer::Config {
                crypto: cfg.crypto,
                hasher: cfg.hasher,
                app: cfg.app,
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
    ) {
        self.runtime.spawn("signer", async move {
            self.signer.run(car_network, ack_network).await;
        });
    }
}
