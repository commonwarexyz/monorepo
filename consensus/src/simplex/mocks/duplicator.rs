//! Byzantine participant that sends different proposals to different nodes.

use super::relay::Relay;
use crate::{
    simplex::{
        select_leader,
        signing_scheme::Scheme,
        types::{Notarize, Proposal, Voter},
    },
    types::Round,
};
use commonware_codec::{Decode, Encode};
use commonware_cryptography::Hasher;
use commonware_p2p::{Receiver, Recipients, Sender};
use commonware_runtime::{spawn_cell, Clock, ContextCell, Handle, Spawner};
use rand::{seq::IteratorRandom, CryptoRng, Rng};
use std::sync::Arc;

pub struct Config<S: Scheme, H: Hasher> {
    pub scheme: S,
    pub namespace: Vec<u8>,
    pub epoch: u64,
    pub relay: Arc<Relay<H::Digest, S::PublicKey>>,
    pub hasher: H,
}

pub struct Duplicator<E: Clock + Rng + CryptoRng + Spawner, S: Scheme, H: Hasher> {
    context: ContextCell<E>,
    scheme: S,
    namespace: Vec<u8>,
    epoch: u64,
    relay: Arc<Relay<H::Digest, S::PublicKey>>,
    hasher: H,
}

impl<E: Clock + Rng + CryptoRng + Spawner, S: Scheme, H: Hasher> Duplicator<E, S, H> {
    pub fn new(context: E, cfg: Config<S, H>) -> Self {
        Self {
            context: ContextCell::new(context),
            scheme: cfg.scheme,
            namespace: cfg.namespace,
            epoch: cfg.epoch,
            relay: cfg.relay,
            hasher: cfg.hasher,
        }
    }

    pub fn start(
        mut self,
        pending_network: (impl Sender<PublicKey = S::PublicKey>, impl Receiver),
        recovered_network: (impl Sender, impl Receiver),
    ) -> Handle<()> {
        spawn_cell!(
            self.context,
            self.run(pending_network, recovered_network).await
        )
    }

    async fn run(
        mut self,
        pending_network: (impl Sender<PublicKey = S::PublicKey>, impl Receiver),
        recovered_network: (impl Sender, impl Receiver),
    ) {
        let (mut pending_sender, _) = pending_network;
        let (_, mut recovered_receiver) = recovered_network;

        loop {
            // Listen to recovered certificates
            let (_, certificate) = recovered_receiver.recv().await.unwrap();

            // Parse notarization
            let Voter::Notarization(notarization) = Voter::<S, H::Digest>::decode_cfg(
                certificate,
                &self.scheme.certificate_codec_config(),
            )
            .unwrap() else {
                continue;
            };

            // Notarization advances us to next view
            let notarized_view = notarization.proposal.round.view();
            let next_view = notarized_view + 1;
            let next_round = Round::new(self.epoch, next_view);

            // Extract seed from the notarization certificate for leader selection
            let seed = self
                .scheme
                .seed(notarization.proposal.round, &notarization.certificate);

            // Check if we are the leader for the next view, otherwise move on
            let (_, leader) =
                select_leader::<S, _>(self.scheme.participants().as_ref(), next_round, seed);
            if leader != self.scheme.me().unwrap() {
                continue;
            }

            // Pick a random victim (excluding ourselves)
            let (_, victim) = self
                .scheme
                .participants()
                .iter()
                .enumerate()
                .filter(|(index, _)| *index as u32 != self.scheme.me().unwrap())
                .choose(&mut self.context)
                .unwrap();

            // Create two different proposals
            let payload_a = (
                next_round,
                notarization.proposal.payload,
                self.context.gen::<u64>(),
            )
                .encode();
            let payload_b = (
                next_round,
                notarization.proposal.payload,
                self.context.gen::<u64>(),
            )
                .encode();

            // Compute digests
            self.hasher.update(&payload_a);
            let digest_a = self.hasher.finalize();
            self.hasher.update(&payload_b);
            let digest_b = self.hasher.finalize();

            let proposal_a = Proposal::new(next_round, notarized_view, digest_a);
            let proposal_b = Proposal::new(next_round, notarized_view, digest_b);

            // Broadcast payloads via relay so nodes can verify
            let me = &self.scheme.participants()[self.scheme.me().unwrap() as usize];
            self.relay.broadcast(me, (digest_a, payload_a.into())).await;
            self.relay.broadcast(me, (digest_b, payload_b.into())).await;

            // Brief delay to let broadcasts propagate
            self.context
                .sleep(std::time::Duration::from_millis(5))
                .await;

            // Notarize proposal A and send it to victim only
            let notarize_a = Notarize::<S, _>::sign(&self.scheme, &self.namespace, proposal_a)
                .expect("sign failed");
            pending_sender
                .send(
                    Recipients::One(victim.clone()),
                    Voter::Notarize(notarize_a).encode().into(),
                    true,
                )
                .await
                .expect("send failed");

            // Notarize proposal B and send it to everyone else
            let notarize_b = Notarize::<S, _>::sign(&self.scheme, &self.namespace, proposal_b)
                .expect("sign failed");
            let non_victims: Vec<_> = self
                .scheme
                .participants()
                .iter()
                .enumerate()
                .filter(|(index, key)| *index as u32 != self.scheme.me().unwrap() && *key != victim)
                .map(|(_, key)| key.clone())
                .collect();
            pending_sender
                .send(
                    Recipients::Some(non_victims),
                    Voter::Notarize(notarize_b).encode().into(),
                    true,
                )
                .await
                .expect("send failed");
        }
    }
}
