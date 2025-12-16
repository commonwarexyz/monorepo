//! Byzantine participant that sends different proposals to different nodes.

use super::relay::Relay;
use crate::{
    simplex::{
        scheme::Scheme,
        select_leader,
        types::{Certificate, Notarize, Proposal, Vote},
    },
    types::{Epoch, Round, View},
};
use commonware_codec::{Decode, Encode};
use commonware_cryptography::{certificate, Hasher};
use commonware_p2p::{Receiver, Recipients, Sender};
use commonware_runtime::{spawn_cell, Clock, ContextCell, Handle, Spawner};
use rand::{seq::IteratorRandom, Rng};
use std::{collections::HashSet, sync::Arc};

pub struct Config<S: certificate::Scheme, H: Hasher> {
    pub scheme: S,
    pub namespace: Vec<u8>,
    pub epoch: Epoch,
    pub relay: Arc<Relay<H::Digest, S::PublicKey>>,
    pub hasher: H,
}

pub struct Equivocator<E: Clock + Rng + Spawner, S: Scheme<H::Digest>, H: Hasher> {
    context: ContextCell<E>,
    scheme: S,
    namespace: Vec<u8>,
    epoch: Epoch,
    relay: Arc<Relay<H::Digest, S::PublicKey>>,
    hasher: H,
    sent: HashSet<View>,
}

impl<E: Clock + Rng + Spawner, S: Scheme<H::Digest>, H: Hasher> Equivocator<E, S, H> {
    pub fn new(context: E, cfg: Config<S, H>) -> Self {
        Self {
            context: ContextCell::new(context),
            scheme: cfg.scheme,
            namespace: cfg.namespace,
            epoch: cfg.epoch,
            relay: cfg.relay,
            hasher: cfg.hasher,
            sent: HashSet::new(),
        }
    }

    pub fn start(
        mut self,
        vote_network: (impl Sender<PublicKey = S::PublicKey>, impl Receiver),
        certificate_network: (impl Sender, impl Receiver),
    ) -> Handle<()> {
        spawn_cell!(
            self.context,
            self.run(vote_network, certificate_network).await
        )
    }

    async fn run(
        mut self,
        vote_network: (impl Sender<PublicKey = S::PublicKey>, impl Receiver),
        certificate_network: (impl Sender, impl Receiver),
    ) {
        let (mut vote_sender, _) = vote_network;
        let (_, mut certificate_receiver) = certificate_network;

        loop {
            // Listen to recovered certificates
            let (_, certificate) = certificate_receiver.recv().await.unwrap();

            // Parse certificate
            let (view, parent, seed) = match Certificate::<S, H::Digest>::decode_cfg(
                certificate,
                &self.scheme.certificate_codec_config(),
            )
            .unwrap()
            {
                Certificate::Notarization(notarization) => (
                    notarization.proposal.round.view(),
                    notarization.proposal.payload,
                    self.scheme
                        .seed(notarization.proposal.round, &notarization.certificate),
                ),
                Certificate::Finalization(finalization) => (
                    finalization.proposal.round.view(),
                    finalization.proposal.payload,
                    self.scheme
                        .seed(finalization.proposal.round, &finalization.certificate),
                ),
                _ => continue, // we don't build on nullifications to avoid tracking complexity
            };

            // Check if we have already sent a proposal for this view
            if !self.sent.insert(view) {
                continue;
            }

            // Notarization advances us to next view
            let next_view = view.next();
            let next_round = Round::new(self.epoch, next_view);

            // Check if we are the leader for the next view, otherwise move on
            let (_, leader) =
                select_leader::<S>(self.scheme.participants().as_ref(), next_round, seed);
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
            let payload_a = (next_round, parent, self.context.gen::<u64>()).encode();
            let payload_b = (next_round, parent, self.context.gen::<u64>()).encode();

            // Compute digests
            self.hasher.update(&payload_a);
            let digest_a = self.hasher.finalize();
            self.hasher.update(&payload_b);
            let digest_b = self.hasher.finalize();

            let proposal_a = Proposal::new(next_round, view, digest_a);
            let proposal_b = Proposal::new(next_round, view, digest_b);

            // Broadcast payloads via relay so nodes can verify
            let me = &self.scheme.participants()[self.scheme.me().unwrap() as usize];
            self.relay.broadcast(me, (digest_a, payload_a.into())).await;
            self.relay.broadcast(me, (digest_b, payload_b.into())).await;

            // Notarize proposal A and send it to victim only
            let notarize_a = Notarize::<S, _>::sign(&self.scheme, &self.namespace, proposal_a)
                .expect("sign failed");
            vote_sender
                .send(
                    Recipients::One(victim.clone()),
                    Vote::Notarize(notarize_a).encode().into(),
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
            vote_sender
                .send(
                    Recipients::Some(non_victims),
                    Vote::Notarize(notarize_b).encode().into(),
                    true,
                )
                .await
                .expect("send failed");
        }
    }
}
