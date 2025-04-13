//! Byzantine participant that sends nullify and finalize messages for the same view.

use crate::{
    threshold_simplex::types::{
        finalize_namespace, nullify_namespace, seed_namespace, view_message, Finalize, Nullify,
        View, Viewable, Voter,
    },
    ThresholdSupervisor,
};
use commonware_codec::Codec;
use commonware_cryptography::{
    bls12381::primitives::{group, ops},
    Hasher,
};
use commonware_p2p::{Receiver, Recipients, Sender};
use commonware_runtime::{Handle, Spawner};
use std::marker::PhantomData;
use tracing::debug;

pub struct Config<
    S: ThresholdSupervisor<Seed = group::Signature, Index = View, Share = group::Share>,
> {
    pub supervisor: S,
    pub namespace: Vec<u8>,
}

pub struct Nuller<
    E: Spawner,
    H: Hasher,
    S: ThresholdSupervisor<Seed = group::Signature, Index = View, Share = group::Share>,
> {
    context: E,
    supervisor: S,
    _hasher: PhantomData<H>,

    seed_namespace: Vec<u8>,
    nullify_namespace: Vec<u8>,
    finalize_namespace: Vec<u8>,
}

impl<
        E: Spawner,
        H: Hasher,
        S: ThresholdSupervisor<Seed = group::Signature, Index = View, Share = group::Share>,
    > Nuller<E, H, S>
{
    pub fn new(context: E, cfg: Config<S>) -> Self {
        Self {
            context,
            supervisor: cfg.supervisor,
            _hasher: PhantomData,

            seed_namespace: seed_namespace(&cfg.namespace),
            nullify_namespace: nullify_namespace(&cfg.namespace),
            finalize_namespace: finalize_namespace(&cfg.namespace),
        }
    }

    pub fn start(mut self, voter_network: (impl Sender, impl Receiver)) -> Handle<()> {
        self.context.spawn_ref()(self.run(voter_network))
    }

    async fn run(self, voter_network: (impl Sender, impl Receiver)) {
        let (mut sender, mut receiver) = voter_network;
        while let Ok((s, msg)) = receiver.recv().await {
            // Parse message
            let msg = match Voter::<H::Digest>::decode(msg) {
                Ok(msg) => msg,
                Err(err) => {
                    debug!(?err, sender = ?s, "failed to decode message");
                    continue;
                }
            };

            // Process message
            match msg {
                Voter::Notarize(notarize) => {
                    // Nullify
                    let view = notarize.view();
                    let share = self.supervisor.share(view).unwrap();
                    let message = view_message(view);
                    let view_signature =
                        ops::partial_sign_message(share, Some(&self.nullify_namespace), &message);
                    let seed_signature =
                        ops::partial_sign_message(share, Some(&self.seed_namespace), &message);
                    let n = Nullify::new(view, view_signature, seed_signature);
                    let msg = Voter::<H::Digest>::Nullify(n).encode().into();
                    sender.send(Recipients::All, msg, true).await.unwrap();

                    // Finalize digest
                    let proposal = notarize.proposal;
                    let message = proposal.encode();
                    let proposal_signature =
                        ops::partial_sign_message(share, Some(&self.finalize_namespace), &message);
                    let f = Finalize::new(proposal, proposal_signature);
                    let msg = Voter::Finalize(f).encode().into();
                    sender.send(Recipients::All, msg, true).await.unwrap();
                }
                _ => continue,
            }
        }
    }
}
