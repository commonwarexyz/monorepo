//! Byzantine participant that behaves correctly except increments the epoch by 1
//! in all outgoing votes (notarize/finalize/nullify). This helps ensure peers
//! reject messages from an unexpected epoch.

use crate::{
    threshold_simplex::types::{Finalize, Notarize, Nullify, Voter},
    types::{Epoch, View},
    ThresholdSupervisor, Viewable,
};
use commonware_codec::{DecodeExt, Encode};
use commonware_cryptography::{
    bls12381::primitives::{group, variant::Variant},
    Hasher,
};
use commonware_p2p::{Receiver, Recipients, Sender};
use commonware_runtime::{Handle, Spawner};
use std::marker::PhantomData;
use tracing::debug;

pub struct Config<S: ThresholdSupervisor<Index = View, Share = group::Share>> {
    pub supervisor: S,
    pub namespace: Vec<u8>,
}

pub struct Reconfigurer<
    E: Spawner,
    V: Variant,
    H: Hasher,
    S: ThresholdSupervisor<Seed = V::Signature, Index = View, Share = group::Share>,
> {
    context: E,
    supervisor: S,
    namespace: Vec<u8>,
    _hasher: PhantomData<H>,
    _variant: PhantomData<V>,
}

impl<
        E: Spawner,
        V: Variant,
        H: Hasher,
        S: ThresholdSupervisor<Seed = V::Signature, Index = View, Share = group::Share>,
    > Reconfigurer<E, V, H, S>
{
    pub fn new(context: E, cfg: Config<S>) -> Self {
        Self {
            context,
            supervisor: cfg.supervisor,
            namespace: cfg.namespace,
            _hasher: PhantomData,
            _variant: PhantomData,
        }
    }

    pub fn start(mut self, pending_network: (impl Sender, impl Receiver)) -> Handle<()> {
        self.context.spawn_ref()(self.run(pending_network))
    }

    async fn run(self, pending_network: (impl Sender, impl Receiver)) {
        let (mut sender, mut receiver) = pending_network;
        while let Ok((s, msg)) = receiver.recv().await {
            // Parse message
            let msg = match Voter::<V, H::Digest>::decode(msg) {
                Ok(msg) => msg,
                Err(err) => {
                    debug!(?err, sender = ?s, "failed to decode message");
                    continue;
                }
            };

            // Process message
            match msg {
                Voter::Notarize(notarize) => {
                    // Build identical proposal but with epoch incremented by 1
                    let share = self.supervisor.share(notarize.view()).unwrap();
                    let mut proposal = notarize.proposal.clone();
                    let old_round = proposal.round;
                    let new_epoch: Epoch = old_round.epoch().saturating_add(1);
                    proposal.round = (new_epoch, old_round.view()).into();

                    // Sign and broadcast
                    let n = Notarize::<V, _>::sign(&self.namespace, share, proposal);
                    let msg = Voter::Notarize(n).encode().into();
                    sender.send(Recipients::All, msg, true).await.unwrap();
                }
                Voter::Finalize(finalize) => {
                    // Build identical proposal but with epoch incremented by 1
                    let share = self.supervisor.share(finalize.view()).unwrap();
                    let mut proposal = finalize.proposal.clone();
                    let old_round = proposal.round;
                    let new_epoch: Epoch = old_round.epoch().saturating_add(1);
                    proposal.round = (new_epoch, old_round.view()).into();

                    // Sign and broadcast
                    let f = Finalize::<V, _>::sign(&self.namespace, share, proposal);
                    let msg = Voter::Finalize(f).encode().into();
                    sender.send(Recipients::All, msg, true).await.unwrap();
                }
                Voter::Nullify(nullify) => {
                    // Re-sign nullify for the next epoch
                    let share = self.supervisor.share(nullify.view()).unwrap();
                    let old_round = nullify.round;
                    let new_epoch: Epoch = old_round.epoch().saturating_add(1);
                    let new_round = (new_epoch, old_round.view()).into();

                    let n = Nullify::<V>::sign(&self.namespace, share, new_round);
                    let msg = Voter::<V, H::Digest>::Nullify(n).encode().into();
                    sender.send(Recipients::All, msg, true).await.unwrap();
                }
                _ => continue,
            }
        }
    }
}
