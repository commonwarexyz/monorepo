//! Byzantine participant that sends nullify and finalize messages for the same view.

use crate::{
    threshold_simplex::types::{Finalize, Nullify, Voter},
    types::View,
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

pub struct Nuller<
    V: Variant,
    H: Hasher,
    S: ThresholdSupervisor<Seed = V::Signature, Index = View, Share = group::Share>,
> {
    supervisor: S,
    namespace: Vec<u8>,
    _hasher: PhantomData<H>,
    _variant: PhantomData<V>,
}

impl<
        V: Variant,
        H: Hasher,
        S: ThresholdSupervisor<Seed = V::Signature, Index = View, Share = group::Share>,
    > Nuller<V, H, S>
{
    pub fn new(cfg: Config<S>) -> Self {
        Self {
            supervisor: cfg.supervisor,
            namespace: cfg.namespace,
            _hasher: PhantomData,
            _variant: PhantomData,
        }
    }

    pub fn start(
        self,
        spawner: impl Spawner,
        pending_network: (impl Sender, impl Receiver),
    ) -> Handle<()> {
        spawner.spawn(|_| self.run(pending_network))
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
                    // Nullify
                    let view = notarize.view();
                    let share = self.supervisor.share(view).unwrap();
                    let n = Nullify::sign(&self.namespace, share, notarize.proposal.round);
                    let msg = Voter::<V, H::Digest>::Nullify(n).encode().into();
                    sender.send(Recipients::All, msg, true).await.unwrap();

                    // Finalize digest
                    let proposal = notarize.proposal;
                    let f = Finalize::<V, _>::sign(&self.namespace, share, proposal);
                    let msg = Voter::Finalize(f).encode().into();
                    sender.send(Recipients::All, msg, true).await.unwrap();
                }
                _ => continue,
            }
        }
    }
}
