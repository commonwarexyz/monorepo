//! Byzantine participant that sends conflicting notarize/finalize messages.

use crate::{
    threshold_simplex::types::{Finalize, Notarize, Proposal, Voter},
    types::View,
    ThresholdSupervisor, Viewable,
};
use commonware_codec::{DecodeExt, Encode};
use commonware_cryptography::{
    bls12381::primitives::{group, variant::Variant},
    Digest, Hasher,
};
use commonware_p2p::{Receiver, Recipients, Sender};
use commonware_runtime::{Handle, Spawner};
use rand::{CryptoRng, Rng};
use std::marker::PhantomData;
use tracing::debug;

pub struct Config<S: ThresholdSupervisor<Index = View, Share = group::Share>> {
    pub supervisor: S,
    pub namespace: Vec<u8>,
}

pub struct Conflicter<
    E: Rng + CryptoRng + Send + 'static,
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
        E: Rng + CryptoRng + Send + 'static,
        V: Variant,
        H: Hasher,
        S: ThresholdSupervisor<Seed = V::Signature, Index = View, Share = group::Share>,
    > Conflicter<E, V, H, S>
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

    pub fn start(
        self,
        spawner: impl Spawner,
        pending_network: (impl Sender, impl Receiver),
    ) -> Handle<()> {
        spawner.spawn(|_| self.run(pending_network))
    }

    async fn run(mut self, pending_network: (impl Sender, impl Receiver)) {
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
                    // Notarize random digest
                    let view = notarize.view();
                    let share = self.supervisor.share(view).unwrap();
                    let payload = H::Digest::random(&mut self.context);
                    let proposal =
                        Proposal::new(notarize.proposal.round, notarize.proposal.parent, payload);
                    let n = Notarize::<V, _>::sign(&self.namespace, share, proposal);
                    let msg = Voter::Notarize(n).encode().into();
                    sender.send(Recipients::All, msg, true).await.unwrap();

                    // Notarize received digest
                    let n = Notarize::<V, _>::sign(&self.namespace, share, notarize.proposal);
                    let msg = Voter::Notarize(n).encode().into();
                    sender.send(Recipients::All, msg, true).await.unwrap();
                }
                Voter::Finalize(finalize) => {
                    // Finalize random digest
                    let view = finalize.view();
                    let share = self.supervisor.share(view).unwrap();
                    let payload = H::Digest::random(&mut self.context);
                    let proposal =
                        Proposal::new(finalize.proposal.round, finalize.proposal.parent, payload);
                    let f = Finalize::<V, _>::sign(&self.namespace, share, proposal);
                    let msg = Voter::Finalize(f).encode().into();
                    sender.send(Recipients::All, msg, true).await.unwrap();

                    // Finalize provided digest
                    let f = Finalize::<V, _>::sign(&self.namespace, share, finalize.proposal);
                    let msg = Voter::Finalize(f).encode().into();
                    sender.send(Recipients::All, msg, true).await.unwrap();
                }
                _ => continue,
            }
        }
    }
}
