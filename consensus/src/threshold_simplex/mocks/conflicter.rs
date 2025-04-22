//! Byzantine participant that sends conflicting notarize/finalize messages.

use crate::{
    threshold_simplex::types::{Finalize, Notarize, Proposal, View, Viewable, Voter},
    ThresholdSupervisor,
};
use commonware_codec::{DecodeExt, Encode};
use commonware_cryptography::{bls12381::primitives::group, Hasher};
use commonware_p2p::{Receiver, Recipients, Sender};
use commonware_runtime::{Clock, Handle, Spawner};
use rand::{CryptoRng, Rng};
use std::marker::PhantomData;
use tracing::debug;

pub struct Config<
    S: ThresholdSupervisor<Seed = group::Signature, Index = View, Share = group::Share>,
> {
    pub supervisor: S,
    pub namespace: Vec<u8>,
}

pub struct Conflicter<
    E: Clock + Rng + CryptoRng + Spawner,
    H: Hasher,
    S: ThresholdSupervisor<Seed = group::Signature, Index = View, Share = group::Share>,
> {
    context: E,
    supervisor: S,

    namespace: Vec<u8>,

    _hasher: PhantomData<H>,
}

impl<
        E: Clock + Rng + CryptoRng + Spawner,
        H: Hasher,
        S: ThresholdSupervisor<Seed = group::Signature, Index = View, Share = group::Share>,
    > Conflicter<E, H, S>
{
    pub fn new(context: E, cfg: Config<S>) -> Self {
        Self {
            context,
            supervisor: cfg.supervisor,

            namespace: cfg.namespace,

            _hasher: PhantomData,
        }
    }

    pub fn start(mut self, voter_network: (impl Sender, impl Receiver)) -> Handle<()> {
        self.context.spawn_ref()(self.run(voter_network))
    }

    async fn run(mut self, voter_network: (impl Sender, impl Receiver)) {
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
                    // Notarize random digest
                    let view = notarize.view();
                    let share = self.supervisor.share(view).unwrap();
                    let payload = H::random(&mut self.context);
                    let proposal = Proposal::new(view, notarize.proposal.parent, payload);
                    let n = Notarize::sign(&self.namespace, share, proposal);
                    let msg = Voter::Notarize(n).encode().into();
                    sender.send(Recipients::All, msg, true).await.unwrap();

                    // Notarize received digest
                    let n = Notarize::sign(&self.namespace, share, notarize.proposal);
                    let msg = Voter::Notarize(n).encode().into();
                    sender.send(Recipients::All, msg, true).await.unwrap();
                }
                Voter::Finalize(finalize) => {
                    // Finalize random digest
                    let view = finalize.view();
                    let share = self.supervisor.share(view).unwrap();
                    let payload = H::random(&mut self.context);
                    let proposal = Proposal::new(view, finalize.proposal.parent, payload);
                    let f = Finalize::sign(&self.namespace, share, proposal);
                    let msg = Voter::Finalize(f).encode().into();
                    sender.send(Recipients::All, msg, true).await.unwrap();

                    // Finalize provided digest
                    let f = Finalize::sign(&self.namespace, share, finalize.proposal);
                    let msg = Voter::Finalize(f).encode().into();
                    sender.send(Recipients::All, msg, true).await.unwrap();
                }
                _ => continue,
            }
        }
    }
}
