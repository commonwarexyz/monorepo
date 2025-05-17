//! Byzantine participant that sends outdated notarize and finalize messages.

use crate::{
    threshold_simplex::types::{Finalize, Notarize, Proposal, View, Viewable, Voter},
    ThresholdSupervisor,
};
use commonware_codec::{DecodeExt, Encode};
use commonware_cryptography::{
    bls12381::primitives::{group, variant::Variant},
    Hasher,
};
use commonware_p2p::{Receiver, Recipients, Sender};
use commonware_runtime::{Clock, Handle, Spawner};
use rand::{CryptoRng, Rng};
use std::{collections::HashMap, marker::PhantomData};
use tracing::debug;

pub struct Config<S: ThresholdSupervisor<Index = View, Share = group::Share>> {
    pub supervisor: S,
    pub namespace: Vec<u8>,
    pub view_delta: u64,
}

pub struct Outdated<
    E: Clock + Rng + CryptoRng + Spawner,
    V: Variant,
    H: Hasher,
    S: ThresholdSupervisor<Seed = V::Signature, Index = View, Share = group::Share>,
> {
    context: E,
    supervisor: S,

    namespace: Vec<u8>,

    history: HashMap<u64, Proposal<H::Digest>>,
    view_delta: u64,

    _hasher: PhantomData<H>,
    _variant: PhantomData<V>,
}

impl<
        E: Clock + Rng + CryptoRng + Spawner,
        V: Variant,
        H: Hasher,
        S: ThresholdSupervisor<Seed = V::Signature, Index = View, Share = group::Share>,
    > Outdated<E, V, H, S>
{
    pub fn new(context: E, cfg: Config<S>) -> Self {
        Self {
            context,
            supervisor: cfg.supervisor,

            namespace: cfg.namespace,

            history: HashMap::new(),
            view_delta: cfg.view_delta,

            _hasher: PhantomData,
            _variant: PhantomData,
        }
    }

    pub fn start(mut self, pending_network: (impl Sender, impl Receiver)) -> Handle<()> {
        self.context.spawn_ref()(self.run(pending_network))
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
            let view = msg.view();

            // Process message
            match msg {
                Voter::Notarize(notarize) => {
                    // Store proposal
                    self.history.insert(view, notarize.proposal.clone());

                    // Notarize old digest
                    let view = view.saturating_sub(self.view_delta);
                    let share = self.supervisor.share(view).unwrap();
                    let Some(proposal) = self.history.get(&view) else {
                        continue;
                    };
                    debug!(?view, "notarizing old proposal");
                    let n = Notarize::<V, _>::sign(&self.namespace, share, proposal.clone());
                    let msg = Voter::Notarize(n).encode().into();
                    sender.send(Recipients::All, msg, true).await.unwrap();
                }
                Voter::Finalize(finalize) => {
                    // Store proposal
                    self.history.insert(view, finalize.proposal.clone());

                    // Finalize old digest
                    let view = view.saturating_sub(self.view_delta);
                    let share = self.supervisor.share(view).unwrap();
                    let Some(proposal) = self.history.get(&view) else {
                        continue;
                    };
                    debug!(?view, "finalizing old proposal");
                    let f = Finalize::<V, _>::sign(&self.namespace, share, proposal.clone());
                    let msg = Voter::Finalize(f).encode().into();
                    sender.send(Recipients::All, msg, true).await.unwrap();
                }
                _ => continue,
            }
        }
    }
}
