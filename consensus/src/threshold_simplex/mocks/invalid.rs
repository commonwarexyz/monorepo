//! Byzantine participant that sends invalid notarize/finalize messages.

use crate::{
    threshold_simplex::types::{Finalize, Notarize, View, Viewable, Voter},
    ThresholdSupervisor,
};
use commonware_codec::{DecodeExt, Encode};
use commonware_cryptography::{
    bls12381::primitives::{
        group::{self, Element},
        variant::Variant,
    },
    Hasher,
};
use commonware_p2p::{Receiver, Recipients, Sender};
use commonware_runtime::{Clock, Handle, Spawner};
use rand::{CryptoRng, Rng};
use std::marker::PhantomData;
use tracing::debug;

pub struct Config<S: ThresholdSupervisor<Index = View, Share = group::Share>> {
    pub supervisor: S,
    pub namespace: Vec<u8>,
}

pub struct Invalid<
    E: Clock + Rng + CryptoRng + Spawner,
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
        E: Clock + Rng + CryptoRng + Spawner,
        V: Variant,
        H: Hasher,
        S: ThresholdSupervisor<Seed = V::Signature, Index = View, Share = group::Share>,
    > Invalid<E, V, H, S>
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
                    // Notarize received digest
                    let share = self.supervisor.share(notarize.view()).unwrap();
                    let mut n = Notarize::<V, _>::sign(&self.namespace, share, notarize.proposal);

                    // Manipulate signature
                    n.seed_signature.value.add(&V::Signature::one());

                    // Send invalid message
                    let msg = Voter::Notarize(n).encode().into();
                    sender.send(Recipients::All, msg, true).await.unwrap();
                }
                Voter::Finalize(finalize) => {
                    // Finalize provided digest
                    let share = self.supervisor.share(finalize.view()).unwrap();
                    let mut f = Finalize::<V, _>::sign(&self.namespace, share, finalize.proposal);

                    // Manipulate signature
                    f.proposal_signature.value.add(&V::Signature::one());

                    // Send invalid message
                    let msg = Voter::Finalize(f).encode().into();
                    sender.send(Recipients::All, msg, true).await.unwrap();
                }
                _ => continue,
            }
        }
    }
}
