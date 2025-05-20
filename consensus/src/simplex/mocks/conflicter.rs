//! Byzantine participant that sends conflicting notarize/finalize messages.

use crate::{
    simplex::types::{Finalize, Notarize, Proposal, View, Viewable, Voter},
    Supervisor,
};
use commonware_codec::{Decode, Encode};
use commonware_cryptography::Digest;
use commonware_cryptography::{Hasher, Scheme};
use commonware_p2p::{Receiver, Recipients, Sender};
use commonware_runtime::{Clock, Handle, Spawner};
use rand::{CryptoRng, Rng};
use std::marker::PhantomData;
use tracing::debug;

pub struct Config<C: Scheme, S: Supervisor<Index = View>> {
    pub crypto: C,
    pub supervisor: S,
    pub namespace: Vec<u8>,
}

pub struct Conflicter<
    E: Clock + Rng + CryptoRng + Spawner,
    C: Scheme,
    H: Hasher,
    S: Supervisor<Index = View, PublicKey = C::PublicKey>,
> {
    context: E,
    crypto: C,
    supervisor: S,
    _hasher: PhantomData<H>,

    namespace: Vec<u8>,
}

impl<
        E: Clock + Rng + CryptoRng + Spawner,
        C: Scheme,
        H: Hasher,
        S: Supervisor<Index = View, PublicKey = C::PublicKey>,
    > Conflicter<E, C, H, S>
{
    pub fn new(context: E, cfg: Config<C, S>) -> Self {
        Self {
            context,
            crypto: cfg.crypto,
            supervisor: cfg.supervisor,
            _hasher: PhantomData,

            namespace: cfg.namespace,
        }
    }

    pub fn start(mut self, voter_network: (impl Sender, impl Receiver)) -> Handle<()> {
        self.context.spawn_ref()(self.run(voter_network))
    }

    async fn run(mut self, voter_network: (impl Sender, impl Receiver)) {
        let (mut sender, mut receiver) = voter_network;
        while let Ok((s, msg)) = receiver.recv().await {
            // Parse message
            let msg = match Voter::<C::Signature, H::Digest>::decode_cfg(msg, &usize::MAX) {
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
                    // Get our index
                    let public_key_index = self
                        .supervisor
                        .is_participant(view, &self.crypto.public_key())
                        .unwrap();

                    // Notarize random digest
                    let payload = H::Digest::random(&mut self.context);
                    let proposal = Proposal::new(view, notarize.proposal.parent, payload);
                    let msg = Notarize::sign(
                        &self.namespace,
                        &mut self.crypto,
                        public_key_index,
                        proposal,
                    );
                    let msg = Voter::Notarize(msg).encode().into();
                    sender.send(Recipients::All, msg, true).await.unwrap();

                    // Notarize received digest
                    let msg = Notarize::sign(
                        &self.namespace,
                        &mut self.crypto,
                        public_key_index,
                        notarize.proposal,
                    );
                    let msg = Voter::Notarize(msg).encode().into();
                    sender.send(Recipients::All, msg, true).await.unwrap();
                }
                Voter::Finalize(finalize) => {
                    // Get our index
                    let public_key_index = self
                        .supervisor
                        .is_participant(view, &self.crypto.public_key())
                        .unwrap();

                    // Finalize random digest
                    let payload = H::Digest::random(&mut self.context);
                    let proposal = Proposal::new(view, finalize.proposal.parent, payload);
                    let msg = Finalize::sign(
                        &self.namespace,
                        &mut self.crypto,
                        public_key_index,
                        proposal,
                    );
                    let msg = Voter::Finalize(msg).encode().into();
                    sender.send(Recipients::All, msg, true).await.unwrap();

                    // Finalize provided digest
                    let msg = Finalize::sign(
                        &self.namespace,
                        &mut self.crypto,
                        public_key_index,
                        finalize.proposal,
                    );
                    let msg = Voter::Finalize(msg).encode().into();
                    sender.send(Recipients::All, msg, true).await.unwrap();
                }
                _ => continue,
            }
        }
    }
}
