//! Byzantine participant that sends outdated notarize and finalize messages.

use crate::{
    simplex::types::{
        finalize_namespace, notarize_namespace, Finalize, Notarize, Proposal, View, Viewable, Voter,
    },
    Supervisor,
};
use commonware_codec::{Decode, Encode};
use commonware_cryptography::{Hasher, Scheme};
use commonware_p2p::{Receiver, Recipients, Sender};
use commonware_runtime::{Clock, Handle, Spawner};
use rand::{CryptoRng, Rng};
use std::{collections::HashMap, marker::PhantomData};
use tracing::debug;

pub struct Config<C: Scheme, S: Supervisor<Index = View>> {
    pub crypto: C,
    pub supervisor: S,
    pub namespace: Vec<u8>,
    pub view_delta: u64,
}

pub struct Outdated<
    E: Clock + Rng + CryptoRng + Spawner,
    C: Scheme,
    H: Hasher,
    S: Supervisor<Index = View, PublicKey = C::PublicKey>,
> {
    context: E,
    crypto: C,
    supervisor: S,
    _hasher: PhantomData<H>,

    notarize_namespace: Vec<u8>,
    finalize_namespace: Vec<u8>,

    history: HashMap<u64, Proposal<H::Digest>>,
    view_delta: u64,
}

impl<
        E: Clock + Rng + CryptoRng + Spawner,
        C: Scheme,
        H: Hasher,
        S: Supervisor<Index = View, PublicKey = C::PublicKey>,
    > Outdated<E, C, H, S>
{
    pub fn new(context: E, cfg: Config<C, S>) -> Self {
        Self {
            context,
            crypto: cfg.crypto,
            supervisor: cfg.supervisor,
            _hasher: PhantomData,

            notarize_namespace: notarize_namespace(&cfg.namespace),
            finalize_namespace: finalize_namespace(&cfg.namespace),

            history: HashMap::new(),
            view_delta: cfg.view_delta,
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
                    // Store proposal
                    self.history.insert(view, notarize.proposal.clone());

                    // Notarize old digest
                    let view = view.saturating_sub(self.view_delta);
                    let public_key_index = self
                        .supervisor
                        .is_participant(view, &self.crypto.public_key())
                        .unwrap();
                    let Some(proposal) = self.history.get(&view) else {
                        continue;
                    };
                    debug!(?view, "notarizing old proposal");
                    let msg = Notarize::sign(
                        &mut self.crypto,
                        public_key_index,
                        proposal.clone(),
                        &self.notarize_namespace,
                    );
                    let msg = Voter::Notarize(msg).encode().into();
                    sender.send(Recipients::All, msg, true).await.unwrap();
                }
                Voter::Finalize(finalize) => {
                    // Store proposal
                    self.history.insert(view, finalize.proposal.clone());

                    // Finalize provided digest
                    let view = view.saturating_sub(self.view_delta);
                    let public_key_index = self
                        .supervisor
                        .is_participant(view, &self.crypto.public_key())
                        .unwrap();
                    let Some(proposal) = self.history.get(&view) else {
                        continue;
                    };
                    debug!(?view, "finalizing old proposal");
                    let msg = Finalize::sign(
                        &mut self.crypto,
                        public_key_index,
                        proposal.clone(),
                        &self.finalize_namespace,
                    );
                    let msg = Voter::Finalize(msg).encode().into();
                    sender.send(Recipients::All, msg, true).await.unwrap();
                }
                _ => continue,
            }
        }
    }
}
