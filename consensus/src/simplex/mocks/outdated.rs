//! Byzantine participant that sends outdated notarize and finalize messages.

use crate::{
    simplex::types::{Finalize, Notarize, Proposal, Voter},
    types::View,
    Supervisor, Viewable,
};
use commonware_codec::{Decode, Encode};
use commonware_cryptography::{Hasher, Signer};
use commonware_p2p::{Receiver, Recipients, Sender};
use commonware_runtime::{Handle, Spawner};
use std::collections::HashMap;
use tracing::debug;

pub struct Config<C: Signer, S: Supervisor<Index = View>> {
    pub crypto: C,
    pub supervisor: S,
    pub namespace: Vec<u8>,
    pub view_delta: u64,
}

pub struct Outdated<C: Signer, H: Hasher, S: Supervisor<Index = View, PublicKey = C::PublicKey>> {
    crypto: C,
    supervisor: S,

    namespace: Vec<u8>,

    history: HashMap<u64, Proposal<H::Digest>>,
    view_delta: u64,
}

impl<C: Signer, H: Hasher, S: Supervisor<Index = View, PublicKey = C::PublicKey>>
    Outdated<C, H, S>
{
    pub fn new(cfg: Config<C, S>) -> Self {
        Self {
            crypto: cfg.crypto,
            supervisor: cfg.supervisor,

            namespace: cfg.namespace,

            history: HashMap::new(),
            view_delta: cfg.view_delta,
        }
    }

    pub fn start(
        self,
        spawner: impl Spawner,
        voter_network: (impl Sender, impl Receiver),
    ) -> Handle<()> {
        spawner.spawn(|_| self.run(voter_network))
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
                        &self.namespace,
                        &mut self.crypto,
                        public_key_index,
                        proposal.clone(),
                    );
                    let msg = Voter::Notarize(msg).encode().into();
                    sender.send(Recipients::All, msg, true).await.unwrap();
                }
                Voter::Finalize(finalize) => {
                    // Store proposal
                    self.history.insert(view, finalize.proposal.clone());

                    // Finalize old digest
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
                        &self.namespace,
                        &mut self.crypto,
                        public_key_index,
                        proposal.clone(),
                    );
                    let msg = Voter::Finalize(msg).encode().into();
                    sender.send(Recipients::All, msg, true).await.unwrap();
                }
                _ => continue,
            }
        }
    }
}
