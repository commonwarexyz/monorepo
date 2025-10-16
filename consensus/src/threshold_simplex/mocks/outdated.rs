//! Byzantine participant that sends outdated notarize and finalize messages.

use crate::{
    threshold_simplex::{
        signing_scheme::SigningScheme,
        types::{Finalize, Notarize, Proposal, Voter},
    },
    Viewable,
};
use commonware_codec::{Decode, Encode};
use commonware_cryptography::Hasher;
use commonware_p2p::{Receiver, Recipients, Sender};
use commonware_runtime::{spawn_cell, Clock, ContextCell, Handle, Spawner};
use rand::{CryptoRng, Rng};
use std::{collections::HashMap, marker::PhantomData};
use tracing::debug;

pub struct Config<S: SigningScheme> {
    pub signing: S,
    pub namespace: Vec<u8>,
    pub view_delta: u64,
}

pub struct Outdated<E: Clock + Rng + CryptoRng + Spawner, S: SigningScheme, H: Hasher> {
    context: ContextCell<E>,
    signing: S,

    namespace: Vec<u8>,

    history: HashMap<u64, Proposal<H::Digest>>,
    view_delta: u64,

    _hasher: PhantomData<H>,
}

impl<E: Clock + Rng + CryptoRng + Spawner, S: SigningScheme, H: Hasher> Outdated<E, S, H> {
    pub fn new(context: E, cfg: Config<S>) -> Self {
        Self {
            context: ContextCell::new(context),
            signing: cfg.signing,

            namespace: cfg.namespace,

            history: HashMap::new(),
            view_delta: cfg.view_delta,

            _hasher: PhantomData,
        }
    }

    pub fn start(mut self, pending_network: (impl Sender, impl Receiver)) -> Handle<()> {
        spawn_cell!(self.context, self.run(pending_network).await)
    }

    async fn run(mut self, pending_network: (impl Sender, impl Receiver)) {
        let (mut sender, mut receiver) = pending_network;
        while let Ok((s, msg)) = receiver.recv().await {
            // Parse message
            let msg = match Voter::<S, H::Digest>::decode_cfg(
                msg,
                &self.signing.certificate_codec_config(),
            ) {
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
                    let Some(proposal) = self.history.get(&view) else {
                        continue;
                    };
                    debug!(?view, "notarizing old proposal");
                    let n =
                        Notarize::<S, _>::sign(&self.signing, &self.namespace, proposal.clone());
                    let msg = Voter::Notarize(n).encode().into();
                    sender.send(Recipients::All, msg, true).await.unwrap();
                }
                Voter::Finalize(finalize) => {
                    // Store proposal
                    self.history.insert(view, finalize.proposal.clone());

                    // Finalize old digest
                    let view = view.saturating_sub(self.view_delta);
                    let Some(proposal) = self.history.get(&view) else {
                        continue;
                    };
                    debug!(?view, "finalizing old proposal");
                    let f =
                        Finalize::<S, _>::sign(&self.signing, &self.namespace, proposal.clone());
                    let msg = Voter::Finalize(f).encode().into();
                    sender.send(Recipients::All, msg, true).await.unwrap();
                }
                _ => continue,
            }
        }
    }
}
