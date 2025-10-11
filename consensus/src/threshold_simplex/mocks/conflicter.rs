//! Byzantine participant that sends conflicting notarize/finalize messages.

use crate::threshold_simplex::types::{Finalize, Notarize, Proposal, SigningScheme, Voter};
use commonware_codec::{Decode, Encode};
use commonware_cryptography::{Digest, Hasher};
use commonware_p2p::{Receiver, Recipients, Sender};
use commonware_runtime::{spawn_cell, Clock, ContextCell, Handle, Spawner};
use rand::{CryptoRng, Rng};
use std::marker::PhantomData;
use tracing::debug;

pub struct Config<S: SigningScheme> {
    pub signing: S,
    pub namespace: Vec<u8>,
}

pub struct Conflicter<E: Clock + Rng + CryptoRng + Spawner, S: SigningScheme, H: Hasher> {
    context: ContextCell<E>,
    signing: S,
    namespace: Vec<u8>,
    _hasher: PhantomData<H>,
}

impl<E: Clock + Rng + CryptoRng + Spawner, S: SigningScheme, H: Hasher> Conflicter<E, S, H> {
    pub fn new(context: E, cfg: Config<S>) -> Self {
        Self {
            context: ContextCell::new(context),
            signing: cfg.signing,
            namespace: cfg.namespace,
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

            // Process message
            match msg {
                Voter::Notarize(notarize) => {
                    // Notarize random digest
                    let payload = H::Digest::random(&mut self.context);
                    let proposal =
                        Proposal::new(notarize.round(), notarize.proposal.parent, payload);
                    let n = Notarize::<S, _>::sign(&self.signing, &self.namespace, proposal);
                    let msg = Voter::Notarize(n).encode().into();
                    sender.send(Recipients::All, msg, true).await.unwrap();

                    // Notarize received digest
                    let n =
                        Notarize::<S, _>::sign(&self.signing, &self.namespace, notarize.proposal);
                    let msg = Voter::Notarize(n).encode().into();
                    sender.send(Recipients::All, msg, true).await.unwrap();
                }
                Voter::Finalize(finalize) => {
                    // Finalize random digest
                    let payload = H::Digest::random(&mut self.context);
                    let proposal =
                        Proposal::new(finalize.round(), finalize.proposal.parent, payload);
                    let f = Finalize::<S, _>::sign(&self.signing, &self.namespace, proposal);
                    let msg = Voter::Finalize(f).encode().into();
                    sender.send(Recipients::All, msg, true).await.unwrap();

                    // Finalize provided digest
                    let f =
                        Finalize::<S, _>::sign(&self.signing, &self.namespace, finalize.proposal);
                    let msg = Voter::Finalize(f).encode().into();
                    sender.send(Recipients::All, msg, true).await.unwrap();
                }
                _ => continue,
            }
        }
    }
}
