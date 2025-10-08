//! Byzantine participant that sends invalid notarize/finalize messages.

use crate::threshold_simplex::types::{Finalize, Notarize, SigningScheme, Voter};
use commonware_codec::{Decode, Encode};
use commonware_cryptography::Hasher;
use commonware_p2p::{Receiver, Recipients, Sender};
use commonware_runtime::{Clock, Handle, Spawner};
use rand::{CryptoRng, Rng};
use std::marker::PhantomData;
use tracing::debug;

pub struct Config<S: SigningScheme> {
    pub signing: S,
    pub namespace: Vec<u8>,
}

pub struct Invalid<E: Clock + Rng + CryptoRng + Spawner, S: SigningScheme, H: Hasher> {
    context: E,
    signing: S,

    namespace: Vec<u8>,

    _hasher: PhantomData<H>,
}

impl<E: Clock + Rng + CryptoRng + Spawner, S: SigningScheme, H: Hasher> Invalid<E, S, H> {
    pub fn new(context: E, cfg: Config<S>) -> Self {
        Self {
            context,
            signing: cfg.signing,

            namespace: cfg.namespace,

            _hasher: PhantomData,
        }
    }

    pub fn start(mut self, pending_network: (impl Sender, impl Receiver)) -> Handle<()> {
        self.context.spawn_ref()(self.run(pending_network))
    }

    async fn run(self, pending_network: (impl Sender, impl Receiver)) {
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
                    // Notarize received digest
                    let mut n = Notarize::<S, _>::sign(
                        &self.signing,
                        &self.namespace,
                        notarize.proposal.clone(),
                    );

                    // Manipulate signature
                    let invalid_signature =
                        Notarize::<S, _>::sign(&self.signing, &[], notarize.proposal)
                            .vote
                            .signature;

                    n.vote.signature = invalid_signature;

                    // Send invalid message
                    let msg = Voter::Notarize(n).encode().into();
                    sender.send(Recipients::All, msg, true).await.unwrap();
                }
                Voter::Finalize(finalize) => {
                    // Finalize provided digest
                    let mut f = Finalize::<S, _>::sign(
                        &self.signing,
                        &self.namespace,
                        finalize.proposal.clone(),
                    );

                    // Manipulate signature
                    let invalid_signature =
                        Finalize::<S, _>::sign(&self.signing, &[], finalize.proposal)
                            .vote
                            .signature;

                    f.vote.signature = invalid_signature;

                    // Send invalid message
                    let msg = Voter::Finalize(f).encode().into();
                    sender.send(Recipients::All, msg, true).await.unwrap();
                }
                _ => continue,
            }
        }
    }
}
