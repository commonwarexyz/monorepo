//! Byzantine participant that sends impersonated (and invalid) notarize/finalize messages.

use crate::simplex::{
    signing_scheme::Scheme,
    types::{Finalize, Notarize, Voter},
};
use commonware_codec::{Decode, Encode};
use commonware_cryptography::Hasher;
use commonware_p2p::{Receiver, Recipients, Sender};
use commonware_runtime::{spawn_cell, Clock, ContextCell, Handle, Spawner};
use rand::{CryptoRng, Rng};
use std::marker::PhantomData;
use tracing::debug;

pub struct Config<S: Scheme> {
    pub signing: S,
    pub namespace: Vec<u8>,
}

pub struct Impersonator<E: Clock + Rng + CryptoRng + Spawner, S: Scheme, H: Hasher> {
    context: ContextCell<E>,
    signing: S,

    namespace: Vec<u8>,

    _hasher: PhantomData<H>,
}

impl<E: Clock + Rng + CryptoRng + Spawner, S: Scheme, H: Hasher> Impersonator<E, S, H> {
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
                    let mut n = Notarize::sign(&self.signing, &self.namespace, notarize.proposal);

                    // Manipulate index
                    if n.vote.signer == 0 {
                        n.vote.signer = 1;
                    } else {
                        n.vote.signer = 0;
                    }

                    // Send invalid message
                    let msg = Voter::Notarize(n).encode().into();
                    sender.send(Recipients::All, msg, true).await.unwrap();
                }
                Voter::Finalize(finalize) => {
                    // Finalize provided digest
                    let mut f = Finalize::sign(&self.signing, &self.namespace, finalize.proposal);

                    // Manipulate signature
                    if f.vote.signer == 0 {
                        f.vote.signer = 1;
                    } else {
                        f.vote.signer = 0;
                    }

                    // Send invalid message
                    let msg = Voter::Finalize(f).encode().into();
                    sender.send(Recipients::All, msg, true).await.unwrap();
                }
                _ => continue,
            }
        }
    }
}
