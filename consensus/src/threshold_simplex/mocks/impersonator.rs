//! Byzantine participant that sends impersonated (and invalid) notarize/finalize messages.

use crate::threshold_simplex::{
    new_types::{Finalize, Notarize, SigningScheme},
    types::Voter,
};
use commonware_codec::{DecodeExt, Encode};
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

pub struct Impersonator<E: Clock + Rng + CryptoRng + Spawner, S: SigningScheme, H: Hasher> {
    context: E,
    signing: S,

    namespace: Vec<u8>,

    _hasher: PhantomData<H>,
}

impl<E: Clock + Rng + CryptoRng + Spawner, S: SigningScheme, H: Hasher> Impersonator<E, S, H> {
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
            let msg = match Voter::<S, H::Digest>::decode(msg) {
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
                        // FIXME
                        // n.seed_signature.index = 1;
                        // n.proposal_signature.index = 1;
                    } else {
                        n.vote.signer = 0;
                        // FIXME
                        // n.proposal_signature.index = 0;
                        // n.proposal_signature.index = 0;
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
