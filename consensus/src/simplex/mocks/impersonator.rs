//! Byzantine participant that sends impersonated (and invalid) notarize/finalize messages.

use crate::simplex::{
    scheme,
    types::{Finalize, Notarize, Vote},
};
use commonware_codec::{DecodeExt, Encode};
use commonware_cryptography::{certificate::Scheme, Hasher};
use commonware_p2p::{Receiver, Recipients, Sender};
use commonware_runtime::{spawn_cell, Clock, ContextCell, Handle, Spawner};
use rand::{CryptoRng, Rng};
use std::marker::PhantomData;
use tracing::debug;

pub struct Config<S: Scheme> {
    pub scheme: S,
    pub namespace: Vec<u8>,
}

pub struct Impersonator<E: Clock + Rng + CryptoRng + Spawner, S: Scheme, H: Hasher> {
    context: ContextCell<E>,
    scheme: S,

    namespace: Vec<u8>,

    _hasher: PhantomData<H>,
}

impl<E: Clock + Rng + CryptoRng + Spawner, S: scheme::Scheme<H::Digest>, H: Hasher>
    Impersonator<E, S, H>
{
    pub fn new(context: E, cfg: Config<S>) -> Self {
        Self {
            context: ContextCell::new(context),
            scheme: cfg.scheme,

            namespace: cfg.namespace,

            _hasher: PhantomData,
        }
    }

    pub fn start(mut self, vote_network: (impl Sender, impl Receiver)) -> Handle<()> {
        spawn_cell!(self.context, self.run(vote_network).await)
    }

    async fn run(self, vote_network: (impl Sender, impl Receiver)) {
        let (mut sender, mut receiver) = vote_network;
        while let Ok((s, msg)) = receiver.recv().await {
            // Parse message
            let msg = match Vote::<S, H::Digest>::decode(msg) {
                Ok(msg) => msg,
                Err(err) => {
                    debug!(?err, sender = ?s, "failed to decode message");
                    continue;
                }
            };

            // Process message
            match msg {
                Vote::Notarize(notarize) => {
                    // Notarize received digest
                    let mut n =
                        Notarize::sign(&self.scheme, &self.namespace, notarize.proposal).unwrap();

                    // Manipulate index
                    if n.attestation.signer == 0 {
                        n.attestation.signer = 1;
                    } else {
                        n.attestation.signer = 0;
                    }

                    // Send invalid message
                    let msg = Vote::Notarize(n).encode().into();
                    sender.send(Recipients::All, msg, true).await.unwrap();
                }
                Vote::Finalize(finalize) => {
                    // Finalize provided digest
                    let mut f =
                        Finalize::sign(&self.scheme, &self.namespace, finalize.proposal).unwrap();

                    // Manipulate signature
                    if f.attestation.signer == 0 {
                        f.attestation.signer = 1;
                    } else {
                        f.attestation.signer = 0;
                    }

                    // Send invalid message
                    let msg = Vote::Finalize(f).encode().into();
                    sender.send(Recipients::All, msg, true).await.unwrap();
                }
                _ => continue,
            }
        }
    }
}
