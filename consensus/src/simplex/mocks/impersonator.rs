//! Byzantine participant that sends impersonated (and invalid) notarize/finalize messages.

use crate::{
    simplex::{
        scheme,
        types::{Finalize, Notarize, Vote},
    },
    types::Participant,
};
use commonware_codec::{DecodeExt, Encode};
use commonware_cryptography::{Hasher, certificate::Scheme};
use commonware_p2p::{Receiver, Recipients, Sender};
use commonware_runtime::{Clock, Handle, Spawner};
use rand_core::CryptoRng;
use std::marker::PhantomData;
use tracing::debug;

pub struct Config<S: Scheme> {
    pub scheme: S,
}

pub struct Impersonator<E: Clock + CryptoRng + Spawner, S: Scheme, H: Hasher> {
    context: E,
    scheme: S,

    _hasher: PhantomData<H>,
}

impl<E: Clock + CryptoRng + Spawner, S: scheme::Scheme<H::Digest>, H: Hasher>
    Impersonator<E, S, H>
{
    pub fn new(context: E, cfg: Config<S>) -> Self {
        Self {
            context,
            scheme: cfg.scheme,

            _hasher: PhantomData,
        }
    }

    pub fn start(self, vote_network: (impl Sender, impl Receiver)) -> Handle<()> {
        self.context
            .child("run")
            .spawn(move |_| self.run(vote_network))
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
                    let mut n = Notarize::sign(&self.scheme, notarize.proposal).unwrap();

                    // Manipulate index
                    if n.attestation.signer == Participant::new(0) {
                        n.attestation.signer = Participant::new(1);
                    } else {
                        n.attestation.signer = Participant::new(0);
                    }

                    // Send invalid message
                    let msg = Vote::Notarize(n).encode();
                    sender.send(Recipients::All, msg, true);
                }
                Vote::Finalize(finalize) => {
                    // Finalize provided digest
                    let mut f = Finalize::sign(&self.scheme, finalize.proposal).unwrap();

                    // Manipulate signature
                    if f.attestation.signer == Participant::new(0) {
                        f.attestation.signer = Participant::new(1);
                    } else {
                        f.attestation.signer = Participant::new(0);
                    }

                    // Send invalid message
                    let msg = Vote::Finalize(f).encode();
                    sender.send(Recipients::All, msg, true);
                }
                _ => continue,
            }
        }
    }
}
