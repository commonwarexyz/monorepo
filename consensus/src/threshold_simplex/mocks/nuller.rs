//! Byzantine participant that sends nullify and finalize messages for the same view.

use crate::threshold_simplex::{
    signing_scheme::SigningScheme,
    types::{Finalize, Nullify, Voter},
};
use commonware_codec::{Decode, Encode};
use commonware_cryptography::Hasher;
use commonware_p2p::{Receiver, Recipients, Sender};
use commonware_runtime::{spawn_cell, ContextCell, Handle, Spawner};
use std::marker::PhantomData;
use tracing::debug;

pub struct Config<S: SigningScheme> {
    pub signing: S,
    pub namespace: Vec<u8>,
}

pub struct Nuller<E: Spawner, S: SigningScheme, H: Hasher> {
    context: ContextCell<E>,
    signing: S,
    namespace: Vec<u8>,
    _hasher: PhantomData<H>,
}

impl<E: Spawner, S: SigningScheme, H: Hasher> Nuller<E, S, H> {
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
                    // Nullify
                    let n = Nullify::sign::<H::Digest>(
                        &self.signing,
                        &self.namespace,
                        notarize.round(),
                    );
                    let msg = Voter::<S, H::Digest>::Nullify(n).encode().into();
                    sender.send(Recipients::All, msg, true).await.unwrap();

                    // Finalize digest
                    let proposal = notarize.proposal;
                    let f = Finalize::<S, _>::sign(&self.signing, &self.namespace, proposal);
                    let msg = Voter::Finalize(f).encode().into();
                    sender.send(Recipients::All, msg, true).await.unwrap();
                }
                _ => continue,
            }
        }
    }
}
