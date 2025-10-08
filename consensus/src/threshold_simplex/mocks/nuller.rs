//! Byzantine participant that sends nullify and finalize messages for the same view.

use crate::threshold_simplex::types::{Finalize, Nullify, SigningScheme, Voter};
use commonware_codec::{Decode, Encode};
use commonware_cryptography::Hasher;
use commonware_p2p::{Receiver, Recipients, Sender};
use commonware_runtime::{Handle, Spawner};
use std::marker::PhantomData;
use tracing::debug;

pub struct Config<S: SigningScheme> {
    pub signing: S,
    pub namespace: Vec<u8>,
}

pub struct Nuller<E: Spawner, S: SigningScheme, H: Hasher> {
    context: E,
    signing: S,
    namespace: Vec<u8>,
    _hasher: PhantomData<H>,
}

impl<E: Spawner, S: SigningScheme, H: Hasher> Nuller<E, S, H> {
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
                    // Nullify
                    let n = Nullify::sign::<H::Digest>(
                        &self.signing,
                        &self.namespace,
                        notarize.proposal.round,
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
