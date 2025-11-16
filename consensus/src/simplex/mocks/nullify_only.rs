//! Byzantine participant that only sends `nullify` votes in response to proposals.
//!
//! This actor observes incoming `Voter` messages and, whenever it receives a
//! `Notarize` proposal for some round, it broadcasts a signed `Nullify` for that
//! same round. It does not emit any `Finalize` messages.

use crate::simplex::{
    signing_scheme::Scheme,
    types::{Nullify, Voter},
};
use commonware_codec::{Decode, Encode};
use commonware_cryptography::Hasher;
use commonware_p2p::{Receiver, Recipients, Sender};
use commonware_runtime::{spawn_cell, ContextCell, Handle, Spawner};
use std::marker::PhantomData;
use tracing::debug;

pub struct Config<S: Scheme> {
    pub scheme: S,
    pub namespace: Vec<u8>,
}

pub struct NullifyOnly<E: Spawner, S: Scheme, H: Hasher> {
    context: ContextCell<E>,
    scheme: S,
    namespace: Vec<u8>,
    _hasher: PhantomData<H>,
}

impl<E: Spawner, S: Scheme, H: Hasher> NullifyOnly<E, S, H> {
    pub fn new(context: E, cfg: Config<S>) -> Self {
        Self {
            context: ContextCell::new(context),
            scheme: cfg.scheme,
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
                &self.scheme.certificate_codec_config(),
            ) {
                Ok(msg) => msg,
                Err(err) => {
                    debug!(?err, sender = ?s, "failed to decode message");
                    continue;
                }
            };

            // Respond with only a `Nullify` vote when a proposal is observed.
            if let Voter::Notarize(notarize) = msg {
                let nullify =
                    Nullify::sign::<H::Digest>(&self.scheme, &self.namespace, notarize.round())
                        .unwrap();
                let msg = Voter::<S, H::Digest>::Nullify(nullify).encode().into();
                sender.send(Recipients::All, msg, true).await.unwrap();
            }
        }
    }
}
