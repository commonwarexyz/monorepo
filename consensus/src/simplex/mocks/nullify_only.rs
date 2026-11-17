//! Byzantine participant that only sends `nullify` votes in response to proposals.
//!
//! This actor observes incoming `Vote` messages and, whenever it receives a
//! `Notarize` proposal for some round, it broadcasts a signed `Nullify` for that
//! same round. It does not emit any `Finalize` messages.

use crate::simplex::{
    scheme::Scheme,
    types::{Nullify, Vote},
};
use commonware_codec::{DecodeExt, Encode};
use commonware_cryptography::{Hasher, certificate};
use commonware_p2p::{Receiver, Recipients, Sender};
use commonware_runtime::{Handle, Spawner};
use std::marker::PhantomData;
use tracing::debug;

pub struct Config<S: certificate::Scheme> {
    pub scheme: S,
}

pub struct NullifyOnly<E: Spawner, S: Scheme<H::Digest>, H: Hasher> {
    context: E,
    scheme: S,
    _hasher: PhantomData<H>,
}

impl<E: Spawner, S: Scheme<H::Digest>, H: Hasher> NullifyOnly<E, S, H> {
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

            // Respond with only a `Nullify` vote when a proposal is observed.
            if let Vote::Notarize(notarize) = msg {
                let nullify = Nullify::sign::<H::Digest>(&self.scheme, notarize.round()).unwrap();
                let msg = Vote::<S, H::Digest>::Nullify(nullify).encode();
                sender.send(Recipients::All, msg, true);
            }
        }
    }
}
