//! Byzantine participant that sends conflicting notarize messages.
//!
//! Unlike simplex, minimmit has no finalize phase, so this conflicter
//! only sends conflicting notarize votes (not finalize).

use crate::minimmit::{
    scheme,
    types::{Notarize, Proposal, Vote},
};
use commonware_codec::{DecodeExt, Encode};
use commonware_cryptography::{certificate::Scheme, Hasher};
use commonware_math::algebra::Random;
use commonware_p2p::{Receiver, Recipients, Sender};
use commonware_runtime::{spawn_cell, Clock, ContextCell, Handle, Spawner};
use rand::{CryptoRng, Rng};
use std::marker::PhantomData;
use tracing::debug;

pub struct Config<S: Scheme> {
    pub scheme: S,
}

pub struct Conflicter<E: Clock + Rng + CryptoRng + Spawner, S: Scheme, H: Hasher> {
    context: ContextCell<E>,
    scheme: S,
    _hasher: PhantomData<H>,
}

impl<E, S, H> Conflicter<E, S, H>
where
    E: Clock + Rng + CryptoRng + Spawner,
    S: scheme::Scheme<H::Digest>,
    H: Hasher,
{
    pub fn new(context: E, cfg: Config<S>) -> Self {
        Self {
            context: ContextCell::new(context),
            scheme: cfg.scheme,
            _hasher: PhantomData,
        }
    }

    pub fn start(mut self, vote_network: (impl Sender, impl Receiver)) -> Handle<()> {
        spawn_cell!(self.context, self.run(vote_network).await)
    }

    async fn run(mut self, vote_network: (impl Sender, impl Receiver)) {
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

            // Process message - only handle notarize votes (no finalize in minimmit)
            match msg {
                Vote::Notarize(notarize) => {
                    // Notarize random digest (conflicting vote)
                    let payload = H::Digest::random(&mut self.context);
                    let proposal =
                        Proposal::new(notarize.round(), notarize.proposal.parent, payload);
                    let n = Notarize::<S, _>::sign(&self.scheme, proposal).unwrap();
                    let msg = Vote::Notarize(n).encode();
                    sender.send(Recipients::All, msg, true).await.unwrap();

                    // Notarize received digest
                    let n = Notarize::<S, _>::sign(&self.scheme, notarize.proposal).unwrap();
                    let msg = Vote::Notarize(n).encode();
                    sender.send(Recipients::All, msg, true).await.unwrap();
                }
                Vote::Nullify(_) => continue,
            }
        }
    }
}
