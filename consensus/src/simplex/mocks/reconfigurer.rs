//! Byzantine participant that behaves correctly except increments the epoch by 1
//! in all outgoing votes (notarize/finalize/nullify). This helps ensure peers
//! reject messages from an unexpected epoch.

use crate::{
    simplex::types::{Finalize, Notarize, Nullify, Voter},
    types::{Epoch, View},
    Supervisor, Viewable,
};
use commonware_codec::{Decode, Encode};
use commonware_cryptography::{Hasher, Signer};
use commonware_p2p::{Receiver, Recipients, Sender};
use commonware_runtime::{ContextCell, Handle, Spawner};
use std::marker::PhantomData;
use tracing::debug;

pub struct Config<C: Signer, S: Supervisor<Index = View, PublicKey = C::PublicKey>> {
    pub crypto: C,
    pub supervisor: S,
    pub namespace: Vec<u8>,
}

pub struct Reconfigurer<
    E: Spawner,
    C: Signer,
    H: Hasher,
    S: Supervisor<Index = View, PublicKey = C::PublicKey>,
> {
    context: ContextCell<E>,
    crypto: C,
    supervisor: S,
    namespace: Vec<u8>,
    _hasher: PhantomData<H>,
}

impl<E: Spawner, C: Signer, H: Hasher, S: Supervisor<Index = View, PublicKey = C::PublicKey>>
    Reconfigurer<E, C, H, S>
{
    pub fn new(context: E, cfg: Config<C, S>) -> Self {
        Self {
            context: ContextCell::new(context),
            crypto: cfg.crypto,
            supervisor: cfg.supervisor,
            namespace: cfg.namespace,
            _hasher: PhantomData,
        }
    }

    pub fn start(mut self, voter_network: (impl Sender, impl Receiver)) -> Handle<()> {
        let context = self.context.take();
        context.spawn(move |context| async move {
            self.context.restore(context);
            self.run(voter_network).await;
        })
    }

    async fn run(mut self, voter_network: (impl Sender, impl Receiver)) {
        let (mut sender, mut receiver) = voter_network;
        while let Ok((s, msg)) = receiver.recv().await {
            // Parse message
            let msg = match Voter::<C::Signature, H::Digest>::decode_cfg(msg, &usize::MAX) {
                Ok(msg) => msg,
                Err(err) => {
                    debug!(?err, sender = ?s, "failed to decode message");
                    continue;
                }
            };

            // Process message
            match msg {
                Voter::Notarize(notarize) => {
                    // Get our index
                    let view = notarize.view();
                    let public_key_index = self
                        .supervisor
                        .is_participant(view, &self.crypto.public_key())
                        .unwrap();

                    // Build identical proposal but with epoch incremented by 1
                    let mut proposal = notarize.proposal.clone();
                    let old_round = proposal.round;
                    let new_epoch: Epoch = old_round.epoch().saturating_add(1);
                    proposal.round = (new_epoch, old_round.view()).into();

                    // Sign and broadcast
                    let n = Notarize::sign(
                        &self.namespace,
                        &mut self.crypto,
                        public_key_index,
                        proposal,
                    );
                    let msg = Voter::<C::Signature, H::Digest>::Notarize(n)
                        .encode()
                        .into();
                    sender.send(Recipients::All, msg, true).await.unwrap();
                }
                Voter::Finalize(finalize) => {
                    // Get our index
                    let view = finalize.view();
                    let public_key_index = self
                        .supervisor
                        .is_participant(view, &self.crypto.public_key())
                        .unwrap();

                    // Build identical proposal but with epoch incremented by 1
                    let mut proposal = finalize.proposal.clone();
                    let old_round = proposal.round;
                    let new_epoch: Epoch = old_round.epoch().saturating_add(1);
                    proposal.round = (new_epoch, old_round.view()).into();

                    // Sign and broadcast
                    let f = Finalize::sign(
                        &self.namespace,
                        &mut self.crypto,
                        public_key_index,
                        proposal,
                    );
                    let msg = Voter::<C::Signature, H::Digest>::Finalize(f)
                        .encode()
                        .into();
                    sender.send(Recipients::All, msg, true).await.unwrap();
                }
                Voter::Nullify(nullify) => {
                    // Get our index
                    let view = nullify.view();
                    let public_key_index = self
                        .supervisor
                        .is_participant(view, &self.crypto.public_key())
                        .unwrap();

                    // Re-sign nullify for the next epoch
                    let old_round = nullify.round;
                    let new_epoch: Epoch = old_round.epoch().saturating_add(1);
                    let new_round = (new_epoch, old_round.view()).into();

                    let n = Nullify::sign(
                        &self.namespace,
                        &mut self.crypto,
                        public_key_index,
                        new_round,
                    );
                    let msg = Voter::<C::Signature, H::Digest>::Nullify(n).encode().into();
                    sender.send(Recipients::All, msg, true).await.unwrap();
                }
                _ => continue,
            }
        }
    }
}
