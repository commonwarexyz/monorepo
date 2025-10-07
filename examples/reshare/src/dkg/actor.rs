use super::{Mailbox, Message};
use crate::{
    dkg::DkgManager,
    orchestrator::EpochTransition,
    utils::{is_last_block_in_epoch, BLOCKS_PER_EPOCH},
};
use commonware_consensus::Reporter;
use commonware_cryptography::{
    bls12381::{
        dkg::player::Output,
        primitives::{group::Share, poly::Public, variant::Variant},
    },
    Digestible, Hasher, PrivateKey,
};
use commonware_p2p::{utils::mux::Muxer, Receiver, Sender};
use commonware_runtime::{Handle, Metrics, Spawner};
use futures::{channel::mpsc, StreamExt};
use rand_core::CryptoRngCore;
use std::cmp::Ordering;
use tracing::info;

pub struct Actor<E, H, C, V>
where
    H: Hasher,
    C: PrivateKey,
    V: Variant,
{
    context: E,
    mailbox: mpsc::Receiver<Message<H, C, V>>,
    signer: C,
    contributors: Vec<C::PublicKey>,
}

impl<E, H, C, V> Actor<E, H, C, V>
where
    E: Spawner + Metrics + CryptoRngCore,
    H: Hasher,
    C: PrivateKey,
    V: Variant,
{
    /// Create a new DKG [Actor] and its associated [Mailbox].
    pub fn new(
        context: E,
        signer: C,
        mut contributors: Vec<C::PublicKey>,
        mailbox_size: usize,
    ) -> (Self, Mailbox<H, C, V>) {
        // Sort the list of contributors to ensure everyone agrees on ordering.
        contributors.sort();

        let (sender, mailbox) = mpsc::channel(mailbox_size);
        (
            Self {
                context,
                mailbox,
                signer,
                contributors,
            },
            Mailbox::new(sender),
        )
    }

    /// Start the DKG actor.
    pub fn start(
        mut self,
        initial_public: Public<V>,
        initial_share: Share,
        mut orchestrator: impl Reporter<Activity = EpochTransition<V, H>>,
        (sender, receiver): (
            impl Sender<PublicKey = C::PublicKey>,
            impl Receiver<PublicKey = C::PublicKey>,
        ),
    ) -> Handle<()> {
        self.context.spawn_ref()(async move {
            // Start a muxer for the physical channel used by DKG/reshare
            let (mux, mut dkg_mux) =
                Muxer::new(self.context.with_label("dkg_mux"), sender, receiver, 100);
            mux.start();

            // Initialize the DKG manager for the first round.
            let mut manager = DkgManager::init(
                &mut self.context,
                0, // TODO: Pick up on last epoch from storage.
                initial_public,
                initial_share,
                &mut self.signer,
                &self.contributors,
                &mut dkg_mux,
            )
            .await;

            while let Some(message) = self.mailbox.next().await {
                match message {
                    Message::Act { response } => {
                        let outcome = manager.take_deal_outcome();

                        if let Some(ref outcome) = outcome {
                            info!(
                                n_acks = outcome.acks.len(),
                                n_reveals = outcome.reveals.len(),
                                "including reshare outcome in proposed block"
                            );
                        }

                        let _ = response.send(outcome);
                    }
                    Message::Finalized { block } => {
                        let epoch = block.height / BLOCKS_PER_EPOCH;
                        let relative_height = block.height % BLOCKS_PER_EPOCH;

                        // Attempt to transition epochs.
                        if let Some(epoch) = is_last_block_in_epoch(block.height) {
                            let Output { public, share } = manager.finalize(epoch).await;

                            info!(epoch, "finalized epoch's reshare; instructing reconfiguration after reshare.");
                            let next_epoch = epoch + 1;

                            let transition: EpochTransition<V, H> = EpochTransition {
                                epoch: next_epoch,
                                seed: block.digest(),
                                poly: public.clone(),
                                share: share.clone(),
                            };
                            orchestrator.report(transition).await;

                            // Rotate the manager to begin a new round.
                            manager = DkgManager::init(
                                &mut self.context,
                                next_epoch,
                                public,
                                share,
                                &mut self.signer,
                                &self.contributors,
                                &mut dkg_mux,
                            )
                            .await;
                        };

                        match relative_height.cmp(&(BLOCKS_PER_EPOCH / 2)) {
                            Ordering::Less => {
                                // Continuously distribute shares to any players who haven't acknowledged
                                // receipt yet.
                                manager.distribute(epoch).await;

                                // Process any incoming messages from other dealers/players.
                                manager.process_messages(epoch).await;
                            }
                            Ordering::Equal => {
                                // Process any final messages from other dealers/players.
                                manager.process_messages(epoch).await;

                                // At the midpoint of the epoch, construct the deal outcome for inclusion.
                                manager.construct_deal_outcome(epoch);
                            }
                            Ordering::Greater => {
                                // Process any incoming deal outcomes from dealing contributors.
                                manager.process_block(epoch, block).await;
                            }
                        }
                    }
                }
            }

            info!("mailbox closed, exiting.");
        })
    }
}
