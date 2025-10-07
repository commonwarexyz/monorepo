use super::{Mailbox, Message};
use crate::{
    dkg::DkgManager,
    orchestrator::{self, EpochTransition, BLOCKS_PER_EPOCH},
};
use commonware_consensus::Reporter;
use commonware_cryptography::{
    bls12381::{
        dkg::player::Output,
        primitives::{group::Share, poly::Public, variant::MinSig},
    },
    ed25519::{PrivateKey, PublicKey},
    Sha256,
};
use commonware_p2p::{Receiver, Sender};
use commonware_runtime::{tokio, Handle, Spawner};
use futures::{channel::mpsc, StreamExt};
use std::cmp::Ordering;
use tracing::info;

pub struct Actor {
    context: tokio::Context,
    mailbox: mpsc::Receiver<Message<Sha256, PrivateKey, MinSig>>,
    signer: PrivateKey,
    contributors: Vec<PublicKey>,
}

impl Actor {
    /// Create a new DKG [Actor] and its associated [Mailbox].
    pub fn new(
        context: tokio::Context,
        signer: PrivateKey,
        mut contributors: Vec<PublicKey>,
        mailbox_size: usize,
    ) -> (Self, Mailbox<Sha256, PrivateKey, MinSig>) {
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
        initial_public: Public<MinSig>,
        initial_share: Share,
        mut orchestrator: impl Reporter<Activity = EpochTransition<Sha256>>,
        (mut sender, mut receiver): (
            impl Sender<PublicKey = PublicKey>,
            impl Receiver<PublicKey = PublicKey>,
        ),
    ) -> Handle<()> {
        self.context.spawn_ref()(async move {
            // Initialize the DKG manager for the first round.
            let mut manager = DkgManager::new(
                &mut self.context,
                initial_public,
                initial_share,
                &mut self.signer,
                &self.contributors,
                &mut sender,
                &mut receiver,
            );

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
                        let round = block.height / BLOCKS_PER_EPOCH;
                        let relative_height = block.height % BLOCKS_PER_EPOCH;

                        // Attempt to transition epochs.
                        if let Some(epoch) = orchestrator::is_last_block_in_epoch(block.height) {
                            let Output { public, share } =
                                manager.finalize(round.saturating_sub(1)).await;

                            let transition: EpochTransition<Sha256> = EpochTransition {
                                epoch: epoch + 1,
                                seed: <Sha256 as commonware_cryptography::Hasher>::empty(),
                                poly: public.clone(),
                                share: share.clone(),
                            };
                            orchestrator.report(transition).await;

                            tracing::info!(target: "dkg", epoch, "INSTRUCTED ENTRY OF NEW EPOCH 🚨");

                            // Rotate the manager to begin a new round.
                            manager = DkgManager::new(
                                &mut self.context,
                                public,
                                share,
                                &mut self.signer,
                                &self.contributors,
                                &mut sender,
                                &mut receiver,
                            );
                        };

                        match relative_height.cmp(&(BLOCKS_PER_EPOCH / 2)) {
                            Ordering::Less => {
                                // Continuously distribute shares to any players who haven't acknowledged
                                // receipt yet.
                                manager.distribute(round).await;

                                // Process any incoming messages from other dealers/players.
                                manager.process_messages(round).await;
                            }
                            Ordering::Equal => {
                                // Process any final messages from other dealers/players.
                                manager.process_messages(round).await;

                                // At the midpoint of the epoch, construct the deal outcome for inclusion.
                                manager.construct_deal_outcome(round);
                            }
                            Ordering::Greater => {
                                // Process any incoming deal outcomes from dealing contributors.
                                manager.process_block(round, block).await;
                            }
                        }
                    }
                }
            }

            info!(target: "dkg", "mailbox closed, exiting.");
        })
    }
}
