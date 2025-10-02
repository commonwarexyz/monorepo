use super::{Mailbox, Message};
use crate::dkg::DkgManager;
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

/// The number of blocks in an epoch.
const EPOCH_LENGTH: u64 = 150;

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
                        let round = block.height / EPOCH_LENGTH;
                        let relative_height = block.height % EPOCH_LENGTH;

                        // Finalize the round if at the end of an epoch.
                        //
                        // This will never include genesis, as marshal never reports that block.
                        if relative_height == 0 {
                            let Output { public, share } =
                                manager.finalize(round.saturating_sub(1)).await;

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
                        }

                        match relative_height.cmp(&(EPOCH_LENGTH / 2)) {
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
