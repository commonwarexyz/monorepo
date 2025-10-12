use super::{Mailbox, Message};
use crate::{
    dkg::{manager::RoundResult, DkgManager},
    orchestrator::EpochTransition,
    utils::{is_last_block_in_epoch, BLOCKS_PER_EPOCH},
};
use commonware_consensus::Reporter;
use commonware_cryptography::{
    bls12381::{
        dkg::player::Output,
        primitives::{group::Share, poly::Public, variant::Variant},
    },
    Digestible, Hasher, Signer,
};
use commonware_p2p::{utils::mux::Muxer, Receiver, Sender};
use commonware_runtime::{spawn_cell, ContextCell, Handle, Metrics, Spawner};
use futures::{channel::mpsc, StreamExt};
use rand::{rngs::StdRng, seq::SliceRandom, SeedableRng};
use rand_core::CryptoRngCore;
use std::cmp::Ordering;
use tracing::info;

pub struct Actor<E, H, C, V>
where
    H: Hasher,
    C: Signer,
    V: Variant,
{
    context: ContextCell<E>,
    mailbox: mpsc::Receiver<Message<H, C, V>>,
    signer: C,
    num_participants_per_epoch: usize,
}

impl<E, H, C, V> Actor<E, H, C, V>
where
    E: Spawner + Metrics + CryptoRngCore,
    H: Hasher,
    C: Signer,
    V: Variant,
{
    /// Create a new DKG [Actor] and its associated [Mailbox].
    pub fn new(
        context: E,
        signer: C,
        num_participants_per_epoch: usize,
        mailbox_size: usize,
    ) -> (Self, Mailbox<H, C, V>) {
        let (sender, mailbox) = mpsc::channel(mailbox_size);
        (
            Self {
                context: ContextCell::new(context),
                mailbox,
                signer,
                num_participants_per_epoch,
            },
            Mailbox::new(sender),
        )
    }

    /// Start the DKG actor.
    pub fn start(
        mut self,
        initial_public: Public<V>,
        initial_share: Option<Share>,
        mut active_participants: Vec<C::PublicKey>,
        mut inactive_participants: Vec<C::PublicKey>,
        mut orchestrator: impl Reporter<Activity = EpochTransition<V, H, C::PublicKey>>,
        (sender, receiver): (
            impl Sender<PublicKey = C::PublicKey>,
            impl Receiver<PublicKey = C::PublicKey>,
        ),
    ) -> Handle<()> {
        spawn_cell!(self.context, async move {
            // Start a muxer for the physical channel used by DKG/reshare
            let (mux, mut dkg_mux) =
                Muxer::new(self.context.with_label("dkg_mux"), sender, receiver, 100);
            mux.start();

            // Collect all contributors (active + inactive.)
            let mut all_participants = active_participants
                .iter()
                .chain(inactive_participants.iter())
                .cloned()
                .collect::<Vec<_>>();

            // Sort participants to ensure everyone agrees on ordering.
            all_participants.sort();
            active_participants.sort();

            if inactive_participants.len() < self.num_participants_per_epoch {
                // Choose some random active participants to also be players if there are not enough.
                let mut rng = StdRng::seed_from_u64(0);
                let dealer_players = active_participants
                    .choose_multiple(&mut rng, self.num_participants_per_epoch - inactive_participants.len())
                    .cloned()
                    .collect::<Vec<_>>();
                inactive_participants.extend_from_slice(dealer_players.as_slice());
            } else if inactive_participants.len() > self.num_participants_per_epoch {
                // Truncate the number of players if there are too many.
                inactive_participants.truncate(self.num_participants_per_epoch);
            }
            inactive_participants.sort();

            // Initialize the DKG manager for the first round.
            let mut manager = DkgManager::init(
                &mut self.context,
                0,
                initial_public,
                initial_share,
                &mut self.signer,
                active_participants,
                inactive_participants,
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
                            let (next_participants, public, share) = match manager.finalize(epoch).await {
                                (next_participants, RoundResult::Output(Output { public, share })) => (next_participants, public, Some(share)),
                                (next_participants, RoundResult::Polynomial(public)) => (next_participants, public, None),
                            };

                            info!(epoch, "finalized epoch's reshare; instructing reconfiguration after reshare.");
                            let next_epoch = epoch + 1;

                            // Pseudorandomly select some random players to receive shares for the next epoch.
                            let mut rng = StdRng::seed_from_u64(epoch);
                            let mut next_players = all_participants
                                .choose_multiple(&mut rng, self.num_participants_per_epoch)
                                .cloned()
                                .collect::<Vec<_>>();
                            next_players.sort();

                            let transition: EpochTransition<V, H, C::PublicKey> = EpochTransition {
                                epoch: next_epoch,
                                seed: block.digest(),
                                poly: public.clone(),
                                share: share.clone(),
                                participants: next_participants.clone(),
                            };
                            orchestrator.report(transition).await;

                            // Rotate the manager to begin a new round.
                            manager = DkgManager::init(
                                &mut self.context,
                                next_epoch,
                                public,
                                share,
                                &mut self.signer,
                                next_participants,
                                next_players,
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
        }.await)
    }
}
