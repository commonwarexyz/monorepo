use super::{Mailbox, Message};
use crate::{
    dkg::{
        state::{DkgState, State},
        PostUpdate, Update, UpdateCallBack,
    },
    namespace,
    orchestrator::{self, EpochTransition},
    self_channel::self_channel,
    setup::PeerConfig,
    BLOCKS_PER_EPOCH,
};
use commonware_consensus::{
    utils::{epoch as compute_epoch, is_last_block_in_epoch, relative_height_in_epoch},
    Reporter,
};
use commonware_cryptography::{
    bls12381::{
        dkg::{observe, Info, Output, SignedDealerLog},
        primitives::{group::Share, variant::Variant},
    },
    transcript::Summary,
    Digest, Hasher, Signer,
};
use commonware_macros::select;
use commonware_p2p::{utils::mux::Muxer, Manager, Receiver, Sender};
use commonware_runtime::{spawn_cell, Clock, ContextCell, Handle, Metrics, Spawner, Storage};
use commonware_utils::{ordered::Set, Acknowledgement as _, NZU32};
use futures::{channel::mpsc, StreamExt};
use governor::clock::Clock as GClock;
use prometheus_client::metrics::counter::Counter;
use rand_core::CryptoRngCore;
use tracing::{info, warn};

mod dealer;
mod player;

pub struct Config<C: Signer, P> {
    pub manager: P,
    pub signer: C,
    pub mailbox_size: usize,
    pub partition_prefix: String,
    pub peer_config: PeerConfig<C::PublicKey>,
}

pub struct Actor<E, P, H, C, V>
where
    E: Spawner + Metrics + CryptoRngCore + Clock + GClock + Storage,
    P: Manager<PublicKey = C::PublicKey, Peers = Set<C::PublicKey>>,
    H: Hasher,
    C: Signer,
    V: Variant,
{
    context: ContextCell<E>,
    manager: P,
    mailbox: mpsc::Receiver<Message<H, C, V>>,
    signer: C,
    peer_config: PeerConfig<C::PublicKey>,
    failed_rounds: Counter,
    partition_prefix: String,
}

impl<E, P, H, C, V> Actor<E, P, H, C, V>
where
    E: Spawner + Metrics + CryptoRngCore + Clock + GClock + Storage,
    P: Manager<PublicKey = C::PublicKey, Peers = Set<C::PublicKey>>,
    H: Hasher,
    C: Signer,
    V: Variant,
{
    /// Create a new DKG [Actor] and its associated [Mailbox].
    pub async fn init(context: E, config: Config<C, P>) -> (Self, Mailbox<H, C, V>) {
        let failed_rounds = Counter::default();
        context.register(
            "failed_rounds",
            "Number of failed DKG/reshare rounds",
            failed_rounds.clone(),
        );

        let context = ContextCell::new(context);

        let (sender, mailbox) = mpsc::channel(config.mailbox_size);
        (
            Self {
                context,
                manager: config.manager,
                mailbox,
                signer: config.signer,
                peer_config: config.peer_config,
                failed_rounds,
                partition_prefix: config.partition_prefix,
            },
            Mailbox::new(sender),
        )
    }

    /// Start the DKG actor.
    pub fn start(
        mut self,
        output: Option<Output<V, C::PublicKey>>,
        share: Option<Share>,
        orchestrator: impl Reporter<Activity = orchestrator::Message<V, C::PublicKey>>,
        dkg_chan: (
            impl Sender<PublicKey = C::PublicKey>,
            impl Receiver<PublicKey = C::PublicKey>,
        ),
        callback: Box<dyn UpdateCallBack<V, C::PublicKey>>,
    ) -> Handle<()> {
        // NOTE: In a production setting with a large validator set, the implementor may want
        // to choose a dedicated thread for the DKG actor. This actor can perform CPU-intensive
        // cryptographic operations.
        spawn_cell!(
            self.context,
            self.run(output, share, orchestrator, dkg_chan, callback)
                .await
        )
    }

    async fn run(
        mut self,
        output: Option<Output<V, C::PublicKey>>,
        share: Option<Share>,
        mut orchestrator: impl Reporter<Activity = orchestrator::Message<V, C::PublicKey>>,
        (sender, receiver): (
            impl Sender<PublicKey = C::PublicKey>,
            impl Receiver<PublicKey = C::PublicKey>,
        ),
        mut update_cb: Box<dyn UpdateCallBack<V, C::PublicKey>>,
    ) {
        let max_read_size = NZU32!(self.peer_config.max_participants_per_round());
        let is_dkg = output.is_none();
        // **This stores persist private key material to disk. In a production
        // environment, this key material should both be stored securely and deleted permanently
        // after use.**
        let state = State::init(
            self.context.with_label("storage"),
            &self.partition_prefix,
            max_read_size,
        )
        .await;
        if state.dkg_state().await.is_none() {
            let initial_state = DkgState {
                round: 0,
                rng_seed: Summary::random(&mut self.context),
                output,
                share,
            };
            state.append_dkg_state(initial_state).await;
        };

        // Start a muxer for the physical channel used by DKG/reshare.
        // Make sure to use a channel allowing sending messages to ourselves.
        let (sender, receiver) = self_channel(self.signer.public_key(), 0, sender, receiver);
        let (mux, mut dkg_mux) =
            Muxer::new(self.context.with_label("dkg_mux"), sender, receiver, 100);
        mux.start();
        'actor: loop {
            let (epoch, dkg_state) = state
                .dkg_state()
                .await
                .expect("dkg_state should be initialized");
            // Prune everything older than the previous epoch.
            if let Some(prev) = epoch.previous() {
                state.prune(prev).await;
            }
            let (dealers, players, next_players) = if is_dkg {
                (
                    self.peer_config.participants.clone(),
                    self.peer_config.dealers(0),
                    Set::from_iter_dedup([]),
                )
            } else {
                (
                    self.peer_config.dealers(dkg_state.round),
                    self.peer_config.dealers(dkg_state.round + 1),
                    self.peer_config.dealers(dkg_state.round + 2),
                )
            };

            // Any given peer set includes:
            // - Dealers and players for the active epoch
            // - Players for the next epoch
            self.manager
                .update(
                    epoch.get(),
                    Set::from_iter_dedup(
                        dealers
                            .iter()
                            .cloned()
                            .chain(players.iter().cloned())
                            .chain(next_players.into_iter()),
                    ),
                )
                .await;

            let self_pk = self.signer.public_key();
            // If we've already submitted a log, there's no point acting as the dealer.
            let am_dealer = dealers.position(&self_pk).is_some()
                && !state.has_submitted_log(epoch, &self_pk).await;
            let am_player = players.position(&self_pk).is_some();

            // Inform the orchestrator of the epoch transition
            if let Some(output) = dkg_state.output.as_ref() {
                let transition: EpochTransition<V, C::PublicKey> = EpochTransition {
                    epoch,
                    poly: Some(output.public().clone()),
                    share: dkg_state.share.clone(),
                    dealers: dealers.clone(),
                };
                orchestrator
                    .report(orchestrator::Message::Enter(transition))
                    .await;
            }

            let round_info = Info::new(
                namespace::APPLICATION,
                epoch.get(),
                dkg_state.output.clone(),
                dealers,
                players,
            )
            .expect("round info configuration should be correct");
            let (to_players, from_dealers) = dkg_mux
                .register(0)
                .await
                .expect("should be able to create channel");
            let (to_dealers, from_players) = dkg_mux
                .register(1)
                .await
                .expect("should be able to create channel");
            let mut mb_dealer = if am_dealer {
                let (dealer, mb) = dealer::Actor::init(
                    self.context.with_label("dealer"),
                    dkg_state.rng_seed,
                    state.clone(),
                    (to_players, from_players),
                    round_info.clone(),
                    self.signer.clone(),
                    dkg_state.share.clone(),
                )
                .await;
                dealer.start();
                Some(mb)
            } else {
                None
            };
            let mut mb_player = if am_player {
                let (player, mb) = player::Actor::init(
                    self.context.with_label("player"),
                    state.clone(),
                    to_dealers,
                    from_dealers,
                    round_info.clone(),
                    max_read_size,
                    self.signer.clone(),
                )
                .await;
                player.start();
                Some(mb)
            } else {
                None
            };

            let mut dealer_result: Option<SignedDealerLog<V, C>> = None;

            let mut epoch_done = false;

            while !epoch_done {
                let m = select! {
                    _ = self.context.stopped() => {
                        break 'actor;
                    },
                    mb = self.mailbox.next() => {
                        let Some(m) = mb else {
                            warn!("dkg actor mailbox closed");
                            break 'actor;
                        };
                        m
                    }
                };

                match m {
                    Message::Act { response } => {
                        let outcome = dealer_result.clone();
                        if outcome.is_some() {
                            info!("including reshare outcome in proposed block");
                        }
                        if response.send(outcome).is_err() {
                            warn!("dkg actor could not send response to Act");
                        }
                    }
                    Message::Finalized { block, response } => {
                        let epoch = compute_epoch(BLOCKS_PER_EPOCH, block.height);
                        let relative_height =
                            relative_height_in_epoch(BLOCKS_PER_EPOCH, block.height);
                        let mid_point = BLOCKS_PER_EPOCH / 2;

                        // Inform the orchestrator of the epoch exit after first finalization
                        if relative_height == 0 {
                            if let Some(prev) = epoch.previous() {
                                orchestrator.report(orchestrator::Message::Exit(prev)).await;
                            }
                        }

                        if let Some(log) = block.log {
                            if let Some((dealer, log)) = log.check(&round_info) {
                                // If we see our dealing outcome in a finalized block,
                                // make sure to take it, so that we don't post
                                // it in a subsequent blocks (although that would be fine).
                                if dealer == self_pk {
                                    dealer_result.take();
                                }
                                state.append_log(epoch, dealer, log).await;
                            }
                        }

                        // Ping the player and dealer to send their messages.
                        if relative_height < mid_point {
                            if let Some(mb_player) = mb_player.as_mut() {
                                if mb_player.transmit().await.is_err() {
                                    info!("dkg player exited");
                                    break 'actor;
                                }
                            }

                            if let Some(mb_dealer) = mb_dealer.as_mut() {
                                if mb_dealer.transmit().await.is_err() {
                                    info!("dkg dealer exited");
                                    break 'actor;
                                }
                            }
                        }

                        // At the midpoint of the epoch, construct the deal outcome for inclusion.
                        if relative_height == BLOCKS_PER_EPOCH / 2 {
                            if let Some(mb_dealer) = mb_dealer.take() {
                                let Ok(res) = mb_dealer.finalize().await else {
                                    info!("dkg dealer exited");
                                    break 'actor;
                                };
                                dealer_result = Some(res);
                            }
                        }

                        epoch_done =
                            is_last_block_in_epoch(BLOCKS_PER_EPOCH, block.height).is_some();

                        // Wait to acknowledge until the block has been processed by the application.
                        //
                        // If we did not block on processing the block, marshal could continue processing finalized blocks and start
                        // at a future block after restart (leaving the application in an unrecoverable state where we are beyond the last epoch height
                        // and not willing to enter the next epoch).
                        response.acknowledge();
                    }
                }
            }

            let logs = state.logs(epoch).await;
            let (success, next_round, next_output, next_share) = if let Some(mb_player) = mb_player
            {
                let Ok(res) = mb_player.finalize(logs).await else {
                    info!("dkg player exited");
                    break 'actor;
                };
                match res {
                    Ok((new_output, new_share)) => {
                        (true, dkg_state.round + 1, Some(new_output), Some(new_share))
                    }
                    Err(_) => (
                        false,
                        dkg_state.round,
                        dkg_state.output.clone(),
                        dkg_state.share.clone(),
                    ),
                }
            } else {
                match observe(round_info, logs, 1) {
                    Ok(output) => (true, dkg_state.round + 1, Some(output), None),
                    Err(_) => (
                        false,
                        dkg_state.round,
                        dkg_state.output.clone(),
                        dkg_state.share.clone(),
                    ),
                }
            };
            if !success {
                self.failed_rounds.inc();
            }

            info!(
                success,
                ?epoch,
                "finalized epoch's reshare; instructing reconfiguration after reshare.",
            );
            state
                .append_dkg_state(DkgState {
                    round: next_round,
                    rng_seed: Summary::random(&mut self.context),
                    output: next_output.clone(),
                    share: next_share.clone(),
                })
                .await;

            let update = if success {
                Update::Success {
                    epoch,
                    output: next_output.expect("success => output exists"),
                    share: next_share.clone(),
                }
            } else {
                Update::Failure { epoch }
            };
            if let PostUpdate::Stop = update_cb.on_update(update).await {
                // Close the mailbox to prevent accepting any new messages.
                drop(self.mailbox);
                // Exit last consensus instance to avoid useless work while we wait for shutdown (we
                // won't need to finalize further blocks after the DKG completes).
                orchestrator
                    .report(orchestrator::Message::Exit(epoch))
                    .await;
                // Keep running until killed to keep the orchestrator mailbox alive, allowing
                // peers that may have gone offline to catch up.
                //
                // The initial DKG process will never be exited automatically, assuming coordination
                // between participants is manual.
                info!("DKG complete; waiting for shutdown.");
                futures::future::pending::<()>().await;
                break 'actor;
            }
        }
        info!("exiting DKG actor");
    }
}
