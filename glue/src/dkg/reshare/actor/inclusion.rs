use crate::dkg::{
    reshare::{
        actor::Mode,
        metrics::Phase,
        store::{Dealer, Store},
        Actor, Message,
    },
    types::{EpochInfo, EpochOutcome, Payload},
    ParticipantsProvider, Registrar, ReshareBlock, SecretStore,
};
use commonware_consensus::{
    marshal::core::Variant as MarshalVariant,
    types::{Epoch, EpochPhase, Epocher, FixedEpocher, Height},
};
use commonware_cryptography::{
    bls12381::{
        dkg::feldman_desmedt::{observe, DealerLog, Info, Logs},
        primitives::{group::Share, variant::Variant as BlsVariant},
    },
    certificate::Scheme,
    BatchVerifier, Signer,
};
use commonware_macros::select_loop;
use commonware_p2p::{Blocker, Manager};
use commonware_parallel::Strategy;
use commonware_runtime::{
    telemetry::traces::TracedExt as _, BufferPooler, Clock, Metrics, Spawner,
    Storage as RuntimeStorage,
};
use commonware_utils::{channel::fallible::OneshotExt, Acknowledgement, N3f1};
use futures::StreamExt;
use rand_core::CryptoRngCore;
use std::{collections::BTreeMap, ops::ControlFlow};
use tracing::{debug, info, info_span, warn, Instrument as _};

struct Artifact<V: BlsVariant, C: Signer> {
    info: EpochInfo<V, C::PublicKey>,
    share: Option<Share>,
}

type PendingLogs<V, P> = BTreeMap<P, DealerLog<V, P>>;

impl<E, B, V, C, M, X, P, SS, T, BV, S, MV, R, A> Actor<E, B, V, C, M, X, P, SS, T, BV, S, MV, R, A>
where
    E: Spawner + CryptoRngCore + Metrics + BufferPooler + Clock + RuntimeStorage,
    B: ReshareBlock<Variant = V, Signer = C>,
    V: BlsVariant,
    C: Signer,
    M: Manager<PublicKey = C::PublicKey>,
    X: Blocker<PublicKey = C::PublicKey>,
    P: ParticipantsProvider<PublicKey = C::PublicKey>,
    SS: SecretStore,
    T: Strategy,
    BV: BatchVerifier<PublicKey = C::PublicKey> + Send + 'static,
    S: Scheme,
    MV: MarshalVariant<ApplicationBlock = B>,
    R: Registrar<Variant = V, PublicKey = C::PublicKey>,
    A: Acknowledgement,
{
    /// Run the inclusion phase for `epoch`.
    ///
    /// This phase begins at the epoch midpoint. It serves this node's finalized
    /// dealer log to the application, re-offering it until it lands in a
    /// finalized block, observes finalized dealer logs included by other
    /// validators, and constructs the final epoch info when the application asks
    /// to build or verify the epoch's final block.
    ///
    /// The phase returns after the finalized reporter delivers the epoch's last
    /// block. At that point, any included final epoch info has been committed to
    /// the store, the registrar has been updated, and the fence has been
    /// unlocked for the next epoch.
    pub(super) async fn inclusion(
        &mut self,
        epoch: Epoch,
        info: &Info<V, C::PublicKey>,
        store: &mut Store<E, SS, V, C::PublicKey>,
        mut dealer: Option<&mut Dealer<V, C>>,
    ) -> ControlFlow<()> {
        self.metrics.set_phase(Phase::Inclusion);

        if let Some(dealer) = dealer.as_deref_mut() {
            dealer.finalize::<N3f1>();
        }

        let mut served_at: Option<Height> = None;
        let mut finalized_tip = self.marshal.get_processed_height().await;
        select_loop! {
            self.context,
            on_stopped => {
                debug!("shutdown signal received");
                return ControlFlow::Break(());
            },
            Some(message) = self.mailbox.recv() else {
                debug!("mailbox closed, shutting down");
                return ControlFlow::Break(());
            } => match message {
                Message::NextLog {
                    span,
                    height,
                    response,
                } => {
                    let process = info_span!(
                        parent: &span,
                        "dkg.reshare.actor.inclusion.next_log",
                        height = height.traced()
                    );
                    process.in_scope(|| {
                        let payload = served_at
                            .is_none()
                            .then(|| {
                                dealer
                                    .as_ref()
                                    .and_then(|dealer| dealer.finalized())
                                    .map(Payload::DealerLog)
                            })
                            .flatten();
                        let has_payload = payload.is_some();
                        if response.send_lossy(payload) && has_payload {
                            served_at = Some(height);
                        }
                    });
                }
                Message::EpochInfo {
                    span,
                    ancestry,
                    response,
                } => {
                    let process = info_span!(
                        parent: &span,
                        "dkg.reshare.actor.inclusion.epoch_info"
                    );
                    async {
                        let final_height = self
                            .epocher
                            .last(epoch)
                            .expect("epocher must know final epoch height");
                        let pending_logs = Self::pending_logs(
                            epoch,
                            info,
                            self.epocher.clone(),
                            finalized_tip,
                            final_height,
                            ancestry,
                        )
                        .await;
                        let payload = self
                            .artifact(epoch, info, store, Some(&pending_logs))
                            .await
                            .map(|artifact| Payload::EpochInfo(artifact.info));
                        let _ = response.send_lossy(payload);
                    }
                    .instrument(process)
                    .await;
                }
                Message::Finalized {
                    span,
                    block,
                    response,
                } => {
                    let process = info_span!(
                        parent: &span,
                        "dkg.reshare.actor.inclusion.finalized",
                        height = block.height().traced()
                    );
                    let done = async {
                        let bounds = self
                            .epocher
                            .containing(block.height())
                            .expect("epocher must know of block height");
                        assert_eq!(
                            bounds.epoch(),
                            epoch,
                            "inclusion received future epoch block"
                        );
                        assert!(
                            matches!(bounds.phase(), EpochPhase::Midpoint | EpochPhase::Late),
                            "inclusion received block before midpoint"
                        );

                        let public_key = self.signer.public_key();
                        Self::observe_dealer_log(
                            &public_key,
                            info,
                            store,
                            epoch,
                            dealer.as_deref_mut(),
                            block.payload(),
                        )
                        .await;

                        let done = block.height() == bounds.last();
                        if done {
                            let artifact = self.artifact(epoch, info, store, None).await;
                            self.handle_finalized_epoch_info(
                                epoch,
                                store,
                                artifact.as_ref(),
                                block.payload(),
                            )
                            .await;
                        }

                        finalized_tip = Some(block.height());

                        // Re-offer our dealer log if finalization reached the height
                        // we served it into without the log landing on-chain. When
                        // our log does finalize, observe_dealer_log above clears it
                        // via clear_finalized, so a still-present finalized log here
                        // means the proposal we served into lost the view.
                        if served_at.is_some_and(|served| block.height() >= served)
                            && dealer
                                .as_ref()
                                .is_some_and(|dealer| dealer.finalized().is_some())
                        {
                            served_at = None;
                        }

                        response.acknowledge();
                        done
                    }
                    .instrument(process)
                    .await;
                    if done {
                        return ControlFlow::Continue(());
                    }
                }
            },
        };

        ControlFlow::Break(())
    }

    /// Persist a finalized dealer log from an included block.
    ///
    /// Invalid logs are ignored because the block has already passed
    /// application verification. The finalized reporter path is the only place
    /// where observed dealer logs become durable state.
    pub(super) async fn observe_dealer_log(
        public_key: &C::PublicKey,
        info: &Info<V, C::PublicKey>,
        store: &mut Store<E, SS, V, C::PublicKey>,
        epoch: Epoch,
        dealer: Option<&mut Dealer<V, C>>,
        payload: Option<Payload<V, C>>,
    ) {
        let Some(Payload::DealerLog(log)) = payload else {
            return;
        };
        let Some((dealer_key, log)) = log.check(info) else {
            warn!(?epoch, "ignoring invalid dealer log");
            return;
        };

        // `log.check` only authenticates the self-signature, not dealer-set
        // membership. A byzantine leader can embed a validly self-signed log from
        // a key outside the round's dealer set in a finalized block. Such a log is
        // never selected (selection filters non-dealers), so persisting it would
        // only grow durable storage by one slot per attacker key. The round's
        // dealers are the current output's players, so reject anything else.
        if store
            .current()
            .is_some_and(|current| current.output.players().position(&dealer_key).is_none())
        {
            warn!(?epoch, "ignoring dealer log from non-dealer");
            return;
        }

        let ours = dealer_key == *public_key;
        let stored = store.append_log(epoch, dealer_key.clone(), log).await;
        info!(
            ?epoch,
            dealer = ?dealer_key,
            ours,
            stored,
            "observed dealer log on chain"
        );

        if ours {
            if let Some(dealer) = dealer {
                dealer.clear_finalized();
            }
        }
    }

    /// The final block is special because proposal and verification may run ahead
    /// of this actor's finalized-block reporter stream. In that case, the block
    /// ancestry given to the application can contain pending dealer logs that are
    /// not yet present in [`Store`].
    ///
    /// Those pending logs must influence the final [`EpochInfo`] calculation so
    /// proposal and verification agree with the block being evaluated. They must
    /// not be persisted here: only the finalized reporter path below is durable.
    /// This module therefore builds final artifacts from a temporary overlay of
    /// finalized logs plus valid pending ancestry logs.
    async fn pending_logs(
        epoch: Epoch,
        info: &Info<V, C::PublicKey>,
        epocher: FixedEpocher,
        finalized_tip: Option<Height>,
        final_height: Height,
        mut ancestry: crate::dkg::reshare::mailbox::ErasedAncestry<B>,
    ) -> PendingLogs<V, C::PublicKey> {
        let mut blocks = Vec::new();
        while let Some(block) = ancestry.next().await {
            let height = block.height();
            if finalized_tip.is_some_and(|tip| height <= tip) {
                break;
            }
            if height >= final_height {
                continue;
            }
            let Some(bounds) = epocher.containing(height) else {
                continue;
            };
            if bounds.epoch() != epoch {
                continue;
            }
            if !matches!(bounds.phase(), EpochPhase::Midpoint | EpochPhase::Late) {
                continue;
            }
            blocks.push(block);
        }

        let mut logs = BTreeMap::new();
        for block in blocks.into_iter().rev() {
            let height = block.height();
            let Some(Payload::DealerLog(log)) = block.payload() else {
                continue;
            };
            let Some((dealer, log)) = log.check(info) else {
                warn!(?epoch, ?height, "ignoring invalid pending dealer log");
                continue;
            };
            logs.entry(dealer).or_insert(log);
        }
        logs
    }

    /// Build the final epoch artifact from finalized state plus pending logs.
    ///
    /// The resulting [`EpochInfo`] is a lookahead for `epoch + 1`: its output is
    /// the outcome of this epoch's reshare, its players are this epoch's
    /// next players, and its next players are fetched for the following epoch.
    ///
    /// When `pending_logs` is present, the artifact is speculative and must not
    /// mutate metrics or durable state. This is used while proposing or
    /// verifying a pending final block.
    async fn artifact(
        &mut self,
        epoch: Epoch,
        info: &Info<V, C::PublicKey>,
        store: &mut Store<E, SS, V, C::PublicKey>,
        pending_logs: Option<&PendingLogs<V, C::PublicKey>>,
    ) -> Option<Artifact<V, C>> {
        let record_metrics = pending_logs.is_none();
        let current = store.current();

        // DKG mode is the only path that reaches inclusion without a current
        // EpochInfo. In that case, the configured DKG participants are both the
        // dealers and players for the one-shot ceremony.
        let dkg_participants = if current.is_none() {
            self.dkg_participants()
        } else {
            None
        };
        if current.is_none() && dkg_participants.is_none() {
            return None;
        }

        let mut log_map = store.logs(epoch);
        if let Some(pending_logs) = pending_logs {
            for (dealer, log) in pending_logs {
                log_map.entry(dealer.clone()).or_insert_with(|| log.clone());
            }
        }

        let mut logs = Logs::<_, _, N3f1>::new(info.clone());
        for (dealer, log) in log_map.clone() {
            logs.record(dealer, log);
        }

        let public_key = self.signer.public_key();
        let players = current
            .as_ref()
            .map(|current| current.players.clone())
            .or(dkg_participants.clone())?;
        let player = players.position(&public_key).map(|_| {
            store.create_player_with_logs::<C, N3f1>(
                epoch,
                self.signer.clone(),
                info.clone(),
                &log_map,
            )
        });

        let outcome = if let Some(player) = player {
            match player.finalize::<N3f1, BV>(self.context.as_present_mut(), logs, &self.strategy) {
                Ok((output, share)) => Some((output, Some(share))),
                Err(error) => {
                    warn!(?epoch, ?error, "failed to finalize player");
                    None
                }
            }
        } else {
            match observe::<_, _, N3f1, BV>(self.context.as_present_mut(), logs, &self.strategy) {
                Ok(output) => Some((output, None)),
                Err(error) => {
                    warn!(?epoch, ?error, "failed to observe reshare outcome");
                    None
                }
            }
        };

        let (epoch, outcome, output, players, next_players, share) = match outcome {
            Some((output, share)) => match current {
                Some(current) => {
                    let next_epoch = epoch.next();
                    let next_players = self
                        .participants_provider
                        .participants(next_epoch.next())
                        .await;
                    if record_metrics {
                        self.metrics.record_success(&output, &public_key);
                    }
                    (
                        next_epoch,
                        EpochOutcome::Success,
                        output,
                        current.next_players,
                        next_players,
                        share,
                    )
                }
                None => {
                    // DKG success emits the genesis threshold artifact directly.
                    // There is no next committee to prefetch because this
                    // one-shot chain terminates after epoch zero.
                    let share = share.expect("DKG participant must receive a share");
                    if record_metrics {
                        self.metrics.record_success(&output, &public_key);
                    }
                    (
                        epoch,
                        EpochOutcome::Success,
                        output,
                        players,
                        Default::default(),
                        Some(share),
                    )
                }
            },
            None => {
                let current = current?;
                if record_metrics {
                    self.metrics.failed_epochs.inc();
                }
                let share = if current.output.players().position(&public_key).is_some() {
                    store.share(epoch).await
                } else {
                    None
                };
                (
                    epoch.next(),
                    EpochOutcome::Failure,
                    current.output.clone(),
                    current.next_players,
                    self.participants_provider
                        .participants(epoch.next().next())
                        .await,
                    share,
                )
            }
        };

        Some(Artifact {
            info: EpochInfo {
                outcome,
                epoch,
                output,
                players,
                next_players,
            },
            share,
        })
    }

    /// Commit finalized epoch info and configure the next epoch.
    ///
    /// The final block must carry epoch info for the next epoch. If the locally
    /// reconstructed artifact matches it, this node also persists its new share.
    /// If not, the epoch info is still committed without a share so the node can
    /// enter the next epoch as a verifier.
    async fn handle_finalized_epoch_info(
        &mut self,
        epoch: Epoch,
        store: &mut Store<E, SS, V, C::PublicKey>,
        artifact: Option<&Artifact<V, C>>,
        payload: Option<Payload<V, C>>,
    ) {
        let dkg = matches!(self.mode, Mode::Dkg { .. });
        if dkg && payload.is_none() {
            // A failed one-shot DKG has no artifact to commit, so the final
            // block intentionally carries no EpochInfo. Continuous reshare
            // never permits this because its final block must always carry the
            // next epoch pointer.
            assert!(
                artifact.is_none(),
                "final block omitted DKG info despite locally reconstructing it"
            );
            return;
        }

        let Some(Payload::EpochInfo(info)) = payload else {
            panic!("final block missing epoch info for epoch {epoch:?}");
        };
        let next_epoch = if dkg { epoch } else { epoch.next() };
        assert_eq!(
            info.epoch, next_epoch,
            "final block carried epoch info for wrong epoch"
        );

        let share = artifact
            .filter(|artifact| artifact.info == info)
            .and_then(|artifact| artifact.share.clone());
        let rng_seed = store
            .seed_or_random(next_epoch, self.context.as_present_mut())
            .await;
        store
            .commit_epoch(info.clone(), rng_seed, share.clone())
            .await;
        info!(
            epoch = ?info.epoch,
            round = info.epoch.get(),
            success = matches!(info.outcome, EpochOutcome::Success),
            dealers = ?info.output.dealers(),
            players = ?info.players,
            next_players = ?info.next_players,
            "completed reshare ceremony"
        );
        if !dkg {
            self.register_epoch(&info, share).await;
        }
    }
}
