use crate::dkg::{
    ParticipantsProvider, Registrar, ReshareBlock, SecretStore,
    reshare::{
        Actor, EpochInfoResponse, Message,
        actor::Mode,
        metrics::Phase,
        store::{Dealer, Store},
    },
    types::{EpochInfo, EpochOutcome, Participants, Payload},
};
use commonware_consensus::{
    marshal::core::Variant as MarshalVariant,
    simplex::scheme::Scheme as SimplexScheme,
    types::{Epoch, EpochPhase, Epocher, FixedEpocher, Height},
};
use commonware_cryptography::{
    BatchVerifier, PublicKey, Signer,
    bls12381::{
        dkg::feldman_desmedt::{DealerLog, Info, Logs, observe},
        primitives::{group::Share, variant::Variant as BlsVariant},
    },
    certificate::Scheme,
};
use commonware_macros::{select, select_loop};
use commonware_p2p::{Blocker, Manager};
use commonware_parallel::Strategy;
use commonware_runtime::{
    BufferPooler, Clock, Metrics, Spawner, Storage as RuntimeStorage, signal,
    telemetry::traces::TracedExt as _,
};
use commonware_utils::{
    Acknowledgement, N3f1,
    channel::{fallible::OneshotExt, oneshot},
    ordered::Set,
};
use futures::StreamExt;
use rand_core::CryptoRng;
use std::{
    collections::BTreeMap,
    num::{NonZeroU32, NonZeroU64},
    ops::ControlFlow,
};
use tracing::{Instrument as _, debug, info, info_span, warn};

#[derive(Clone)]
struct Artifact<V: BlsVariant, C: Signer> {
    info: EpochInfo<V, C::PublicKey>,
    share: Option<Share>,
}

type PendingLogs<V, P> = BTreeMap<P, DealerLog<V, P>>;

struct CachedArtifact<V: BlsVariant, C: Signer> {
    // The cache is valid only for this exact effective view of finalized and
    // pending logs. It lives for one inclusion phase and never owns durable
    // protocol state.
    logs: PendingLogs<V, C::PublicKey>,
    artifact: Option<Artifact<V, C>>,
}

struct PendingLogScan<'a, V: BlsVariant, P> {
    epoch: Epoch,
    info: &'a Info<V, P>,
    epocher: FixedEpocher,
    finalized_tip: Option<Height>,
    final_height: Height,
}

fn validate_future_participants<V: BlsVariant, P: PublicKey>(
    participants: &Set<P>,
    max_participants: NonZeroU32,
    blocks_per_epoch: NonZeroU64,
) {
    assert!(
        !participants.is_empty(),
        "participants provider returned empty future participant set"
    );

    let actual = participants.len();
    let max = max_participants.get() as usize;
    assert!(
        actual <= max,
        "participants provider returned oversized future participant set: {actual} > {max}"
    );

    // Two epochs after this set is embedded it becomes both the dealer set
    // and the previous output's player set, so its quorum bounds the dealer
    // logs the ceremony must land on-chain. Reject an unusable provider set
    // before it reaches a finalized EpochInfo, where the capacity violation
    // would be re-derived from the chain and panic every node at the boundary.
    Participants {
        dealers: participants.clone(),
        players: participants.clone(),
        next_players: Set::default(),
    }
    .validate_epoch_capacity::<V>(blocks_per_epoch, None)
    .expect("participants provider returned set exceeding epoch dealer-log capacity");
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
async fn pending_logs<B, V, C>(
    scan: PendingLogScan<'_, V, C::PublicKey>,
    mut ancestry: crate::dkg::reshare::mailbox::ErasedAncestry<B>,
    mut shutdown: signal::Signal,
    response: &mut oneshot::Sender<EpochInfoResponse<V, C>>,
) -> Option<PendingLogs<V, C::PublicKey>>
where
    B: ReshareBlock<Variant = V, Signer = C>,
    V: BlsVariant,
    C: Signer,
{
    let mut blocks = Vec::new();
    loop {
        let block = select! {
            _ = &mut shutdown => return None,
            _ = response.closed() => return None,
            block = ancestry.next() => block,
        };
        let Some(block) = block else {
            break;
        };
        let height = block.height();
        if scan.finalized_tip.is_some_and(|tip| height <= tip) {
            break;
        }
        if height >= scan.final_height {
            continue;
        }
        let Some(bounds) = scan.epocher.containing(height) else {
            continue;
        };
        if bounds.epoch() != scan.epoch {
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
        let Some((dealer, log)) = log.check(scan.info) else {
            warn!(epoch = ?scan.epoch, ?height, "ignoring invalid pending dealer log");
            continue;
        };
        logs.entry(dealer).or_insert(log);
    }
    Some(logs)
}

impl<E, B, V, C, M, X, P, SS, T, BV, S, MV, R, A> Actor<E, B, V, C, M, X, P, SS, T, BV, S, MV, R, A>
where
    E: Spawner + CryptoRng + Metrics + BufferPooler + Clock + RuntimeStorage,
    B: ReshareBlock<Variant = V, Signer = C>,
    V: BlsVariant,
    C: Signer,
    M: Manager<PublicKey = C::PublicKey>,
    X: Blocker<PublicKey = C::PublicKey>,
    P: ParticipantsProvider<PublicKey = C::PublicKey>,
    SS: SecretStore,
    T: Strategy,
    BV: BatchVerifier<PublicKey = C::PublicKey> + Send + 'static,
    S: Scheme + SimplexScheme<MV::Commitment, PublicKey = C::PublicKey>,
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
        let mut next_players = None;
        let mut artifact_cache = None;
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
                    release,
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
                        let reservation = payload
                            .map(|payload| crate::dkg::reshare::mailbox::LogReservation::new(
                                height, payload, release,
                            ));
                        if response.send_lossy(reservation) && has_payload {
                            served_at = Some(height);
                        }
                    });
                }
                Message::ReleaseLog { height } => {
                    if served_at == Some(height)
                        && dealer
                            .as_ref()
                            .is_some_and(|dealer| dealer.finalized().is_some())
                    {
                        served_at = None;
                    }
                }
                Message::EpochInfo {
                    span,
                    ancestry,
                    mut response,
                } => {
                    if response.is_closed() {
                        continue;
                    }
                    let process = info_span!(
                        parent: &span,
                        "dkg.reshare.actor.inclusion.epoch_info"
                    );
                    async {
                        let final_height = self
                            .epocher
                            .last(epoch)
                            .expect("epocher must know final epoch height");
                        let scan = PendingLogScan {
                            epoch,
                            info,
                            epocher: self.epocher.clone(),
                            finalized_tip,
                            final_height,
                        };
                        let Some(pending_logs) = pending_logs(
                            scan,
                            ancestry,
                            self.context.stopped(),
                            &mut response,
                        )
                        .await
                        else {
                            return;
                        };
                        if response.is_closed() {
                            return;
                        }
                        let artifact = self
                            .artifact(
                                epoch,
                                info,
                                store,
                                Some(&pending_logs),
                                &mut next_players,
                                &mut artifact_cache,
                            )
                            .await;
                        let result = match artifact {
                            Some(artifact) => {
                                EpochInfoResponse::Available(Some(Payload::EpochInfo(
                                    artifact.info,
                                )))
                            }
                            None if matches!(self.mode, Mode::Dkg { .. }) => {
                                EpochInfoResponse::Available(None)
                            }
                            None => EpochInfoResponse::Unavailable,
                        };
                        let _ = response.send_lossy(result);
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
                            let artifact = self
                                .artifact(
                                    epoch,
                                    info,
                                    store,
                                    None,
                                    &mut next_players,
                                    &mut artifact_cache,
                                )
                                .await;
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

        if ours && let Some(dealer) = dealer {
            dealer.clear_finalized();
        }
    }

    /// Build the final epoch artifact from finalized state plus pending logs.
    ///
    /// The resulting [`EpochInfo`] is a lookahead for `epoch + 1`: its output is
    /// the outcome of this epoch's reshare, its players are this epoch's
    /// next players, and its next players are fetched for the following epoch.
    ///
    /// Artifact construction never mutates metrics or durable state. A
    /// speculative result is cached only for the exact effective dealer-log map
    /// and becomes authoritative only if a matching final block is finalized.
    async fn artifact(
        &mut self,
        epoch: Epoch,
        info: &Info<V, C::PublicKey>,
        store: &mut Store<E, SS, V, C::PublicKey>,
        pending_logs: Option<&PendingLogs<V, C::PublicKey>>,
        next_players: &mut Option<Set<C::PublicKey>>,
        artifact_cache: &mut Option<CachedArtifact<V, C>>,
    ) -> Option<Artifact<V, C>> {
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

        if let Some(cached) = artifact_cache
            .as_ref()
            .filter(|cached| cached.logs == log_map)
        {
            return cached.artifact.clone();
        }

        let mut logs = Logs::<_, _, N3f1>::new(info.clone());
        for (dealer, log) in log_map.clone() {
            logs.record(dealer, log);
        }

        let public_key = self.signer.public_key();
        let players = current
            .as_ref()
            .map(|current| current.players.clone())
            .or(dkg_participants.clone())
            .expect("current epoch or DKG mode must provide players");
        let player = players.position(&public_key).and_then(|_| {
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

        let future_players = if current.is_some() {
            match next_players {
                Some(players) => players.clone(),
                None => {
                    // The provider contract requires this set to remain stable
                    // for the epoch, so reuse one lookup across competing final
                    // block proposals and verification attempts.
                    let players = self
                        .participants_provider
                        .participants(epoch.next().next())
                        .await;
                    validate_future_participants::<V, _>(
                        &players,
                        self.max_participants,
                        self.blocks_per_epoch,
                    );
                    *next_players = Some(players.clone());
                    players
                }
            }
        } else {
            Default::default()
        };

        let artifact = match outcome {
            Some((output, share)) => match current {
                Some(current) => {
                    let next_epoch = epoch.next();
                    Some(Artifact {
                        info: EpochInfo {
                            outcome: EpochOutcome::Success,
                            epoch: next_epoch,
                            output,
                            players: current.next_players,
                            next_players: future_players,
                        },
                        share,
                    })
                }
                None => {
                    // DKG success emits the genesis threshold artifact directly.
                    // There is no next committee to prefetch because this
                    // one-shot chain terminates after epoch zero.
                    let share = share.expect("DKG participant must receive a share");
                    Some(Artifact {
                        info: EpochInfo {
                            outcome: EpochOutcome::Success,
                            epoch,
                            output,
                            players,
                            next_players: future_players,
                        },
                        share: Some(share),
                    })
                }
            },
            None => {
                let Some(current) = current else {
                    *artifact_cache = Some(CachedArtifact {
                        logs: log_map,
                        artifact: None,
                    });
                    return None;
                };
                let share = if current.output.players().position(&public_key).is_some() {
                    store.share(epoch).await
                } else {
                    None
                };
                Some(Artifact {
                    info: EpochInfo {
                        outcome: EpochOutcome::Failure,
                        epoch: epoch.next(),
                        output: current.output,
                        players: current.next_players,
                        next_players: future_players,
                    },
                    share,
                })
            }
        };

        *artifact_cache = Some(CachedArtifact {
            logs: log_map,
            artifact: artifact.clone(),
        });
        artifact
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

        // Record only canonical finalized outcomes. Speculative artifact
        // construction is intentionally side-effect free.
        match info.outcome {
            EpochOutcome::Success => self
                .metrics
                .record_success(&info.output, &self.signer.public_key()),
            EpochOutcome::Failure => {
                self.metrics.failed_epochs.inc();
            }
        }

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dkg::tests::mocks::{TestBlock, TestBlsVariant};
    use commonware_cryptography::{
        Signer,
        bls12381::primitives::sharing::Mode as SharingMode,
        ed25519::{PrivateKey, PublicKey},
    };
    use commonware_runtime::{Runner, Spawner, Supervisor, deterministic};
    use commonware_utils::{N3f1, NZU32, NZU64, channel::oneshot, ordered::Set};
    use futures::{FutureExt, stream};
    use std::sync::Arc;

    type TestResponse = EpochInfoResponse<TestBlsVariant, PrivateKey>;

    fn signers() -> Vec<PrivateKey> {
        (0..4).map(PrivateKey::from_seed).collect()
    }

    fn players() -> Set<PublicKey> {
        Set::from_iter_dedup(signers().iter().map(Signer::public_key))
    }

    fn info() -> Info<TestBlsVariant, PublicKey> {
        Info::new::<N3f1>(
            b"_COMMONWARE_GLUE_DKG_RESHARE_INCLUSION_TEST",
            0,
            None,
            SharingMode::NonZeroCounter,
            players(),
            players(),
        )
        .expect("valid info")
    }

    fn stalled_ancestry() -> crate::dkg::reshare::mailbox::ErasedAncestry<TestBlock> {
        Box::pin(stream::pending::<Arc<TestBlock>>())
    }

    fn scan(
        info: &Info<TestBlsVariant, PublicKey>,
    ) -> PendingLogScan<'_, TestBlsVariant, PublicKey> {
        PendingLogScan {
            epoch: Epoch::zero(),
            info,
            epocher: FixedEpocher::new(NZU64!(4)),
            finalized_tip: None,
            final_height: Height::new(3),
        }
    }

    #[test]
    #[should_panic(expected = "participants provider returned empty future participant set")]
    fn future_participants_rejects_empty_provider_set() {
        validate_future_participants::<TestBlsVariant, _>(
            &Set::<PublicKey>::default(),
            NZU32!(4),
            NZU64!(8),
        );
    }

    #[test]
    #[should_panic(expected = "participants provider returned oversized future participant set")]
    fn future_participants_rejects_oversized_provider_set() {
        validate_future_participants::<TestBlsVariant, _>(&players(), NZU32!(3), NZU64!(8));
    }

    #[test]
    fn future_participants_accepts_set_within_epoch_capacity() {
        // Four participants need a three-log dealer quorum; an eight-block
        // epoch has three inclusion slots.
        validate_future_participants::<TestBlsVariant, _>(&players(), NZU32!(4), NZU64!(8));
    }

    #[test]
    #[should_panic(expected = "exceeding epoch dealer-log capacity")]
    fn future_participants_rejects_set_exceeding_epoch_capacity() {
        // Four participants need a three-log dealer quorum, but a four-block
        // epoch only has one inclusion slot.
        validate_future_participants::<TestBlsVariant, _>(&players(), NZU32!(4), NZU64!(4));
    }

    #[test]
    fn pending_logs_cancels_stalled_ancestry_when_response_closes() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let info = info();
            let (mut response_tx, response_rx) = oneshot::channel::<TestResponse>();
            let pending = pending_logs(
                scan(&info),
                stalled_ancestry(),
                context.stopped(),
                &mut response_tx,
            );
            futures::pin_mut!(pending);
            assert!(pending.as_mut().now_or_never().is_none());

            drop(response_rx);

            assert!(pending.await.is_none());
        });
    }

    #[test]
    fn pending_logs_cancels_stalled_ancestry_when_runtime_stops() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let info = info();
            let (mut response_tx, _response_rx) = oneshot::channel::<TestResponse>();
            let pending = pending_logs(
                scan(&info),
                stalled_ancestry(),
                context.stopped(),
                &mut response_tx,
            );
            futures::pin_mut!(pending);
            assert!(pending.as_mut().now_or_never().is_none());

            let stopper = context.child("stopper");
            let stop = context.child("stop").spawn(|_| async move {
                stopper.stop(0, None).await.expect("runtime should stop");
            });

            assert!(pending.await.is_none());
            stop.await.expect("stop task should finish");
        });
    }
}
