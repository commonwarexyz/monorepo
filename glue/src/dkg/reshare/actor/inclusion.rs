use crate::dkg::{
    ParticipantsProvider, Registrar, ReshareBlock, SecretStore,
    reshare::{
        Actor, EpochInfoResponse, Message,
        actor::Mode,
        metrics::Phase,
        store::{Dealer, Player, Store},
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
        dkg::feldman_desmedt::{DealerLog, Info, Logs, Output, observe},
        primitives::{group::Share, variant::Variant as BlsVariant},
    },
    certificate::Scheme,
};
use commonware_macros::{select, select_loop};
use commonware_p2p::{Blocker, Manager};
use commonware_parallel::Strategy;
use commonware_runtime::{
    BufferPooler, Clock, Handle, Metrics, Spawner, Storage as RuntimeStorage, signal,
    telemetry::traces::TracedExt as _,
};
use commonware_utils::{
    Acknowledgement, N3f1,
    channel::{fallible::OneshotExt, oneshot},
    futures::OptionFuture,
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

/// The exact effective dealer-log view used for one verification.
type PendingLogs<V, P> = BTreeMap<P, DealerLog<V, P>>;

/// Boundary-block requests waiting for the current verification target.
///
/// Retargeting must drain these with [`EpochInfoResponse::Pending`] before
/// accepting waiters for the replacement.
type ArtifactWaiters<V, C> = Vec<oneshot::Sender<EpochInfoResponse<V, C>>>;

/// A locally reconstructed boundary artifact and this node's matching share.
///
/// This value is phase-local. It becomes durable only after the same
/// [`EpochInfo`] appears in a finalized boundary block.
#[derive(Clone)]
struct Artifact<V: BlsVariant, C: Signer> {
    info: EpochInfo<V, C::PublicKey>,
    share: Option<Share>,
}

/// The output of successful dealer-log verification.
///
/// `share` is present when this node participated as a player and absent when
/// it only observed the public ceremony.
#[derive(Clone)]
struct Ceremony<V: BlsVariant, C: Signer> {
    output: Output<V, C::PublicKey>,
    share: Option<Share>,
}

/// A verification result bound to the complete log view that produced it.
///
/// An absent `ceremony` means the log view proves that the ceremony failed.
struct VerifiedLogs<V: BlsVariant, C: Signer> {
    logs: PendingLogs<V, C::PublicKey>,
    ceremony: Option<Ceremony<V, C>>,
}

/// Tracks verification for the latest effective dealer-log set.
///
/// CPU work is allowed to finish once started. If the target changes while it
/// runs, only the latest log set is retained and started after the active task
/// completes. This bounds verification to one shared task at a time. All state
/// is reconstructable after a crash; no speculative result is persisted.
struct Verification<V: BlsVariant, C: Signer> {
    target: PendingLogs<V, C::PublicKey>,
    task: OptionFuture<Handle<VerifiedLogs<V, C>>>,
    result: Option<VerifiedLogs<V, C>>,
}

impl<V: BlsVariant, C: Signer> Verification<V, C> {
    /// Creates an idle verifier targeting `target`.
    fn new(target: PendingLogs<V, C::PublicKey>) -> Self {
        Self {
            target,
            task: None.into(),
            result: None,
        }
    }

    /// Selects the latest desired log view without interrupting active work.
    ///
    /// Returns whether the target changed. Any completed result for the old
    /// target is discarded immediately. On change, the caller must also
    /// invalidate assembled artifacts and resolve old-target waiters.
    fn retarget(&mut self, target: PendingLogs<V, C::PublicKey>) -> bool {
        if self.target == target {
            return false;
        }

        self.target = target;
        self.result = None;
        true
    }

    /// Installs the sole active task for the current target.
    fn start(&mut self, task: Handle<VerifiedLogs<V, C>>) {
        assert!(self.task.is_none(), "verification task already running");
        assert!(self.result.is_none(), "verification result already available");
        self.task = Some(task).into();
    }

    /// Accepts `result` only when it matches the latest target.
    ///
    /// Returns false for obsolete work so the caller can start the latest
    /// target after the active CPU task has exited.
    fn complete(&mut self, result: VerifiedLogs<V, C>) -> bool {
        self.task = None.into();
        if result.logs != self.target {
            return false;
        }

        self.result = Some(result);
        true
    }

    /// Returns the ceremony result only for the requested exact log view.
    ///
    /// The outer `None` means no matching verification has completed;
    /// `Some(None)` means verification completed and the ceremony failed.
    fn ready(
        &self,
        logs: &PendingLogs<V, C::PublicKey>,
    ) -> Option<&Option<Ceremony<V, C>>> {
        self.result
            .as_ref()
            .filter(|result| result.logs == *logs)
            .map(|result| &result.ceremony)
    }
}

impl<V: BlsVariant, C: Signer> Drop for Verification<V, C> {
    fn drop(&mut self) {
        // Dropping a runtime handle does not stop its task. Abort explicitly so
        // work that has not begun polling cannot outlive the inclusion phase.
        // Synchronous crypto already executing in a poll may still finish.
        if let Some(task) = self.task.as_ref() {
            task.abort();
        }
    }
}

/// A fully assembled artifact cached for one exact verified log view.
///
/// The cache avoids repeating participant-policy and secret-store lookups for
/// competing boundary-block requests. It is scoped to one inclusion phase,
/// never acts as recovery state, and may contain `None` for failed one-shot DKG.
struct CachedArtifact<V: BlsVariant, C: Signer> {
    logs: PendingLogs<V, C::PublicKey>,
    artifact: Option<Artifact<V, C>>,
}

/// Bounds used to extract non-finalized dealer logs from block ancestry.
struct PendingLogScan<'a, V: BlsVariant, P> {
    epoch: Epoch,
    info: &'a Info<V, P>,
    epocher: FixedEpocher,
    finalized_tip: Option<Height>,
    final_height: Height,
}

/// An owned, side-effect-free snapshot for dealer-log verification.
///
/// The task contains no store, provider, registrar, or metrics handle. It can
/// therefore be abandoned by a crash or superseded without exposing partial
/// protocol state.
struct VerificationTask<V, C, T>
where
    V: BlsVariant,
    C: Signer,
    T: Strategy,
{
    epoch: Epoch,
    player: Option<Player<V, C>>,
    logs: Logs<V, C::PublicKey, N3f1>,
    strategy: T,
}

impl<V, C, T> VerificationTask<V, C, T>
where
    V: BlsVariant,
    C: Signer,
    T: Strategy,
{
    /// Verifies and selects dealer logs, deriving the public output and local
    /// share when this node is a player.
    ///
    /// Failure is represented by `None` and assembled into the protocol's DKG
    /// or reshare failure response later on the actor task.
    fn run<E, BV>(self, mut context: E) -> Option<Ceremony<V, C>>
    where
        E: CryptoRng,
        BV: BatchVerifier<PublicKey = C::PublicKey>,
    {
        if let Some(player) = self.player {
            match player.finalize::<N3f1, BV>(&mut context, self.logs, &self.strategy) {
                Ok((output, share)) => Some(Ceremony {
                    output,
                    share: Some(share),
                }),
                Err(error) => {
                    warn!(epoch = ?self.epoch, ?error, "failed to finalize player");
                    None
                }
            }
        } else {
            match observe::<_, _, N3f1, BV>(&mut context, self.logs, &self.strategy) {
                Ok(output) => Some(Ceremony {
                    output,
                    share: None,
                }),
                Err(error) => {
                    warn!(epoch = ?self.epoch, ?error, "failed to observe reshare outcome");
                    None
                }
            }
        }
    }
}

/// Rejects participant sets that cannot be embedded in a valid future epoch.
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
    ///
    /// Verification tasks and assembled artifacts are intentionally ephemeral.
    /// Finalized dealer logs are journaled before their reporter is acknowledged,
    /// and a restart reconstructs the boundary artifact from canonical blocks and
    /// replayed storage rather than trusting an interrupted task or cache.
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
        let initial_logs = store.logs(epoch);
        let mut verification = Verification::new(initial_logs);
        self.start_verification(&mut verification, epoch, info, store);
        let mut artifact_waiters: ArtifactWaiters<V, C> = Vec::new();
        select_loop! {
            self.context,
            on_stopped => {
                debug!("shutdown signal received");
                return ControlFlow::Break(());
            },
            completed = &mut verification.task => {
                let completed = completed.expect("verification task failed");
                if !verification.complete(completed) {
                    self.start_verification(&mut verification, epoch, info, store);
                    continue;
                }
                if artifact_waiters.is_empty() {
                    continue;
                }
                let logs = verification.target.clone();
                let ceremony = verification
                    .ready(&logs)
                    .expect("completed verification must have a result")
                    .clone();
                let artifact = self
                    .artifact(
                        epoch,
                        store,
                        logs,
                        &ceremony,
                        &mut next_players,
                        &mut artifact_cache,
                    )
                    .await;
                let result = self.artifact_response(&artifact);
                for waiter in artifact_waiters.drain(..) {
                    let _ = waiter.send_lossy(result.clone());
                }
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
                        let mut log_map = store.logs(epoch);
                        for (dealer, log) in pending_logs {
                            log_map.entry(dealer).or_insert(log);
                        }
                        if self.replace_verification(
                            &mut verification,
                            epoch,
                            info,
                            store,
                            log_map.clone(),
                        ) {
                            artifact_cache = None;
                            for waiter in artifact_waiters.drain(..) {
                                let _ = waiter.send_lossy(EpochInfoResponse::Pending);
                            }
                        }

                        if let Some(ceremony) = verification.ready(&log_map).cloned() {
                            let artifact = self
                                .artifact(
                                    epoch,
                                    store,
                                    log_map,
                                    &ceremony,
                                    &mut next_players,
                                    &mut artifact_cache,
                                )
                                .await;
                            let _ = response.send_lossy(self.artifact_response(&artifact));
                            return;
                        }
                        artifact_waiters.retain(|waiter| !waiter.is_closed());
                        artifact_waiters.push(response);
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
                        let canonical_logs = store.logs(epoch);
                        if self.replace_verification(
                            &mut verification,
                            epoch,
                            info,
                            store,
                            canonical_logs.clone(),
                        ) {
                            artifact_cache = None;
                            for waiter in artifact_waiters.drain(..) {
                                let _ = waiter.send_lossy(EpochInfoResponse::Pending);
                            }
                        }
                        if done {
                            while verification.ready(&canonical_logs).is_none() {
                                let task = verification
                                    .task
                                    .take()
                                    .expect("pending verification must have a task");
                                let completed = task.await.expect("verification task failed");
                                if !verification.complete(completed) {
                                    self.start_verification(
                                        &mut verification,
                                        epoch,
                                        info,
                                        store,
                                    );
                                }
                            }
                            let ceremony = verification
                                .ready(&canonical_logs)
                                .expect("final verification must be cached")
                                .clone();
                            let artifact = self
                                .artifact(
                                    epoch,
                                    store,
                                    canonical_logs,
                                    &ceremony,
                                    &mut next_players,
                                    &mut artifact_cache,
                                )
                                .await;
                            let result = self.artifact_response(&artifact);
                            for waiter in artifact_waiters.drain(..) {
                                let _ = waiter.send_lossy(result.clone());
                            }
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

    /// Retargets asynchronous verification to an exact effective log set.
    ///
    /// A running verification is never overlapped with its replacement. The
    /// active task finishes first, after which only the latest target is run.
    /// A true return value requires the caller to invalidate the assembled
    /// artifact and resolve waiters for the old target with `Pending`.
    fn replace_verification(
        &mut self,
        verification: &mut Verification<V, C>,
        epoch: Epoch,
        info: &Info<V, C::PublicKey>,
        store: &Store<E, SS, V, C::PublicKey>,
        log_map: PendingLogs<V, C::PublicKey>,
    ) -> bool {
        if !verification.retarget(log_map) {
            return false;
        }

        if verification.task.is_none() {
            self.start_verification(verification, epoch, info, store);
        }
        true
    }

    /// Starts the current verification target on the shared pool.
    ///
    /// The copied log map tags completion so obsolete results can be rejected
    /// after retargeting. [`Verification::start`] enforces that no other task or
    /// completed result is installed.
    fn start_verification(
        &mut self,
        verification: &mut Verification<V, C>,
        epoch: Epoch,
        info: &Info<V, C::PublicKey>,
        store: &Store<E, SS, V, C::PublicKey>,
    ) {
        let log_map = verification.target.clone();
        let task = self.verification_task(epoch, info, store, &log_map);
        let handle = self
            .context
            .child("verification")
            .shared(true)
            .spawn(move |context| async move {
                let ceremony = task.run::<E, BV>(context);
                VerifiedLogs {
                    logs: log_map,
                    ceremony,
                }
            });
        verification.start(handle);
    }

    /// Builds the owned inputs needed to verify one effective dealer-log set.
    ///
    /// Player state is reconstructed before spawning because it reads from the
    /// actor-owned store. The returned task owns everything used by the shared
    /// CPU worker and cannot mutate durable state or metrics.
    fn verification_task(
        &mut self,
        epoch: Epoch,
        info: &Info<V, C::PublicKey>,
        store: &Store<E, SS, V, C::PublicKey>,
        log_map: &PendingLogs<V, C::PublicKey>,
    ) -> VerificationTask<V, C, T> {
        let current = store.current();
        let dkg_participants = if current.is_none() {
            self.dkg_participants()
        } else {
            None
        };
        assert!(
            current.is_some() || dkg_participants.is_some(),
            "inclusion must have current epoch or DKG participants"
        );

        let mut logs = Logs::<_, _, N3f1>::new(info.clone());
        for (dealer, log) in log_map {
            let dealer = dealer.clone();
            let log = log.clone();
            logs.record(dealer, log);
        }

        let public_key = self.signer.public_key();
        let players = current
            .as_ref()
            .map(|current| current.players.clone())
            .or(dkg_participants)
            .expect("current epoch or DKG mode must provide players");
        let player = players.position(&public_key).and_then(|_| {
            store.create_player_with_logs::<C, N3f1>(
                epoch,
                self.signer.clone(),
                info.clone(),
                log_map,
            )
        });

        VerificationTask {
            epoch,
            player,
            logs,
            strategy: self.strategy.clone(),
        }
    }

    /// Assembles final epoch information from an already verified ceremony.
    ///
    /// Participant policy and retained-share storage are consulted here, while
    /// building or finalizing the boundary block, rather than by speculative
    /// verification. Results are cached only for the exact effective log set.
    /// A failed reshare carries the prior output and retained local share into a
    /// failure artifact; a failed one-shot DKG produces no artifact.
    async fn artifact(
        &mut self,
        epoch: Epoch,
        store: &mut Store<E, SS, V, C::PublicKey>,
        log_map: PendingLogs<V, C::PublicKey>,
        ceremony: &Option<Ceremony<V, C>>,
        next_players: &mut Option<Set<C::PublicKey>>,
        cache: &mut Option<CachedArtifact<V, C>>,
    ) -> Option<Artifact<V, C>> {
        if let Some(cached) = cache.as_ref().filter(|cached| cached.logs == log_map) {
            return cached.artifact.clone();
        }

        let current = store.current();
        let dkg_participants = if current.is_none() {
            self.dkg_participants()
        } else {
            None
        };
        assert!(
            current.is_some() || dkg_participants.is_some(),
            "inclusion must have current epoch or DKG participants"
        );

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
            Set::default()
        };

        let artifact = match (ceremony, current) {
            (Some(ceremony), Some(current)) => Some(Artifact {
                info: EpochInfo {
                    outcome: EpochOutcome::Success,
                    epoch: epoch.next(),
                    output: ceremony.output.clone(),
                    players: current.next_players,
                    next_players: future_players,
                },
                share: ceremony.share.clone(),
            }),
            (Some(ceremony), None) => {
                let share = ceremony
                    .share
                    .clone()
                    .expect("DKG participant must receive a share");
                Some(Artifact {
                    info: EpochInfo {
                        outcome: EpochOutcome::Success,
                        epoch,
                        output: ceremony.output.clone(),
                        players: dkg_participants
                            .expect("DKG mode must provide participants"),
                        next_players: future_players,
                    },
                    share: Some(share),
                })
            }
            (None, Some(current)) => {
                let public_key = self.signer.public_key();
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
            (None, None) => None,
        };

        *cache = Some(CachedArtifact {
            logs: log_map,
            artifact: artifact.clone(),
        });
        artifact
    }

    /// Maps local reconstruction into the application response contract.
    ///
    /// A failed one-shot DKG legitimately produces no boundary artifact. A
    /// continuous reshare must always carry an artifact, including one that
    /// records ceremony failure, so local absence is unavailable there.
    fn artifact_response(&self, artifact: &Option<Artifact<V, C>>) -> EpochInfoResponse<V, C> {
        match artifact {
            Some(artifact) => {
                EpochInfoResponse::Available(Some(Payload::EpochInfo(artifact.info.clone())))
            }
            None if matches!(self.mode, Mode::Dkg { .. }) => EpochInfoResponse::Available(None),
            None => EpochInfoResponse::Unavailable,
        }
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
        bls12381::{
            dkg::feldman_desmedt::Dealer as CryptoDealer,
            primitives::sharing::Mode as SharingMode,
        },
        ed25519::{PrivateKey, PublicKey},
    };
    use commonware_runtime::{Runner, Spawner, Supervisor, deterministic};
    use commonware_utils::{N3f1, NZU32, NZU64, channel::oneshot, ordered::Set, test_rng};
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

    fn dealer_logs(index: usize) -> PendingLogs<TestBlsVariant, PublicKey> {
        let info = info();
        let signer = signers()[index].clone();
        let (dealer, _, _) =
            CryptoDealer::start::<N3f1>(test_rng(), info.clone(), signer, None)
                .expect("dealer should start");
        let signed = dealer.finalize::<N3f1>();
        let (public_key, log) = signed.check(&info).expect("dealer log should be valid");
        BTreeMap::from([(public_key, log)])
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

    #[test]
    fn verification_keeps_only_latest_target() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let first = dealer_logs(0);
            let second = dealer_logs(1);
            let latest = dealer_logs(2);
            let completed_logs = first.clone();
            let (release_tx, release_rx) = oneshot::channel();
            let task = context.child("first").spawn(|_| async move {
                release_rx.await.expect("task should be released");
                VerifiedLogs::<TestBlsVariant, PrivateKey> {
                    logs: completed_logs,
                    ceremony: None,
                }
            });
            let mut verification = Verification::new(first);
            verification.start(task);

            assert!(verification.retarget(second));
            assert!(verification.retarget(latest.clone()));
            release_tx.send(()).expect("task should still be running");
            let completed = verification
                .task
                .take()
                .expect("task should be present")
                .await
                .expect("task should complete");

            assert!(!verification.complete(completed));
            assert_eq!(verification.target, latest);
            assert!(verification.task.is_none());
            assert!(verification.result.is_none());
        });
    }

    #[test]
    fn verification_reuses_active_target_after_retargeting() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let active = dealer_logs(0);
            let replacement = dealer_logs(1);
            let completed_logs = active.clone();
            let (release_tx, release_rx) = oneshot::channel();
            let task = context.child("active").spawn(|_| async move {
                release_rx.await.expect("task should be released");
                VerifiedLogs::<TestBlsVariant, PrivateKey> {
                    logs: completed_logs,
                    ceremony: None,
                }
            });
            let mut verification = Verification::new(active.clone());
            verification.start(task);

            assert!(verification.retarget(replacement));
            assert!(verification.retarget(active.clone()));
            release_tx.send(()).expect("task should still be running");
            let completed = verification
                .task
                .take()
                .expect("task should be present")
                .await
                .expect("task should complete");

            assert!(verification.complete(completed));
            assert!(verification.ready(&active).is_some());
        });
    }

}
