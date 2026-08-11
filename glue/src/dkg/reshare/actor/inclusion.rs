use crate::dkg::{
    ParticipantsProvider, Registrar, ReshareBlock, SecretStore,
    network::{Directory, Manager},
    reshare::{
        Actor, EpochInfoResponse, Message,
        actor::Mode,
        metrics::Phase,
        store::{Dealer, Player, Store},
    },
    types::{EpochInfo, EpochOutcome, Participants, Payload},
};
use commonware_consensus::{
    marshal::{ancestry::Ancestry as _, core::Variant as MarshalVariant},
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
use commonware_p2p::Blocker;
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
use futures::{Stream, StreamExt};
use rand_core::CryptoRng;
use std::{
    collections::{BTreeMap, VecDeque},
    num::{NonZeroU32, NonZeroU64},
    ops::ControlFlow,
    pin::Pin,
    sync::Arc,
};
use tracing::{Instrument as _, Span, debug, info, info_span, warn};

/// The exact effective dealer-log view used for one verification.
type PendingLogs<V, P> = BTreeMap<P, DealerLog<V, P>>;

/// Type-erased ancestry retained while a boundary request waits for verification.
type ErasedAncestry<B> = Pin<Box<dyn Stream<Item = Arc<B>> + Send>>;

/// Shared ownership of one log view across verification and artifact assembly.
type LogView<V, P> = Arc<PendingLogs<V, P>>;

/// An unmaterialized boundary-artifact request anchored to its boundary parent.
struct ArtifactRequest<B, V, C>
where
    B: ReshareBlock<Variant = V, Signer = C>,
    V: BlsVariant,
    C: Signer,
{
    parent: B::Digest,
    span: Span,
    ancestry: ErasedAncestry<B>,
    response: oneshot::Sender<EpochInfoResponse<V, C, B::Directory>>,
}

/// Lazy artifact requests in admission order.
///
/// A parent digest commits the complete ancestry that contributes pending
/// dealer logs. Keeping the streams lazy prevents queued views from expanding
/// into full dealer-log maps while the sole verifier is occupied.
struct ArtifactRequests<B, V, C>
where
    B: ReshareBlock<Variant = V, Signer = C>,
    V: BlsVariant,
    C: Signer,
{
    inner: VecDeque<ArtifactRequest<B, V, C>>,
}

impl<B, V, C> Default for ArtifactRequests<B, V, C>
where
    B: ReshareBlock<Variant = V, Signer = C>,
    V: BlsVariant,
    C: Signer,
{
    fn default() -> Self {
        Self {
            inner: VecDeque::new(),
        }
    }
}

impl<B, V, C> ArtifactRequests<B, V, C>
where
    B: ReshareBlock<Variant = V, Signer = C>,
    V: BlsVariant,
    C: Signer,
{
    /// Retains a request without consuming its ancestry stream.
    fn push(
        &mut self,
        parent: B::Digest,
        span: Span,
        ancestry: ErasedAncestry<B>,
        response: oneshot::Sender<EpochInfoResponse<V, C, B::Directory>>,
    ) {
        self.inner.push_back(ArtifactRequest {
            parent,
            span,
            ancestry,
            response,
        });
    }

    /// Selects one live request without materializing any other view.
    fn pop(&mut self) -> Option<ArtifactRequest<B, V, C>> {
        while let Some(request) = self.inner.pop_front() {
            if !request.response.is_closed() {
                return Some(request);
            }
        }
        None
    }

    /// Drains the phase-ending queue and returns live canonical responses.
    fn drain_canonical(
        &mut self,
        parent: &B::Digest,
    ) -> Vec<oneshot::Sender<EpochInfoResponse<V, C, B::Directory>>> {
        self.inner
            .drain(..)
            .filter_map(|request| {
                (request.parent == *parent && !request.response.is_closed())
                    .then_some(request.response)
            })
            .collect()
    }
}

/// The sole materialized speculative request.
struct ArtifactWaiter<B, V, C>
where
    B: ReshareBlock<Variant = V, Signer = C>,
    V: BlsVariant,
    C: Signer,
{
    logs: LogView<V, C::PublicKey>,
    response: oneshot::Sender<EpochInfoResponse<V, C, B::Directory>>,
}

/// A locally reconstructed boundary artifact and this node's matching share.
///
/// This value is phase-local. It becomes durable only after the same
/// [`EpochInfo`] appears in a finalized boundary block.
#[derive(Clone)]
struct Artifact<V: BlsVariant, C: Signer, D: Directory<C::PublicKey>> {
    info: EpochInfo<V, C::PublicKey, D>,
    share: Option<Share>,
}

/// The output of successful dealer-log verification.
///
/// `share` is present when this node participated as a player and absent when
/// it only observed the public ceremony.
struct Ceremony<V: BlsVariant, C: Signer> {
    output: Output<V, C::PublicKey>,
    share: Option<Share>,
}

/// A verification result bound to the complete log view that produced it.
///
/// An absent `ceremony` means the log view proves that the ceremony failed.
struct VerifiedLogs<V: BlsVariant, C: Signer> {
    logs: LogView<V, C::PublicKey>,
    ceremony: Option<Ceremony<V, C>>,
}

/// Tracks verification for one effective dealer-log set.
///
/// One exact completed result is retained independently of the active task so
/// canonical work cannot be displaced by a later speculative completion. All
/// state is reconstructable after a crash; no speculative result is persisted.
struct Verification<V: BlsVariant, C: Signer> {
    task: OptionFuture<Handle<VerifiedLogs<V, C>>>,
    result: Option<VerifiedLogs<V, C>>,
}

impl<V: BlsVariant, C: Signer> Default for Verification<V, C> {
    fn default() -> Self {
        Self {
            task: None.into(),
            result: None,
        }
    }
}

impl<V: BlsVariant, C: Signer> Verification<V, C> {
    /// Installs the sole active task for the selected effective log view.
    fn start(&mut self, task: Handle<VerifiedLogs<V, C>>) {
        assert!(self.task.is_none(), "verification task already running");
        self.task = Some(task).into();
    }

    /// Marks the active task complete while its tagged result is processed.
    fn finish(&mut self) {
        self.task = None.into();
    }

    /// Retains one tagged result, preferring the current canonical view.
    fn retain(&mut self, result: VerifiedLogs<V, C>, canonical: &PendingLogs<V, C::PublicKey>) {
        let retained_is_canonical = self
            .result
            .as_ref()
            .is_some_and(|retained| retained.logs.as_ref() == canonical);
        if result.logs.as_ref() == canonical || !retained_is_canonical {
            self.result = Some(result);
        }
    }

    /// Returns the ceremony result only for the requested exact log view.
    ///
    /// The outer `None` means no matching verification has completed;
    /// `Some(None)` means verification completed and the ceremony failed.
    fn ready(&self, logs: &PendingLogs<V, C::PublicKey>) -> Option<Option<&Ceremony<V, C>>> {
        self.result
            .as_ref()
            .filter(|result| result.logs.as_ref() == logs)
            .map(|result| result.ceremony.as_ref())
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
struct CachedArtifact<V: BlsVariant, C: Signer, D: Directory<C::PublicKey>> {
    logs: LogView<V, C::PublicKey>,
    artifact: Option<Artifact<V, C, D>>,
}

struct ArtifactCache<V: BlsVariant, C: Signer, D: Directory<C::PublicKey>> {
    next_players: Option<Set<C::PublicKey>>,
    artifact: Option<CachedArtifact<V, C, D>>,
}

impl<V: BlsVariant, C: Signer, D: Directory<C::PublicKey>> Default for ArtifactCache<V, C, D> {
    fn default() -> Self {
        Self {
            next_players: None,
            artifact: None,
        }
    }
}

impl<V: BlsVariant, C: Signer, D: Directory<C::PublicKey>> ArtifactCache<V, C, D> {
    /// Returns the cached artifact for an exact log view.
    fn get(&self, logs: &PendingLogs<V, C::PublicKey>) -> Option<&CachedArtifact<V, C, D>> {
        self.artifact
            .as_ref()
            .filter(|cached| cached.logs.as_ref() == logs)
    }
}

/// Phase-local artifact state with lazy queued requests, at most one active
/// materialized view, and one-entry verification and artifact caches.
struct ArtifactWork<B, V, C>
where
    B: ReshareBlock<Variant = V, Signer = C>,
    V: BlsVariant,
    C: Signer,
{
    requests: ArtifactRequests<B, V, C>,
    waiter: Option<ArtifactWaiter<B, V, C>>,
    verification: Verification<V, C>,
    artifacts: ArtifactCache<V, C, B::Directory>,
}

impl<B, V, C> Default for ArtifactWork<B, V, C>
where
    B: ReshareBlock<Variant = V, Signer = C>,
    V: BlsVariant,
    C: Signer,
{
    fn default() -> Self {
        Self {
            requests: ArtifactRequests::default(),
            waiter: None,
            verification: Verification::default(),
            artifacts: ArtifactCache::default(),
        }
    }
}

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
/// therefore be aborted with the inclusion phase without exposing partial
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
    parent: B::Digest,
    mut ancestry: ErasedAncestry<B>,
    mut shutdown: signal::Signal,
    response: &mut oneshot::Sender<EpochInfoResponse<V, C, B::Directory>>,
) -> Option<PendingLogs<V, C::PublicKey>>
where
    B: ReshareBlock<Variant = V, Signer = C>,
    V: BlsVariant,
    C: Signer,
{
    let midpoint = scan
        .epocher
        .midpoint(scan.epoch)
        .expect("epocher must know epoch midpoint");
    let first_pending = scan
        .finalized_tip
        .filter(|tip| *tip >= midpoint)
        .map_or(midpoint, Height::next);
    let Some(mut expected_height) = scan.final_height.previous() else {
        return Some(PendingLogs::new());
    };
    if first_pending > expected_height {
        return Some(PendingLogs::new());
    }

    // Walk backward from the boundary parent through every inclusion block not
    // already reflected in durable storage. The expected height and digest
    // prove that all yielded blocks belong to one contiguous chain.
    let mut expected_digest = parent;
    let mut allow_final = true;
    let mut blocks = Vec::new();
    loop {
        let block = select! {
            _ = &mut shutdown => return None,
            _ = response.closed() => return None,
            block = ancestry.next() => block,
        };
        let Some(block) = block else {
            warn!(
                epoch = ?scan.epoch,
                ?expected_height,
                "epoch info ancestry ended before covering pending dealer logs"
            );
            return None;
        };
        let height = block.height();

        // Verification includes the final block itself, while proposal starts
        // at its parent. Both forms must commit to the same parent chain.
        if allow_final && height == scan.final_height && block.parent() == expected_digest {
            allow_final = false;
            continue;
        }

        // The pending window is valid only as a height-by-height digest chain.
        // Rejecting its first mismatch prevents omitted or substituted logs.
        allow_final = false;
        if height != expected_height || block.digest() != expected_digest {
            warn!(
                epoch = ?scan.epoch,
                ?height,
                ?expected_height,
                "epoch info ancestry is not contiguous"
            );
            return None;
        }

        expected_digest = block.parent();
        blocks.push(block);
        if height == first_pending {
            break;
        }
        expected_height = height
            .previous()
            .expect("pending dealer-log ancestry must remain above genesis");
    }

    // Authenticate the proven segment in forward chain order so each dealer's
    // earliest valid log wins, matching durable storage's first-log rule.
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
    (!response.is_closed()).then_some(logs)
}

impl<E, B, V, C, M, X, P, SS, T, BV, S, MV, R, A> Actor<E, B, V, C, M, X, P, SS, T, BV, S, MV, R, A>
where
    E: Spawner + CryptoRng + Metrics + BufferPooler + Clock + RuntimeStorage,
    B: ReshareBlock<Variant = V, Signer = C>,
    V: BlsVariant,
    C: Signer,
    M: Manager<PublicKey = C::PublicKey, Directory = B::Directory>,
    X: Blocker<PublicKey = C::PublicKey>,
    P: ParticipantsProvider<PublicKey = C::PublicKey, Directory = B::Directory>,
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
    /// replayed storage; interrupted tasks and caches are never recovery state.
    pub(super) async fn inclusion(
        &mut self,
        epoch: Epoch,
        info: &Info<V, C::PublicKey>,
        store: &mut Store<E, SS, V, C::PublicKey, B::Directory>,
        mut dealer: Option<&mut Dealer<V, C>>,
    ) -> ControlFlow<()> {
        self.metrics.set_phase(Phase::Inclusion);

        if let Some(dealer) = dealer.as_deref_mut() {
            dealer.finalize::<N3f1>();
        }

        // The loop owns one outstanding log reservation and at most one
        // materialized artifact request. The finalized tip bounds ancestry scans
        // to blocks not yet reflected in storage. Queued ancestries remain lazy
        // until the sole verifier is free.
        let mut served_at: Option<Height> = None;
        let mut finalized_tip = self.marshal.get_processed_height().await;
        let mut work = ArtifactWork::default();
        select_loop! {
            self.context,
            on_stopped => {
                debug!("shutdown signal received");
                return ControlFlow::Break(());
            },
            completed = &mut work.verification.task => {
                let completed = completed.expect("verification task failed");
                self.complete_verification(epoch, store, &mut work, completed)
                    .await;
                self.advance_artifact_requests(
                    epoch,
                    info,
                    finalized_tip,
                    store,
                    &mut work,
                )
                .await;
            },
            Some(message) = self.mailbox.recv() else {
                debug!("mailbox closed, shutting down");
                return ControlFlow::Break(());
            } => {
                match message {
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
                    response,
                } => {
                    if !response.is_closed() {
                        // Proposal ancestry starts at the final block's parent,
                        // while verification ancestry starts at the final block.
                        // Normalize both to the parent digest that commits the
                        // complete pre-boundary view.
                        let final_height = self
                            .epocher
                            .last(epoch)
                            .expect("epocher must know final epoch height");
                        let Some(head) = ancestry.peek() else {
                            let _ = response.send_lossy(EpochInfoResponse::Unavailable);
                            continue;
                        };
                        let parent = if head.height() == final_height {
                            Some(head.parent())
                        } else if final_height.previous() == Some(head.height()) {
                            Some(head.digest())
                        } else {
                            None
                        };
                        let Some(parent) = parent else {
                            let _ = response.send_lossy(EpochInfoResponse::Unavailable);
                            continue;
                        };
                        work.requests
                            .push(parent, span, Box::pin(ancestry), response);
                        self.advance_artifact_requests(
                            epoch,
                            info,
                            finalized_tip,
                            store,
                            &mut work,
                        )
                        .await;
                    }
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
                            let canonical_logs = Arc::new(store.logs(epoch));
                            let cached = work
                                .artifacts
                                .get(canonical_logs.as_ref())
                                .map(|cached| cached.artifact.clone());

                            // A verification admitted before finalization owns a
                            // stable application verdict. Publish that bounded
                            // work before reconstructing the canonical artifact.
                            if work.verification.task.is_some() {
                                let completed = (&mut work.verification.task)
                                    .await
                                    .expect("verification task failed");
                                self.complete_verification(epoch, store, &mut work, completed)
                                    .await;
                            }

                            let cached = cached.or_else(|| {
                                work.artifacts
                                    .get(canonical_logs.as_ref())
                                    .map(|cached| cached.artifact.clone())
                            });
                            let artifact = if let Some(cached) = cached {
                                cached
                            } else {
                                if work
                                    .verification
                                    .ready(canonical_logs.as_ref())
                                    .is_none()
                                {
                                    self.start_verification(
                                        &mut work.verification,
                                        epoch,
                                        info,
                                        store,
                                        canonical_logs.clone(),
                                    );
                                    let completed = (&mut work.verification.task)
                                        .await
                                        .expect("verification task failed");
                                    work.verification.finish();
                                    assert_eq!(
                                        completed.logs.as_ref(),
                                        canonical_logs.as_ref(),
                                        "canonical verification returned a different view"
                                    );
                                    work.verification
                                        .retain(completed, canonical_logs.as_ref());
                                }
                                let ceremony = work
                                    .verification
                                    .ready(canonical_logs.as_ref())
                                    .expect("final verification must be cached");
                                self.artifact(
                                    epoch,
                                    store,
                                    canonical_logs.clone(),
                                    ceremony,
                                    &mut work.artifacts,
                                )
                                .await
                            };
                            let responses = work.requests.drain_canonical(&block.parent());
                            let result = self.artifact_response(artifact.as_ref());
                            for response in responses {
                                let _ = response.send_lossy(result.clone());
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
                }
            },
        };

        ControlFlow::Break(())
    }

    /// Advances admitted requests until one starts verification or none remain.
    async fn advance_artifact_requests(
        &mut self,
        epoch: Epoch,
        info: &Info<V, C::PublicKey>,
        finalized_tip: Option<Height>,
        store: &mut Store<E, SS, V, C::PublicKey, B::Directory>,
        work: &mut ArtifactWork<B, V, C>,
    ) {
        while work.verification.task.is_none() {
            let Some(request) = work.requests.pop() else {
                return;
            };
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
            self.start_artifact_request(scan, store, request, work)
                .await;
        }
    }

    /// Persist a finalized dealer log from an included block.
    ///
    /// Invalid logs are ignored because the block has already passed
    /// application verification. The finalized reporter path is the only place
    /// where observed dealer logs become durable state.
    pub(super) async fn observe_dealer_log(
        public_key: &C::PublicKey,
        info: &Info<V, C::PublicKey>,
        store: &mut Store<E, SS, V, C::PublicKey, B::Directory>,
        epoch: Epoch,
        dealer: Option<&mut Dealer<V, C>>,
        payload: Option<Payload<V, C, B::Directory>>,
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

    /// Materializes and starts verification for one lazy ancestry request.
    async fn start_artifact_request(
        &mut self,
        scan: PendingLogScan<'_, V, C::PublicKey>,
        store: &mut Store<E, SS, V, C::PublicKey, B::Directory>,
        mut request: ArtifactRequest<B, V, C>,
        work: &mut ArtifactWork<B, V, C>,
    ) {
        if request.response.is_closed() {
            return;
        }
        let process = info_span!(
            parent: &request.span,
            "dkg.reshare.actor.inclusion.epoch_info"
        );
        async {
            let epoch = scan.epoch;
            let info = scan.info;

            // The request remains ancestry-bound until its complete unfinalized
            // segment is available. An incomplete or canceled scan cannot
            // produce a reusable log view.
            let Some(pending) = pending_logs(
                scan,
                request.parent,
                request.ancestry,
                self.context.stopped(),
                &mut request.response,
            )
            .await
            else {
                let _ = request.response.send_lossy(EpochInfoResponse::Unavailable);
                return;
            };

            // Finalized logs are authoritative. Pending ancestry may fill only
            // a dealer slot that durable storage has not already claimed.
            let mut logs = store.logs(epoch);
            for (dealer, log) in pending {
                logs.entry(dealer).or_insert(log);
            }
            let logs = Arc::new(logs);

            // Reuse is keyed by the exact effective log view. An assembled
            // artifact can answer immediately; a verified ceremony still needs
            // phase-local participant and directory assembly.
            if let Some(cached) = work.artifacts.get(logs.as_ref()) {
                let artifact = cached.artifact.clone();
                let _ = request
                    .response
                    .send_lossy(self.artifact_response(artifact.as_ref()));
                return;
            }
            if let Some(ceremony) = work.verification.ready(logs.as_ref()) {
                let artifact = self
                    .artifact(epoch, store, logs.clone(), ceremony, &mut work.artifacts)
                    .await;
                let _ = request
                    .response
                    .send_lossy(self.artifact_response(artifact.as_ref()));
                return;
            }

            // A cache miss transfers the response to the sole active waiter.
            // Sharing the log view tags the waiter and task with the same input.
            assert!(work.waiter.is_none(), "materialized waiter already active");
            work.waiter = Some(ArtifactWaiter {
                logs: logs.clone(),
                response: request.response,
            });
            self.start_verification(&mut work.verification, epoch, info, store, logs);
        }
        .instrument(process)
        .await;
    }

    /// Publishes one completed verification to its exact ancestry requests.
    async fn complete_verification(
        &mut self,
        epoch: Epoch,
        store: &mut Store<E, SS, V, C::PublicKey, B::Directory>,
        work: &mut ArtifactWork<B, V, C>,
        completed: VerifiedLogs<V, C>,
    ) {
        // Every speculative task has exactly one materialized waiter tagged with
        // the same log view.
        work.verification.finish();
        let waiter = work
            .waiter
            .take()
            .expect("completed speculative verification must own a waiter");
        assert_eq!(
            waiter.logs.as_ref(),
            completed.logs.as_ref(),
            "verification completed for a different materialized view"
        );

        // Requester cancellation suppresses speculative artifact assembly.
        // Verification retention is independent so a canonical result cannot be
        // displaced.
        if !waiter.response.is_closed() {
            let artifact = self
                .artifact(
                    epoch,
                    store,
                    completed.logs.clone(),
                    completed.ceremony.as_ref(),
                    &mut work.artifacts,
                )
                .await;
            let _ = waiter
                .response
                .send_lossy(self.artifact_response(artifact.as_ref()));
        }

        let canonical_logs = store.logs(epoch);
        work.verification.retain(completed, &canonical_logs);
    }

    /// Starts one exact verification target on the shared pool.
    ///
    /// The shared log map tags completion for exact reuse without copying the
    /// complete dealer-log view between phase-local owners.
    fn start_verification(
        &mut self,
        verification: &mut Verification<V, C>,
        epoch: Epoch,
        info: &Info<V, C::PublicKey>,
        store: &Store<E, SS, V, C::PublicKey, B::Directory>,
        log_map: LogView<V, C::PublicKey>,
    ) {
        assert!(
            verification.ready(log_map.as_ref()).is_none(),
            "selected verification result already available"
        );
        let task = self.verification_task(epoch, info, store, log_map.as_ref());
        let handle =
            self.context
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
        store: &Store<E, SS, V, C::PublicKey, B::Directory>,
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
            logs.record(dealer.clone(), log.clone());
        }

        let public_key = self.signer.public_key();
        let players = current
            .as_ref()
            .map(|current| &current.players)
            .or(dkg_participants.as_ref())
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
    /// Participant policy, transport directory, and retained-share storage are
    /// consulted here, while building or finalizing the boundary block, rather
    /// than by speculative verification. Results are cached only for the exact
    /// effective log set. A failed reshare carries the prior output and retained
    /// local share into a failure artifact; a failed one-shot DKG produces no
    /// artifact.
    async fn artifact(
        &mut self,
        epoch: Epoch,
        store: &mut Store<E, SS, V, C::PublicKey, B::Directory>,
        log_map: LogView<V, C::PublicKey>,
        ceremony: Option<&Ceremony<V, C>>,
        artifacts: &mut ArtifactCache<V, C, B::Directory>,
    ) -> Option<Artifact<V, C, B::Directory>> {
        if let Some(cached) = artifacts.get(log_map.as_ref()) {
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

        let next_players = if current.is_some() {
            match &mut artifacts.next_players {
                Some(players) => players.clone(),
                None => {
                    // The provider contract requires this value to remain
                    // stable for the epoch, so reuse one lookup across
                    // competing final block proposals and verification
                    // attempts.
                    let players = self
                        .participants_provider
                        .participants(epoch.next().next())
                        .await;
                    validate_future_participants::<V, _>(
                        &players,
                        self.max_participants,
                        self.blocks_per_epoch,
                    );
                    artifacts.next_players = Some(players.clone());
                    players
                }
            }
        } else {
            Set::default()
        };

        let artifact = match (ceremony, current) {
            (Some(ceremony), Some(current)) => {
                let next_epoch = epoch.next();
                let requested = Set::from_iter_dedup(
                    ceremony
                        .output
                        .players()
                        .iter()
                        .chain(current.next_players.iter())
                        .chain(next_players.iter())
                        .cloned(),
                );
                let directory = self
                    .participants_provider
                    .directory(next_epoch, requested.clone())
                    .await;
                assert!(
                    directory.matches(&requested),
                    "participants provider returned directory that does not exactly match requested peers"
                );
                Some(Artifact {
                    info: EpochInfo {
                        outcome: EpochOutcome::Success,
                        epoch: next_epoch,
                        output: ceremony.output.clone(),
                        players: current.next_players,
                        next_players,
                        directory,
                    },
                    share: ceremony.share.clone(),
                })
            }
            (Some(ceremony), None) => {
                let share = ceremony
                    .share
                    .clone()
                    .expect("DKG participant must receive a share");
                let players = dkg_participants.expect("DKG mode must provide participants");
                let requested = Set::from_iter_dedup(
                    ceremony
                        .output
                        .players()
                        .iter()
                        .chain(players.iter())
                        .chain(next_players.iter())
                        .cloned(),
                );
                let directory = self
                    .dkg_directory()
                    .expect("DKG mode must provide directory");
                assert!(
                    directory.matches(&requested),
                    "configured DKG directory does not exactly match participants"
                );
                Some(Artifact {
                    info: EpochInfo {
                        outcome: EpochOutcome::Success,
                        epoch,
                        output: ceremony.output.clone(),
                        players,
                        next_players,
                        directory,
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
                let requested = Set::from_iter_dedup(
                    current
                        .output
                        .players()
                        .iter()
                        .chain(current.next_players.iter())
                        .chain(next_players.iter())
                        .cloned(),
                );
                let directory = self
                    .participants_provider
                    .directory(epoch.next(), requested.clone())
                    .await;
                assert!(
                    directory.matches(&requested),
                    "participants provider returned directory that does not exactly match requested peers"
                );
                Some(Artifact {
                    info: EpochInfo {
                        outcome: EpochOutcome::Failure,
                        epoch: epoch.next(),
                        output: current.output,
                        players: current.next_players,
                        next_players,
                        directory,
                    },
                    share,
                })
            }
            (None, None) => None,
        };

        artifacts.artifact = Some(CachedArtifact {
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
    fn artifact_response(
        &self,
        artifact: Option<&Artifact<V, C, B::Directory>>,
    ) -> EpochInfoResponse<V, C, B::Directory> {
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
        store: &mut Store<E, SS, V, C::PublicKey, B::Directory>,
        artifact: Option<&Artifact<V, C, B::Directory>>,
        payload: Option<Payload<V, C, B::Directory>>,
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
    use crate::dkg::{
        fence::Fence,
        reshare::actor::{Config, DkgConfig},
        state_sync::Plan as StateSyncPlan,
        tests::mocks::{self, MemorySecretStore, TestBlock, TestBlsVariant},
    };
    use commonware_actor::Feedback;
    use commonware_consensus::{Reporter, marshal};
    use commonware_cryptography::{
        Digestible as _, Signer,
        bls12381::{
            dkg::feldman_desmedt::{Dealer as CryptoDealer, Verdict},
            primitives::sharing::Mode as SharingMode,
        },
        ed25519::{PrivateKey, PublicKey},
        sha256::Sha256,
    };
    use commonware_p2p::simulated::{Config as NetworkConfig, Network};
    use commonware_parallel::Sequential;
    use commonware_runtime::{Runner, Spawner, Supervisor, deterministic};
    use commonware_utils::{
        Acknowledgement, N3f1, NZU32, NZU64, NZUsize, acknowledgement::Exact, channel::oneshot,
        ordered::Set, sequence::Unit, test_rng,
    };
    use futures::{FutureExt, stream};
    use std::{
        marker::PhantomData,
        pin::Pin,
        sync::Arc,
        task::{Context, Poll},
        time::Duration,
    };

    const TEST_NAMESPACE: &[u8] = b"_COMMONWARE_GLUE_DKG_RESHARE_INCLUSION_TEST";

    type TestResponse = EpochInfoResponse<TestBlsVariant, PrivateKey>;
    type TestArtifacts = ArtifactCache<TestBlsVariant, PrivateKey, Unit>;
    type TestRequests = ArtifactRequests<TestBlock, TestBlsVariant, PrivateKey>;

    #[derive(Clone)]
    struct StalledAncestry;

    impl futures::Stream for StalledAncestry {
        type Item = Arc<TestBlock>;

        fn poll_next(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            Poll::Pending
        }
    }

    impl marshal::ancestry::Ancestry<TestBlock> for StalledAncestry {
        fn peek(&self) -> Option<&TestBlock> {
            None
        }
    }

    struct DropNotifier(Option<oneshot::Sender<()>>);

    impl Drop for DropNotifier {
        fn drop(&mut self) {
            if let Some(sender) = self.0.take() {
                let _ = sender.send(());
            }
        }
    }

    fn signers() -> Vec<PrivateKey> {
        (0..4).map(PrivateKey::from_seed).collect()
    }

    fn players() -> Set<PublicKey> {
        Set::from_iter_dedup(signers().iter().map(Signer::public_key))
    }

    fn info() -> Info<TestBlsVariant, PublicKey> {
        Info::new::<N3f1>(
            TEST_NAMESPACE,
            0,
            None,
            SharingMode::NonZeroCounter,
            players(),
            players(),
        )
        .expect("valid info")
    }

    fn stalled_ancestry() -> ErasedAncestry<TestBlock> {
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
        let (dealer, _, _) = CryptoDealer::start::<N3f1>(test_rng(), info.clone(), signer, None)
            .expect("dealer should start");
        let signed = dealer.finalize::<N3f1>();
        let (public_key, log) = signed.check(&info).expect("dealer log should be valid");
        BTreeMap::from([(public_key, log)])
    }

    #[test]
    fn dropping_verification_aborts_active_task() {
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|context| async move {
            let (started_tx, started_rx) = oneshot::channel();
            let (dropped_tx, dropped_rx) = oneshot::channel();
            let task = context.child("active").spawn(|_| async move {
                let _notifier = DropNotifier(Some(dropped_tx));
                let _ = started_tx.send(());
                futures::future::pending::<VerifiedLogs<TestBlsVariant, PrivateKey>>().await
            });
            let mut verification = Verification::default();
            verification.start(task);
            started_rx.await.expect("task should start");

            drop(verification);

            dropped_rx.await.expect("task should be aborted");
        });
    }

    #[test]
    fn exact_failed_artifact_is_a_cache_hit() {
        let logs = dealer_logs(0);
        let artifacts = TestArtifacts {
            next_players: None,
            artifact: Some(CachedArtifact {
                logs: Arc::new(logs.clone()),
                artifact: None,
            }),
        };

        assert!(
            artifacts
                .get(&logs)
                .is_some_and(|cached| cached.artifact.is_none())
        );
        assert!(artifacts.get(&dealer_logs(1)).is_none());
    }

    #[test]
    fn finalization_preserves_active_and_answers_queued_canonical_request() {
        let executor = deterministic::Runner::timed(Duration::from_secs(30));
        executor.start(|mut context| async move {
            let signer = PrivateKey::from_seed(0);
            let public_key = signer.public_key();
            let participants = Set::from_iter_dedup([public_key.clone()]);
            let info = Info::new::<N3f1>(
                TEST_NAMESPACE,
                0,
                None,
                SharingMode::NonZeroCounter,
                participants.clone(),
                participants.clone(),
            )
            .expect("valid singleton info");
            let secret_store = MemorySecretStore::default();
            let mut store = Store::init(
                context.child("store"),
                "inclusion-actor-store",
                NZU32!(16),
                secret_store.clone(),
            )
            .await;

            let seed = store.seed_or_random(Epoch::zero(), test_rng()).await;
            let mut dealer = store
                .create_dealer::<PrivateKey, N3f1>(
                    Epoch::zero(),
                    signer.clone(),
                    info.clone(),
                    None,
                    seed,
                )
                .expect("dealer");
            let mut player = store
                .create_player::<PrivateKey, N3f1>(Epoch::zero(), signer.clone(), info.clone())
                .expect("player");
            let (recipient, public, private) =
                dealer.shares_to_distribute().next().expect("self dealing");
            assert_eq!(recipient, public_key);
            let Verdict::Valid(ack) = player
                .handle(
                    &mut store,
                    Epoch::zero(),
                    public_key.clone(),
                    public,
                    private,
                )
                .await
            else {
                panic!("valid self dealing");
            };
            assert!(matches!(
                dealer
                    .handle(&mut store, Epoch::zero(), public_key.clone(), ack)
                    .await,
                Verdict::Valid(())
            ));
            assert!(dealer.finalize::<N3f1>());
            let signed_log = dealer.finalized().expect("signed dealer log");

            let fixture = mocks::scheme_fixture_n(&mut context, 1);
            let marshal = mocks::closed_marshal_mailbox(
                context.child("marshal"),
                &signer,
                fixture.schemes[0].clone(),
                "inclusion-actor",
                NZU64!(4),
            )
            .await;
            let (_network, oracle) = Network::new_with_peers(
                context.child("network"),
                NetworkConfig {
                    max_size: 1024,
                    max_peers_per_set: NZUsize!(participants.len()),
                    disconnect_on_block: true,
                    tracked_peer_sets: NZUsize!(1),
                },
                vec![public_key.clone()],
            )
            .await;
            let (fence, _gate) = Fence::new(Epoch::zero());
            let (mut actor, mut mailbox) = mocks::TestReshareActor::new_dkg(
                context.child("actor"),
                Config {
                    signer: signer.clone(),
                    manager: oracle.manager(),
                    blocker: oracle.control(public_key.clone()),
                    participants_provider: mocks::StaticParticipants(participants.clone()),
                    secret_store,
                    strategy: Sequential,
                    registrar: mocks::MockConsumer::default(),
                    marshal,
                    state_sync: StateSyncPlan::disabled(),
                    fence,
                    namespace: TEST_NAMESPACE,
                    sharing_mode: SharingMode::NonZeroCounter,
                    mailbox_size: NZUsize!(16),
                    partition_prefix: "inclusion-actor".into(),
                    max_participants: NZU32!(16),
                    blocks_per_epoch: NZU64!(4),
                    batch_verifier: PhantomData,
                },
                DkgConfig {
                    participants: participants.clone(),
                    directory: Unit,
                    completion: Box::new(|_| {}),
                },
            );

            let genesis = mocks::genesis_block(public_key);
            let losing_block = TestBlock::new::<Sha256>(
                genesis.context().clone(),
                genesis.digest(),
                Height::new(2),
                2,
            )
            .with_payload::<Sha256, TestBlsVariant, PrivateKey>(
                NZU32!(16),
                Payload::DealerLog(signed_log),
            );
            let canonical_block = TestBlock::new::<Sha256>(
                genesis.context().clone(),
                genesis.digest(),
                Height::new(2),
                3,
            );
            let final_block = TestBlock::new::<Sha256>(
                genesis.context().clone(),
                canonical_block.digest(),
                Height::new(3),
                4,
            );
            let inclusion = context.child("inclusion").spawn(|_| async move {
                let result = actor
                    .inclusion(Epoch::zero(), &info, &mut store, None)
                    .await;
                (result, store)
            });

            let mut losing_mailbox = mailbox.clone();
            let losing =
                losing_mailbox.epoch_info(marshal::ancestry::from_iter([Arc::new(losing_block)]));
            futures::pin_mut!(losing);
            assert!(losing.as_mut().now_or_never().is_none());

            let mut canonical_mailbox = mailbox.clone();
            let canonical = canonical_mailbox.epoch_info(marshal::ancestry::with_prefix(
                [Arc::new(canonical_block.clone())],
                StalledAncestry,
            ));
            futures::pin_mut!(canonical);
            assert!(canonical.as_mut().now_or_never().is_none());

            let (parent_ack, parent_waiter) = Exact::handle();
            assert_eq!(
                mailbox.report(marshal::Update::Block(
                    Arc::new(canonical_block),
                    parent_ack,
                )),
                Feedback::Ok
            );

            let (ack, ack_waiter) = Exact::handle();
            assert_eq!(
                mailbox.report(marshal::Update::Block(Arc::new(final_block), ack)),
                Feedback::Ok
            );

            assert!(matches!(
                canonical.await,
                EpochInfoResponse::Available(None)
            ));
            assert!(matches!(
                losing.await,
                EpochInfoResponse::Available(Some(Payload::EpochInfo(_)))
            ));

            parent_waiter
                .await
                .expect("canonical parent should be acknowledged");
            ack_waiter
                .await
                .expect("final block should be acknowledged");
            let (result, store) = inclusion.await.expect("inclusion should finish");
            assert!(result.is_continue());
            assert!(store.current().is_none());
        });
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
                mocks::genesis_block(signers()[0].public_key()).digest(),
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
                mocks::genesis_block(signers()[0].public_key()).digest(),
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
    fn pending_logs_discards_view_when_response_closes_at_eof() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let info = info();
            let (mut response_tx, response_rx) = oneshot::channel::<TestResponse>();
            let mut response_rx = Some(response_rx);
            let ancestry = Box::pin(stream::poll_fn(move |_| {
                drop(response_rx.take());
                std::task::Poll::<Option<Arc<TestBlock>>>::Ready(None)
            }));

            assert!(
                pending_logs(
                    scan(&info),
                    mocks::genesis_block(signers()[0].public_key()).digest(),
                    ancestry,
                    context.stopped(),
                    &mut response_tx,
                )
                .await
                .is_none()
            );
        });
    }

    #[test]
    fn pending_logs_rejects_ancestry_truncated_before_inclusion_start() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let info = info();
            let genesis = mocks::genesis_block(signers()[0].public_key());
            let block_five = TestBlock::new::<Sha256>(
                genesis.context().clone(),
                genesis.digest(),
                Height::new(5),
                5,
            );
            let block_six = TestBlock::new::<Sha256>(
                genesis.context().clone(),
                block_five.digest(),
                Height::new(6),
                6,
            );
            let parent = block_six.digest();
            let ancestry = Box::pin(stream::iter([Arc::new(block_six), Arc::new(block_five)]));
            let (mut response_tx, _response_rx) = oneshot::channel::<TestResponse>();
            let scan = PendingLogScan {
                epoch: Epoch::zero(),
                info: &info,
                epocher: FixedEpocher::new(NZU64!(8)),
                finalized_tip: None,
                final_height: Height::new(7),
            };

            assert!(
                pending_logs(scan, parent, ancestry, context.stopped(), &mut response_tx,)
                    .await
                    .is_none()
            );
        });
    }

    #[test]
    fn pending_logs_stop_at_the_first_unfinalized_block() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let info = info();
            let genesis = mocks::genesis_block(signers()[0].public_key());
            let block_five = TestBlock::new::<Sha256>(
                genesis.context().clone(),
                genesis.digest(),
                Height::new(5),
                5,
            );
            let block_six = TestBlock::new::<Sha256>(
                genesis.context().clone(),
                block_five.digest(),
                Height::new(6),
                6,
            );
            let parent = block_six.digest();
            let ancestry = Box::pin(
                stream::iter([Arc::new(block_six), Arc::new(block_five)]).chain(stream::pending()),
            );
            let (mut response_tx, _response_rx) = oneshot::channel::<TestResponse>();
            let scan = PendingLogScan {
                epoch: Epoch::zero(),
                info: &info,
                epocher: FixedEpocher::new(NZU64!(8)),
                finalized_tip: Some(Height::new(4)),
                final_height: Height::new(7),
            };

            assert!(
                pending_logs(scan, parent, ancestry, context.stopped(), &mut response_tx,)
                    .now_or_never()
                    .is_some_and(|logs| logs.is_some_and(|logs| logs.is_empty()))
            );
        });
    }

    #[test]
    fn verification_retains_completed_result_for_exact_reuse() {
        let completed = dealer_logs(0);
        let canonical = dealer_logs(1);
        let mut verification = Verification::<TestBlsVariant, PrivateKey>::default();

        verification.retain(
            VerifiedLogs {
                logs: Arc::new(completed.clone()),
                ceremony: None,
            },
            &canonical,
        );

        assert!(verification.ready(&completed).is_some());
        assert!(verification.ready(&canonical).is_none());
    }

    #[test]
    fn verification_retains_canonical_result_over_speculative_completion() {
        let canonical = dealer_logs(0);
        let speculative = dealer_logs(1);
        let mut verification = Verification::<TestBlsVariant, PrivateKey>::default();

        verification.retain(
            VerifiedLogs {
                logs: Arc::new(canonical.clone()),
                ceremony: None,
            },
            &canonical,
        );
        verification.retain(
            VerifiedLogs {
                logs: Arc::new(speculative.clone()),
                ceremony: None,
            },
            &canonical,
        );

        assert!(verification.ready(&canonical).is_some());
        assert!(verification.ready(&speculative).is_none());
    }

    #[test]
    fn canceled_request_is_not_selected() {
        let parent = mocks::genesis_block(signers()[0].public_key()).digest();
        let (response_tx, response_rx) = oneshot::channel();
        let mut requests = TestRequests::default();
        requests.push(parent, Span::none(), Box::pin(stream::empty()), response_tx);
        drop(response_rx);

        assert!(requests.pop().is_none());
    }

    #[test]
    fn requests_are_selected_in_arrival_order() {
        let genesis = mocks::genesis_block(signers()[0].public_key());
        let first = genesis.digest();
        let second =
            TestBlock::new::<Sha256>(genesis.context().clone(), first, Height::new(1), 1).digest();
        let (earlier, later) = if first < second {
            (second, first)
        } else {
            (first, second)
        };
        let (earlier_tx, _earlier_rx) = oneshot::channel();
        let (later_tx, _later_rx) = oneshot::channel();
        let mut requests = TestRequests::default();
        requests.push(earlier, Span::none(), Box::pin(stream::empty()), earlier_tx);
        requests.push(later, Span::none(), Box::pin(stream::empty()), later_tx);

        assert_eq!(requests.pop().map(|request| request.parent), Some(earlier));
    }

    #[test]
    fn queued_requests_retain_lazy_ancestries() {
        let genesis = mocks::genesis_block(signers()[0].public_key());
        let first = genesis.digest();
        let second =
            TestBlock::new::<Sha256>(genesis.context().clone(), first, Height::new(1), 1).digest();
        let (first_tx, _first_rx) = oneshot::channel();
        let (second_tx, _second_rx) = oneshot::channel();
        let mut requests = TestRequests::default();

        requests.push(first, Span::none(), stalled_ancestry(), first_tx);
        requests.push(second, Span::none(), stalled_ancestry(), second_tx);

        assert_eq!(requests.inner.len(), 2);
    }
}
