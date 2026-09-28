use crate::dkg::{
    ParticipantsProvider, Registrar, ReshareBlock, SecretStore,
    network::{Directory, Manager},
    reshare::{
        Actor, EpochInfoResponse, Message,
        actor::{FinalizedTip, Mode},
        mailbox::LogReservation,
        metrics::Phase,
        store::{Dealer, Player, Store},
    },
    types::{EpochInfo, EpochOutcome, Participants, Payload},
};
use commonware_actor::mailbox::Sender as ActorSender;
use commonware_consensus::{
    marshal::{ancestry::BoxedAncestry, core::Variant as MarshalVariant},
    simplex::scheme::Scheme as SimplexScheme,
    types::{Epoch, EpochPhase, Epocher, FixedEpocher, Height},
};
use commonware_cryptography::{
    BatchVerifier, PublicKey, Signer,
    bls12381::{
        dkg::feldman_desmedt::{
            DealerLog, FinalizeError as DkgFinalizeError, Info, Logs, Output, observe,
        },
        primitives::{group::Share, variant::Variant as BlsVariant},
    },
    certificate::Scheme,
};
use commonware_macros::{select, select_loop};
use commonware_p2p::Blocker;
use commonware_parallel::Strategy;
use commonware_runtime::{
    BufferPooler, Clock, Error as RuntimeError, Handle, Metrics, Spawner,
    Storage as RuntimeStorage, signal, telemetry::traces::TracedExt as _,
};
use commonware_utils::{
    Acknowledgement, N3f1,
    channel::{fallible::OneshotExt, oneshot},
    futures::OptionFuture,
    ordered::Set,
};
use futures::{FutureExt, Stream, StreamExt, future::BoxFuture};
use rand_core::CryptoRng;
use std::{
    collections::{BTreeMap, VecDeque},
    future::Future,
    num::{NonZeroU32, NonZeroU64},
    ops::ControlFlow,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tracing::{Instrument as _, Span, debug, info, info_span, warn};

type PendingLogs<V, P> = BTreeMap<P, DealerLog<V, P>>;
type ArtifactScanTask<'a, V, P> = OptionFuture<BoxFuture<'a, Option<PendingLogs<V, P>>>>;
type LogView<V, P> = Arc<PendingLogs<V, P>>;

/// A queued epoch-info request whose ancestry has not been read.
struct ArtifactRequest<B, V, C>
where
    B: ReshareBlock<Variant = V, Signer = C>,
    V: BlsVariant,
    C: Signer,
{
    span: Span,
    ancestry: BoxedAncestry<B>,
    response: oneshot::Sender<EpochInfoResponse<V, C, B::Directory>>,
}

/// The active ancestry scan and its request, kept so a finalized block can
/// restart the scan.
struct ArtifactScan<'a, B, V, C>
where
    B: ReshareBlock<Variant = V, Signer = C>,
    V: BlsVariant,
    C: Signer,
{
    request: Option<ArtifactRequest<B, V, C>>,
    task: ArtifactScanTask<'a, V, C::PublicKey>,
}

impl<'a, B, V, C> Default for ArtifactScan<'a, B, V, C>
where
    B: ReshareBlock<Variant = V, Signer = C>,
    V: BlsVariant,
    C: Signer,
{
    fn default() -> Self {
        Self {
            request: None,
            task: None.into(),
        }
    }
}

impl<'a, B, V, C> ArtifactScan<'a, B, V, C>
where
    B: ReshareBlock<Variant = V, Signer = C>,
    V: BlsVariant,
    C: Signer,
{
    /// Starts scanning a clone of `request`'s ancestry.
    ///
    /// Panics if a scan is active.
    fn start(
        &mut self,
        scan: PendingLogScan<'a, V, C::PublicKey, B::Digest>,
        request: ArtifactRequest<B, V, C>,
        shutdown: signal::Signal,
    ) {
        assert!(self.request.is_none(), "artifact scan already active");
        let process = info_span!(
            parent: &request.span,
            "dkg.reshare.actor.inclusion.epoch_info"
        );
        let task = pending_logs(scan, request.ancestry.clone(), shutdown)
            .instrument(process)
            .boxed();
        self.request = Some(request);
        self.task = Some(task).into();
    }

    const fn is_active(&self) -> bool {
        self.request.is_some()
    }

    fn take_request(&mut self) -> Option<ArtifactRequest<B, V, C>> {
        self.task = None.into();
        self.request.take()
    }
}

// The only pinned state lives behind BoxFuture, so moving this struct cannot
// move a future after it has been polled.
impl<B, V, C> Unpin for ArtifactScan<'_, B, V, C>
where
    B: ReshareBlock<Variant = V, Signer = C>,
    V: BlsVariant,
    C: Signer,
{
}

impl<B, V, C> Future for ArtifactScan<'_, B, V, C>
where
    B: ReshareBlock<Variant = V, Signer = C>,
    V: BlsVariant,
    C: Signer,
{
    type Output = Option<PendingLogs<V, C::PublicKey>>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let Some(request) = self.request.as_mut() else {
            return Poll::Pending;
        };

        // A cancelled request ends its scan early so the next request can start.
        if request.response.poll_closed(cx).is_ready() {
            return Poll::Ready(None);
        }
        Pin::new(&mut self.task).poll(cx)
    }
}

/// Queued epoch-info requests in arrival order.
// Queued ancestries stay unread so waiting requests do not each hold a full
// dealer-log map while the verifier is busy.
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
    fn push(
        &mut self,
        span: Span,
        ancestry: BoxedAncestry<B>,
        response: oneshot::Sender<EpochInfoResponse<V, C, B::Directory>>,
    ) {
        self.inner.push_back(ArtifactRequest {
            span,
            ancestry,
            response,
        });
    }

    fn push_front(&mut self, request: ArtifactRequest<B, V, C>) {
        self.inner.push_front(request);
    }

    /// Removes and returns the oldest request whose requester is still waiting,
    /// dropping cancelled ones.
    fn pop(&mut self) -> Option<ArtifactRequest<B, V, C>> {
        while let Some(request) = self.inner.pop_front() {
            if !request.response.is_closed() {
                return Some(request);
            }
        }
        None
    }

    /// Answers every queued request with [`EpochInfoResponse::Pending`].
    fn drain_pending(&mut self) {
        for request in self.inner.drain(..) {
            if request.response.is_closed() {
                continue;
            }
            let _ = request.response.send_lossy(EpochInfoResponse::Pending);
        }
    }
}

/// A locally derived [`EpochInfo`] and this node's share of its output (never
/// persisted).
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

/// A verification result and the dealer logs it was computed from (`ceremony`
/// is `None` if they yield no output).
struct VerifiedLogs<V: BlsVariant, C: Signer> {
    logs: LogView<V, C::PublicKey>,
    ceremony: Option<Ceremony<V, C>>,
}

/// The running verification task and the last retained result (never
/// persisted).
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
    /// Installs `task` as the running verification.
    ///
    /// Panics if one is running.
    fn start(&mut self, task: Handle<VerifiedLogs<V, C>>) {
        assert!(self.task.is_none(), "verification task already running");
        self.task = Some(task).into();
    }

    /// Returns `Continue` with the task's result, or `Break` if the runtime
    /// closed the task.
    ///
    /// Panics on any other task error.
    fn join(
        result: Result<VerifiedLogs<V, C>, RuntimeError>,
    ) -> ControlFlow<(), VerifiedLogs<V, C>> {
        match result {
            Ok(completed) => ControlFlow::Continue(completed),
            Err(RuntimeError::Closed) => ControlFlow::Break(()),
            Err(error) => panic!("verification task failed: {error}"),
        }
    }

    /// Retains `result` unless that would replace a result for the `canonical`
    /// (finalized) logs with one for other logs.
    fn retain(&mut self, result: VerifiedLogs<V, C>, canonical: &PendingLogs<V, C::PublicKey>) {
        let retained_is_canonical = self
            .result
            .as_ref()
            .is_some_and(|retained| retained.logs.as_ref() == canonical);
        if result.logs.as_ref() == canonical || !retained_is_canonical {
            self.result = Some(result);
        }
    }

    /// Returns `None` if no result for exactly `logs` is retained, `Some(None)`
    /// if those logs yield no output, and `Some(Some(_))` otherwise.
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
        if let Some(task) = self.task.as_ref() {
            task.abort();
        }
    }
}

/// The artifact derived from one dealer-log set (`None` for a failed DKG).
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
    /// Returns the cached artifact if it was derived from exactly `logs`.
    fn get(&self, logs: &PendingLogs<V, C::PublicKey>) -> Option<&CachedArtifact<V, C, D>> {
        self.artifact
            .as_ref()
            .filter(|cached| cached.logs.as_ref() == logs)
    }
}

/// Epoch-info request state for one inclusion window.
struct ArtifactWork<B, V, C>
where
    B: ReshareBlock<Variant = V, Signer = C>,
    V: BlsVariant,
    C: Signer,
{
    requests: ArtifactRequests<B, V, C>,
    waiter: Option<oneshot::Sender<EpochInfoResponse<V, C, B::Directory>>>,
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

struct PendingLogScan<'a, V: BlsVariant, P, D> {
    epoch: Epoch,
    info: &'a Info<V, P>,
    epocher: FixedEpocher,
    finalized_tip: Option<FinalizedTip<D>>,
    final_height: Height,
}

/// Owned inputs for one dealer-log verification.
// It holds no store, provider, registrar, or metrics handle, so aborting it has
// no side effects.
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
    /// Verifies and selects dealer logs, returning the output and, if this node
    /// is a player, its share (`None` if the logs yield no output).
    ///
    /// Panics if the local player state is invalid.
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
                Err(DkgFinalizeError::Error(error)) => {
                    panic!("invalid local state while finalizing reshare player: {error:?}")
                }
                Err(DkgFinalizeError::Failure(failure)) => {
                    warn!(epoch = ?self.epoch, ?failure, "failed to finalize player");
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

/// Panics if a provider-supplied future participant set is empty, exceeds
/// `max_participants`, or needs more dealer logs than an epoch can carry.
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

    // Two epochs after this set is embedded it becomes both the dealer set and
    // the previous output's player set, so its quorum bounds the dealer logs the
    // ceremony must land on-chain. Panicking here keeps an unusable set out of a
    // finalized EpochInfo, where every node would re-derive the violation and
    // panic at the boundary.
    Participants {
        dealers: participants.clone(),
        players: participants.clone(),
        next_players: Set::default(),
    }
    .validate_epoch_capacity::<V>(blocks_per_epoch, None)
    .expect("participants provider returned set exceeding epoch dealer-log capacity");
}

/// Returns the valid dealer logs in `ancestry` above the finalized tip, keeping
/// each dealer's earliest.
///
/// Returns `None` if the runtime stops, or if `ancestry` ends early or does not
/// extend the finalized tip.
async fn pending_logs<B, V, C>(
    scan: PendingLogScan<'_, V, C::PublicKey, B::Digest>,
    mut ancestry: impl Stream<Item = Arc<B>> + Send + Unpin,
    mut shutdown: signal::Signal,
) -> Option<PendingLogs<V, C::PublicKey>>
where
    B: ReshareBlock<Variant = V, Signer = C>,
    V: BlsVariant,
    C: Signer,
{
    // Scan only unfinalized blocks from the midpoint on, and require them to
    // extend the finalized tip.
    let midpoint = scan
        .epocher
        .midpoint(scan.epoch)
        .expect("epocher must know epoch midpoint");
    let first_pending = scan
        .finalized_tip
        .filter(|tip| tip.height >= midpoint)
        .map_or(midpoint, |tip| tip.height.next());
    let anchor = scan
        .finalized_tip
        .filter(|tip| tip.height.next() == first_pending)
        .map(|tip| tip.digest);
    let Some(mut cursor_height) = scan.final_height.previous() else {
        return Some(PendingLogs::new());
    };

    // Verification ancestry starts at the final block and proposal ancestry at
    // its parent. Reading it in this scan, which runs alongside the mailbox,
    // keeps a slow parent fetch from stalling the actor.
    let first = select! {
        _ = &mut shutdown => return None,
        block = ancestry.next() => block,
    };
    let Some(first) = first else {
        warn!(
            epoch = ?scan.epoch,
            ?cursor_height,
            "epoch info ancestry ended before yielding a boundary block"
        );
        return None;
    };
    let block = if first.height() == scan.final_height {
        let parent = select! {
            _ = &mut shutdown => return None,
            block = ancestry.next() => block,
        };
        let Some(parent) = parent else {
            warn!(
                epoch = ?scan.epoch,
                ?cursor_height,
                "epoch info ancestry ended before yielding the boundary parent"
            );
            return None;
        };
        parent
    } else {
        first
    };

    let mut attachment = block.digest();
    let mut blocks = Vec::new();
    if first_pending <= cursor_height {
        attachment = block.parent();
        blocks.push(block);
        while cursor_height > first_pending {
            cursor_height = cursor_height
                .previous()
                .expect("pending dealer-log ancestry must remain above genesis");
            let block = select! {
                _ = &mut shutdown => return None,
                block = ancestry.next() => block,
            };
            let Some(block) = block else {
                warn!(
                    epoch = ?scan.epoch,
                    ?cursor_height,
                    "epoch info ancestry ended before covering pending dealer logs"
                );
                return None;
            };
            attachment = block.parent();
            blocks.push(block);
        }
    }

    // Ancestry guarantees parent links between the blocks it yields, but not
    // that they extend the finalized chain.
    if anchor.is_some_and(|digest| digest != attachment) {
        warn!(
            epoch = ?scan.epoch,
            "epoch info ancestry is detached from finalized prefix"
        );
        return None;
    }

    // Authenticate logs in chain order so each dealer's earliest valid log wins,
    // matching the journal's first-log rule.
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
    /// Runs the inclusion window of `epoch`.
    ///
    /// Offers this node's signed dealer log until a finalized block includes it,
    /// records valid dealer logs from finalized blocks, and answers final-block
    /// [`EpochInfo`] requests.
    ///
    /// Returns `Continue` once the epoch's final block is applied (see
    /// [`Self::handle_finalized_epoch_info`]). Returns `Break` on shutdown, when
    /// the mailbox closes, or when the runtime closes a verification task.
    ///
    /// Panics if an unapplied finalized block lies outside the inclusion window
    /// of `epoch`. Also panics as described on [`Self::artifact`] and
    /// [`Self::handle_finalized_epoch_info`].
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

        let mut served_at: Option<Height> = None;
        let mut work = ArtifactWork::default();
        let mut scan = ArtifactScan::default();

        // Queued requests start from a branch after the mailbox, so an admitted
        // finalized block updates the tip before the next scan begins.
        let mut advance = OptionFuture::from(None::<std::future::Ready<()>>);
        select_loop! {
            self.context,
            on_stopped => {
                debug!("shutdown signal received");
                return ControlFlow::Break(());
            },
            completed = &mut work.verification.task => {
                let ControlFlow::Continue(completed) = Verification::join(completed) else {
                    return ControlFlow::Break(());
                };
                self.complete_verification(epoch, store, &mut work, completed)
                    .await;
                advance = Some(std::future::ready(())).into();
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
                    Self::handle_next_log(
                        dealer.as_deref(),
                        &mut served_at,
                        span,
                        height,
                        release,
                        response,
                    );
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
                        work.requests.push(span, ancestry, response);
                        if advance.is_none() {
                            self.advance_artifact_requests(epoch, info, &mut scan, &mut work);
                        }
                    }
                }
                Message::Finalized {
                    span,
                    block,
                    response,
                } => {
                    if self.covered(&block) {
                        response.acknowledge();
                        continue;
                    }
                    let process = info_span!(
                        parent: &span,
                        "dkg.reshare.actor.inclusion.finalized",
                        height = block.height().traced()
                    );
                    let outcome = async {
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

                        // Restart any active scan after this block is applied, so
                        // it checks against the new finalized tip.
                        if let Some(request) = scan.take_request() {
                            work.requests.push_front(request);
                        }

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
                        if done
                            && self
                                .complete_epoch_artifact(
                                epoch,
                                info,
                                store,
                                &mut work,
                                block.as_ref(),
                            )
                            .await
                            .is_break()
                        {
                            return ControlFlow::Break(());
                        }

                        // A log still held once finalization reaches its served height
                        // was not included, so it becomes available to the next request.
                        if served_at.is_some_and(|served| block.height() >= served)
                            && dealer
                                .as_ref()
                                .is_some_and(|dealer| dealer.finalized().is_some())
                        {
                            served_at = None;
                        }

                        self.advance(&block);
                        response.acknowledge();
                        ControlFlow::Continue(done)
                    }
                    .instrument(process)
                    .await;
                    let ControlFlow::Continue(done) = outcome else {
                        return ControlFlow::Break(());
                    };
                    if done {
                        return ControlFlow::Continue(());
                    }
                    advance = Some(std::future::ready(())).into();
                }
                }
            },
            // Mailbox traffic precedes scan completion, so an admitted finalized
            // block restarts a finished scan before it can answer from a losing
            // fork.
            pending = &mut scan => {
                let request = scan
                    .take_request()
                    .expect("completed artifact scan must own a request");
                self.complete_artifact_scan(
                    epoch,
                    info,
                    store,
                    request,
                    pending,
                    &mut work,
                )
                .await;
                advance = Some(std::future::ready(())).into();
            },
            _ = &mut advance => {
                advance = None.into();
                self.advance_artifact_requests(epoch, info, &mut scan, &mut work);
            },
        };

        ControlFlow::Break(())
    }

    /// Answers a dealer-log request with this node's signed log unless one is
    /// already served, recording `height` once the reservation is delivered.
    fn handle_next_log(
        dealer: Option<&Dealer<V, C>>,
        served_at: &mut Option<Height>,
        span: Span,
        height: Height,
        release: ActorSender<Message<B, V, C, A>>,
        response: oneshot::Sender<Option<LogReservation<B, V, C, A>>>,
    ) {
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
                        .and_then(|dealer| dealer.finalized())
                        .map(Payload::DealerLog)
                })
                .flatten();
            let has_payload = payload.is_some();
            let reservation = payload.map(|payload| LogReservation::new(height, payload, release));
            if response.send_lossy(reservation) && has_payload {
                *served_at = Some(height);
            }
        });
    }

    /// Derives the [`EpochInfo`] from the finalized logs, answers queued
    /// requests with [`EpochInfoResponse::Pending`], and commits the final
    /// block's [`EpochInfo`].
    ///
    /// Returns `Break` if the runtime closes a verification task.
    async fn complete_epoch_artifact(
        &mut self,
        epoch: Epoch,
        info: &Info<V, C::PublicKey>,
        store: &mut Store<E, SS, V, C::PublicKey, B::Directory>,
        work: &mut ArtifactWork<B, V, C>,
        block: &B,
    ) -> ControlFlow<()> {
        // Read the cache first, because completing the running verification
        // below may replace it with another log set.
        let canonical_logs = Arc::new(store.logs(epoch));
        let cached = work
            .artifacts
            .get(canonical_logs.as_ref())
            .map(|cached| cached.artifact.clone());

        // Finish a running verification first. It answers its requester, and
        // only one verification runs at a time.
        if work.verification.task.is_some() {
            let ControlFlow::Continue(completed) =
                Verification::join((&mut work.verification.task).await)
            else {
                return ControlFlow::Break(());
            };
            self.complete_verification(epoch, store, work, completed)
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
            if work.verification.ready(canonical_logs.as_ref()).is_none() {
                self.start_verification(
                    &mut work.verification,
                    epoch,
                    info,
                    store,
                    canonical_logs.clone(),
                );
                let ControlFlow::Continue(completed) =
                    Verification::join((&mut work.verification.task).await)
                else {
                    return ControlFlow::Break(());
                };
                work.verification.task = None.into();
                assert_eq!(
                    completed.logs.as_ref(),
                    canonical_logs.as_ref(),
                    "canonical verification returned a different view"
                );
                work.verification.retain(completed, canonical_logs.as_ref());
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
        work.requests.drain_pending();
        self.handle_finalized_epoch_info(epoch, store, artifact.as_ref(), block.payload())
            .await;
        ControlFlow::Continue(())
    }

    /// Starts a scan for the oldest waiting request when no scan or
    /// verification is running and the block before the midpoint is applied.
    fn advance_artifact_requests<'a>(
        &mut self,
        epoch: Epoch,
        info: &'a Info<V, C::PublicKey>,
        scan: &mut ArtifactScan<'a, B, V, C>,
        work: &mut ArtifactWork<B, V, C>,
    ) {
        // The scan checks its lowest block against the finalized tip, so wait
        // until the tip reaches the block before the midpoint.
        let midpoint = self
            .epocher
            .midpoint(epoch)
            .expect("epocher must know epoch midpoint");
        let prefix_ready = midpoint
            .previous()
            .is_none_or(|predecessor| self.tip.is_some_and(|tip| tip.height >= predecessor));
        if !prefix_ready || scan.is_active() || work.verification.task.is_some() {
            return;
        }
        let Some(request) = work.requests.pop() else {
            return;
        };
        let final_height = self
            .epocher
            .last(epoch)
            .expect("epocher must know final epoch height");
        scan.start(
            PendingLogScan {
                epoch,
                info,
                epocher: self.epocher.clone(),
                finalized_tip: self.tip,
                final_height,
            },
            request,
            self.context.stopped(),
        );
    }

    /// Durably records a valid dealer log carried by a finalized block.
    ///
    /// Block validity does not check dealer logs, so a finalized block may carry
    /// an invalid log, which is ignored. Once a current epoch is committed, logs
    /// from outside its dealer set are ignored too. Once this node's own log is
    /// observed, `dealer` drops its signed log.
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

        // `check` authenticates the signature but not dealer membership. Once a
        // current epoch is committed, drop logs from outside its dealer set so a
        // Byzantine leader cannot grow storage with logs that selection ignores.
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

    /// Answers a request whose scan finished: with
    /// [`EpochInfoResponse::Unavailable`] if the scan failed, from the caches if
    /// they hold its logs, and otherwise after a new verification.
    async fn complete_artifact_scan(
        &mut self,
        epoch: Epoch,
        info: &Info<V, C::PublicKey>,
        store: &mut Store<E, SS, V, C::PublicKey, B::Directory>,
        request: ArtifactRequest<B, V, C>,
        pending: Option<PendingLogs<V, C::PublicKey>>,
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
            let Some(pending) = pending else {
                let _ = request.response.send_lossy(EpochInfoResponse::Unavailable);
                return;
            };

            // Finalized logs take precedence. Pending ancestry fills only dealer
            // slots the journal has not claimed.
            let mut logs = store.logs(epoch);
            for (dealer, log) in pending {
                logs.entry(dealer).or_insert(log);
            }
            let logs = Arc::new(logs);

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

            // No scan starts while a verification runs, so no other requester is
            // waiting.
            assert!(work.waiter.is_none(), "materialized waiter already active");
            work.waiter = Some(request.response);
            self.start_verification(&mut work.verification, epoch, info, store, logs);
        }
        .instrument(process)
        .await;
    }

    /// Answers the request that started `completed` (unless cancelled) and
    /// retains the result.
    async fn complete_verification(
        &mut self,
        epoch: Epoch,
        store: &mut Store<E, SS, V, C::PublicKey, B::Directory>,
        work: &mut ArtifactWork<B, V, C>,
        completed: VerifiedLogs<V, C>,
    ) {
        work.verification.task = None.into();
        let response = work
            .waiter
            .take()
            .expect("completed speculative verification must own a response");

        // A cancelled requester skips artifact assembly. The result is still
        // retained below because it may match the finalized logs.
        if !response.is_closed() {
            let artifact = self
                .artifact(
                    epoch,
                    store,
                    completed.logs.clone(),
                    completed.ceremony.as_ref(),
                    &mut work.artifacts,
                )
                .await;
            let _ = response.send_lossy(self.artifact_response(artifact.as_ref()));
        }

        let canonical_logs = store.logs(epoch);
        work.verification.retain(completed, &canonical_logs);
    }

    /// Spawns verification of `log_map` as CPU-bound work.
    ///
    /// Panics if a result for `log_map` is retained or a verification is running.
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

    /// Builds the inputs to verify `log_map`, including this node's player state
    /// if it is a player.
    fn verification_task(
        &mut self,
        epoch: Epoch,
        info: &Info<V, C::PublicKey>,
        store: &Store<E, SS, V, C::PublicKey, B::Directory>,
        log_map: &PendingLogs<V, C::PublicKey>,
    ) -> VerificationTask<V, C, T> {
        // Continuous reshare takes players from the committed epoch. One-shot DKG
        // commits no epoch before its final block and uses its configured
        // participants instead.
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

    /// Derives the [`EpochInfo`] the final block must carry from `ceremony`, the
    /// verification result for `log_map`, and caches it.
    ///
    /// A successful ceremony installs its output. A failed reshare carries the
    /// current output forward with this node's share of it. A failed one-shot
    /// DKG yields `None`.
    ///
    /// Panics if the provider returns an invalid future participant set, or if a
    /// directory does not exactly match the requested peers.
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

        // One-shot DKG has no committed epoch and no lookahead committee.
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
                    // The provider must return the same set for the epoch, so
                    // one lookup serves every competing final-block request.
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

    /// Converts `artifact` into a response.
    ///
    /// A missing artifact is `Available(None)` in one-shot DKG and `Unavailable`
    /// in continuous reshare, whose final block always carries an [`EpochInfo`].
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

    /// Commits the [`EpochInfo`] carried by the final block of `epoch` and, in
    /// continuous reshare, registers its scheme.
    ///
    /// This node's share is committed only if `artifact` matches the finalized
    /// [`EpochInfo`]. Otherwise the epoch is committed without a share. A failed
    /// one-shot DKG's final block carries no payload, and nothing is committed.
    ///
    /// Panics if the payload is not an [`EpochInfo`] for the expected epoch, or
    /// if a one-shot DKG final block carries no payload while `artifact` is
    /// `Some`.
    async fn handle_finalized_epoch_info(
        &mut self,
        epoch: Epoch,
        store: &mut Store<E, SS, V, C::PublicKey, B::Directory>,
        artifact: Option<&Artifact<V, C, B::Directory>>,
        payload: Option<Payload<V, C, B::Directory>>,
    ) {
        let dkg = matches!(self.mode, Mode::Dkg { .. });
        if dkg && payload.is_none() {
            // A failed one-shot DKG finalizes its final block without a payload.
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
        reshare::{
            actor::{Config, DkgConfig, Setup, utils},
            store::AckOutcome,
        },
        state_sync::Plan as StateSyncPlan,
        tests::mocks::{self, MemorySecretStore, TestBlock, TestBlsVariant, child},
    };
    use commonware_actor::Feedback;
    use commonware_consensus::{Reporter, marshal};
    use commonware_cryptography::{
        Digestible as _, Signer,
        bls12381::{
            dkg::feldman_desmedt::{
                Dealer as CryptoDealer, DealerPrivMsg, DealerPubMsg, Player as CryptoPlayer,
                Reveal, SignedDealerLog, deal,
            },
            primitives::sharing::Mode as SharingMode,
        },
        ed25519::{PrivateKey, PublicKey},
        sha256::Sha256,
        transcript::Summary,
    };
    use commonware_math::algebra::Random as _;
    use commonware_p2p::{
        simulated::{Config as NetworkConfig, Network},
        utils::mocks::inert_channel,
    };
    use commonware_parallel::Sequential;
    use commonware_runtime::{ContextCell, Runner, Spawner, Supervisor, deterministic};
    use commonware_utils::{
        Acknowledgement, N3f1, NZU32, NZU64, NZUsize, TestRng, acknowledgement::Exact,
        channel::oneshot, ordered::Set, sequence::Unit, sync::Mutex, test_rng,
    };
    use futures::{FutureExt, stream};
    use std::{
        collections::BTreeMap,
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
    type TestInclusionMailbox = crate::dkg::reshare::Mailbox<TestBlock, TestBlsVariant, PrivateKey>;
    type TestInclusionStore =
        Store<deterministic::Context, MemorySecretStore, TestBlsVariant, PublicKey>;

    /// Owns every resource that must remain live while an inclusion test runs.
    struct InclusionHarness {
        _network: Network<deterministic::Context, PublicKey>,
        actor: mocks::TestReshareActor,
        mailbox: TestInclusionMailbox,
        store: TestInclusionStore,
        info: Info<TestBlsVariant, PublicKey>,
        signed_log: SignedDealerLog<TestBlsVariant, PrivateKey>,
        public_key: PublicKey,
    }

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

    /// Hides its head while a gate delays stream materialization.
    #[derive(Clone)]
    struct GatedAncestry {
        blocks: VecDeque<Arc<TestBlock>>,
        gate: futures::future::Shared<oneshot::Receiver<()>>,
        started: Arc<Mutex<Option<oneshot::Sender<()>>>>,
        released: bool,
    }

    impl GatedAncestry {
        fn new(
            blocks: impl IntoIterator<Item = Arc<TestBlock>>,
            gate: oneshot::Receiver<()>,
        ) -> (Self, oneshot::Receiver<()>) {
            let (started, observed) = oneshot::channel();
            (
                Self {
                    blocks: blocks.into_iter().collect(),
                    gate: gate.shared(),
                    started: Arc::new(Mutex::new(Some(started))),
                    released: false,
                },
                observed,
            )
        }
    }

    impl futures::Stream for GatedAncestry {
        type Item = Arc<TestBlock>;

        fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            if let Some(started) = self.started.lock().take() {
                let _ = started.send(());
            }
            if !self.released {
                if self.gate.poll_unpin(cx).is_pending() {
                    return Poll::Pending;
                }
                self.released = true;
            }
            Poll::Ready(self.blocks.pop_front())
        }
    }

    impl marshal::ancestry::Ancestry<TestBlock> for GatedAncestry {
        fn peek(&self) -> Option<&TestBlock> {
            self.released
                .then(|| self.blocks.front().map(Arc::as_ref))
                .flatten()
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
            Reveal::V1,
            players(),
            players(),
        )
        .expect("valid info")
    }

    fn empty_ancestry() -> BoxedAncestry<TestBlock> {
        BoxedAncestry::new(marshal::ancestry::from_iter(Vec::<Arc<TestBlock>>::new()))
    }

    fn scan(
        info: &Info<TestBlsVariant, PublicKey>,
    ) -> PendingLogScan<'_, TestBlsVariant, PublicKey, mocks::TestDigest> {
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

    /// Builds a singleton inclusion actor with one authenticated local dealer log.
    async fn setup_inclusion_harness(
        context: &mut deterministic::Context,
        partition_prefix: &str,
        blocks_per_epoch: NonZeroU64,
    ) -> InclusionHarness {
        let signer = PrivateKey::from_seed(0);
        let public_key = signer.public_key();
        let participants = Set::from_iter_dedup([public_key.clone()]);
        let info = Info::new::<N3f1>(
            TEST_NAMESPACE,
            0,
            None,
            SharingMode::NonZeroCounter,
            Reveal::V1,
            participants.clone(),
            participants.clone(),
        )
        .expect("valid singleton info");
        let secret_store = MemorySecretStore::default();
        let mut store = mocks::store(
            context.child("store"),
            &format!("{partition_prefix}-store"),
            secret_store.clone(),
        )
        .await;

        // Complete self-dealing so ancestry fixtures can carry a fully
        // authenticated log without depending on the actor's dealing phase.
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
        let Ok(ack) = player
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
            Ok(AckOutcome::Recorded)
        ));
        assert!(dealer.finalize::<N3f1>());
        let signed_log = dealer.finalized().expect("signed dealer log");

        // The inclusion actor is driven directly by its mailbox. Its marshal
        // handle remains readable but has no running actor, while the simulated
        // network stays alive for the manager and blocker handles it owns.
        let fixture = mocks::scheme_fixture_n(context, 1);
        let marshal = mocks::closed_marshal_mailbox(
            context.child("marshal"),
            &signer,
            fixture.schemes[0].clone(),
            partition_prefix,
            blocks_per_epoch,
        )
        .await;
        let (network, oracle) = Network::new_with_peers(
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
        let (actor, mailbox) = mocks::TestReshareActor::new_dkg(
            context.child("actor"),
            Config {
                signer,
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
                reveal: Reveal::V1,
                mailbox_size: NZUsize!(16),
                partition_prefix: partition_prefix.into(),
                page_cache: mocks::page_cache(context),
                write_buffer: mocks::IO_BUFFER,
                replay_buffer: mocks::IO_BUFFER,
                max_participants: NZU32!(16),
                blocks_per_epoch,
                batch_verifier: PhantomData,
            },
            DkgConfig {
                participants,
                directory: Unit,
                completion: Box::new(|_| {}),
            },
        );

        InclusionHarness {
            _network: network,
            actor,
            mailbox,
            store,
            info,
            signed_log,
            public_key,
        }
    }

    /// Reports a finalized block and returns its acknowledgement waiter.
    fn deliver(
        mailbox: &mut TestInclusionMailbox,
        block: &Arc<TestBlock>,
    ) -> <Exact as Acknowledgement>::Waiter {
        let (ack, waiter) = Exact::handle();
        assert_eq!(
            mailbox.report(marshal::Update::Block(block.clone(), ack)),
            Feedback::Ok
        );
        waiter
    }

    /// Marshal can redeliver finalized blocks after the actor has moved past them. Each receipt
    /// is acknowledged, and a block from an earlier phase or epoch does not re-enter its handler.
    /// The DKG-mode harness is required for an epoch-zero final block without epoch info, while
    /// the dealing and inclusion handlers it drives are shared by both modes.
    #[test]
    fn redelivered_receipts_survive_phase_changes() {
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|mut context| async move {
            let InclusionHarness {
                _network,
                mut actor,
                mut mailbox,
                mut store,
                info,
                public_key,
                ..
            } = setup_inclusion_harness(&mut context, "redelivered-receipts", NZU64!(4)).await;

            // Epoch zero spans heights 0..=3 and epoch one spans 4..=7. Each early phase ends one
            // block before its epoch midpoint.
            let mut blocks = vec![Arc::new(mocks::genesis_block(public_key.clone()))];
            while blocks.len() < 6 {
                blocks.push(Arc::new(child(blocks.last().unwrap())));
            }

            // Dealing completes epoch zero's early phase.
            let receipts = [0, 1].map(|height| deliver(&mut mailbox, &blocks[height]));
            assert!(
                actor
                    .dealing(
                        Epoch::zero(),
                        &mut store,
                        None,
                        None,
                        inert_channel([public_key.clone()]),
                    )
                    .await
                    .is_continue()
            );
            for receipt in receipts {
                receipt.await.expect("early receipt must be acknowledged");
            }

            // Inclusion receives a redelivered early block and a repeated midpoint before the
            // final block completes the epoch.
            let receipts = [1, 2, 2, 3].map(|height| deliver(&mut mailbox, &blocks[height]));
            assert!(
                actor
                    .inclusion(Epoch::zero(), &info, &mut store, None)
                    .await
                    .is_continue()
            );
            for receipt in receipts {
                receipt
                    .await
                    .expect("inclusion receipt must be acknowledged");
            }

            // The next epoch's dealing receives redelivered epoch-zero blocks before its own
            // early phase.
            let receipts = [2, 3, 4, 5].map(|height| deliver(&mut mailbox, &blocks[height]));
            assert!(
                actor
                    .dealing(
                        Epoch::new(1),
                        &mut store,
                        None,
                        None,
                        inert_channel([public_key]),
                    )
                    .await
                    .is_continue()
            );
            for receipt in receipts {
                receipt
                    .await
                    .expect("next-epoch receipt must be acknowledged");
            }
        });
    }

    /// Inclusion entered from dealing inherits the covered prefix, so a boundary request is
    /// served before inclusion finalizes a block of its own. The harness marshal has no running
    /// actor, so inclusion cannot learn the prefix from marshal's processed position.
    #[test]
    fn inclusion_serves_requests_on_entry() {
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|mut context| async move {
            let InclusionHarness {
                _network,
                mut actor,
                mut mailbox,
                mut store,
                info,
                public_key,
                ..
            } = setup_inclusion_harness(&mut context, "inclusion-entry", NZU64!(4)).await;

            // Epoch zero spans heights 0..=3 with its midpoint at 2.
            let mut blocks = vec![Arc::new(mocks::genesis_block(public_key.clone()))];
            while blocks.len() < 3 {
                blocks.push(Arc::new(child(blocks.last().unwrap())));
            }

            // Dealing covers every block below the midpoint.
            let receipts = [0, 1].map(|height| deliver(&mut mailbox, &blocks[height]));
            assert!(
                actor
                    .dealing(
                        Epoch::zero(),
                        &mut store,
                        None,
                        None,
                        inert_channel([public_key]),
                    )
                    .await
                    .is_continue()
            );
            for receipt in receipts {
                receipt.await.expect("early receipt must be acknowledged");
            }

            // A proposal for the final block asks for epoch info before inclusion finalizes
            // any block of its own.
            let _inclusion = context.child("inclusion").spawn(|_| async move {
                actor
                    .inclusion(Epoch::zero(), &info, &mut store, None)
                    .await
            });
            let response = mailbox
                .epoch_info(marshal::ancestry::from_iter([blocks[2].clone()]))
                .await;
            assert!(matches!(response, EpochInfoResponse::Available(_)));
        });
    }

    /// Marshal finalizes one block per height, so a finalized block that conflicts with the
    /// covered tip at its height is a contract violation. The actor panics instead of
    /// acknowledging it as covered.
    #[test]
    #[should_panic(expected = "conflicting finalized block")]
    fn conflicting_redelivery_panics() {
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|mut context| async move {
            let InclusionHarness {
                _network,
                mut actor,
                mut mailbox,
                mut store,
                info,
                public_key,
                ..
            } = setup_inclusion_harness(&mut context, "conflicting-redelivery", NZU64!(4)).await;

            // Dealing covers genesis and its canonical child, the last block before the midpoint.
            let genesis = Arc::new(mocks::genesis_block(public_key.clone()));
            let canonical = Arc::new(child(&genesis));
            let receipts = [&genesis, &canonical].map(|block| deliver(&mut mailbox, block));
            assert!(
                actor
                    .dealing(
                        Epoch::zero(),
                        &mut store,
                        None,
                        None,
                        inert_channel([public_key]),
                    )
                    .await
                    .is_continue()
            );
            for receipt in receipts {
                receipt.await.expect("early receipt must be acknowledged");
            }

            // A sibling shares the canonical block's parent and height but not its digest.
            let sibling = Arc::new(TestBlock::new::<Sha256>(
                genesis.context().clone(),
                genesis.digest(),
                Height::new(1),
                u64::MAX,
            ));
            assert_ne!(sibling.digest(), canonical.digest());

            // Inclusion receives the sibling at the covered tip's height.
            let _receipt = deliver(&mut mailbox, &sibling);
            let _ = actor
                .inclusion(Epoch::zero(), &info, &mut store, None)
                .await;
        });
    }

    /// A follower covers the boundary it commits, so setup resumes in the next epoch and that
    /// epoch acknowledges a redelivered boundary without handling it as a block of its own. The
    /// harness is built in DKG mode although follow and setup run only in reshare mode. None of
    /// the three handlers it drives reads the mode, so they behave as they would under reshare.
    #[test]
    fn follower_boundary_redelivery_is_acknowledged() {
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|mut context| async move {
            let InclusionHarness {
                _network,
                mut actor,
                mut mailbox,
                mut store,
                public_key,
                ..
            } = setup_inclusion_harness(&mut context, "follower-redelivery", NZU64!(4)).await;

            // Epoch zero's final block carries epoch one's public info.
            let participants = Set::from_iter_dedup([public_key.clone()]);
            let (output, _) = deal::<TestBlsVariant, _, N3f1>(
                TestRng::new(0),
                SharingMode::NonZeroCounter,
                participants.clone(),
            )
            .expect("trusted sharing");
            let next = EpochInfo {
                outcome: EpochOutcome::Success,
                epoch: Epoch::new(1),
                output,
                players: participants.clone(),
                next_players: participants,
                directory: Unit,
            };
            let mut blocks = vec![Arc::new(mocks::genesis_block(public_key.clone()))];
            while blocks.len() < 3 {
                blocks.push(Arc::new(child(blocks.last().unwrap())));
            }
            blocks.push(Arc::new(
                child(&blocks[2]).with_payload::<Sha256, TestBlsVariant, PrivateKey>(
                    NZU32!(16),
                    Payload::EpochInfo(next),
                ),
            ));
            while blocks.len() < 6 {
                blocks.push(Arc::new(child(blocks.last().unwrap())));
            }

            // Following acknowledges a repeated block and commits epoch one at the boundary.
            let receipts = [0, 1, 1, 2, 3].map(|height| deliver(&mut mailbox, &blocks[height]));
            assert!(actor.follow(&mut store).await.is_continue());
            for receipt in receipts {
                receipt
                    .await
                    .expect("follower receipt must be acknowledged");
            }
            assert_eq!(store.current().map(|info| info.epoch), Some(Epoch::new(1)));

            // Setup resumes at the first height after the covered boundary.
            let Some(Setup::Participate(prepared)) = actor.setup(&mut store, None).await else {
                panic!("setup must prepare the next epoch");
            };
            assert_eq!(prepared.epoch, Epoch::new(1));
            assert_eq!(prepared.phase, EpochPhase::Early);

            // The next epoch's dealing receives the redelivered boundary before its own early
            // phase.
            let receipts = [3, 4, 5].map(|height| deliver(&mut mailbox, &blocks[height]));
            assert!(
                actor
                    .dealing(
                        Epoch::new(1),
                        &mut store,
                        None,
                        None,
                        inert_channel([public_key]),
                    )
                    .await
                    .is_continue()
            );
            for receipt in receipts {
                receipt
                    .await
                    .expect("next-epoch receipt must be acknowledged");
            }
        });
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
    fn closed_terminal_verification_exits_without_acknowledging() {
        let executor = deterministic::Runner::new(
            deterministic::Config::default()
                .with_timeout(Some(Duration::from_secs(30)))
                .with_catch_panics(true),
        );
        executor.start(|mut context| async move {
            let InclusionHarness {
                _network,
                mut actor,
                mut mailbox,
                mut store,
                info,
                signed_log: _,
                public_key,
            } = setup_inclusion_harness(&mut context, "closed-verification", NZU64!(6)).await;

            // A task context whose owning task has exited rejects descendants
            // with Error::Closed.
            let closed_context = context
                .child("closed_context")
                .spawn(|context| async move { context })
                .await
                .expect("context task should finish");
            actor.context = ContextCell::new(closed_context);

            let genesis = mocks::genesis_block(public_key);
            let final_block = Arc::new(TestBlock::new::<Sha256>(
                genesis.context().clone(),
                genesis.digest(),
                Height::new(5),
                1,
            ));
            let inclusion = context.child("inclusion").spawn(|_| async move {
                let result = actor
                    .inclusion(Epoch::zero(), &info, &mut store, None)
                    .await;
                (result, store)
            });

            let (final_ack, final_waiter) = Exact::handle();
            assert_eq!(
                mailbox.report(marshal::Update::Block(final_block, final_ack)),
                Feedback::Ok
            );
            assert!(
                final_waiter.await.is_err(),
                "canceled finalization must remain unacknowledged"
            );
            let (result, store) = inclusion
                .await
                .expect("canceled verification should stop inclusion cleanly");
            assert!(result.is_break());
            assert!(store.current().is_none());
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
    fn unanchored_or_delayed_ancestry_does_not_block_finalization() {
        let executor = deterministic::Runner::timed(Duration::from_secs(30));
        executor.start(|mut context| async move {
            let InclusionHarness {
                _network,
                mut actor,
                mut mailbox,
                mut store,
                info,
                signed_log,
                public_key,
            } = setup_inclusion_harness(&mut context, "inclusion-actor", NZU64!(6)).await;

            // Build canonical and detached histories over the same pre-midpoint
            // prefix. Only the detached midpoint carries the dealer log.
            let genesis = mocks::genesis_block(public_key);
            let common_parent = TestBlock::new::<Sha256>(
                genesis.context().clone(),
                genesis.digest(),
                Height::new(1),
                1,
            );
            let canonical_two = TestBlock::new::<Sha256>(
                genesis.context().clone(),
                common_parent.digest(),
                Height::new(2),
                2,
            );
            let canonical_midpoint = Arc::new(TestBlock::new::<Sha256>(
                genesis.context().clone(),
                canonical_two.digest(),
                Height::new(3),
                3,
            ));
            let canonical_four = Arc::new(TestBlock::new::<Sha256>(
                genesis.context().clone(),
                canonical_midpoint.digest(),
                Height::new(4),
                4,
            ));
            let final_block = Arc::new(TestBlock::new::<Sha256>(
                genesis.context().clone(),
                canonical_four.digest(),
                Height::new(5),
                5,
            ));

            let detached_midpoint = Arc::new(
                TestBlock::new::<Sha256>(
                    genesis.context().clone(),
                    canonical_two.digest(),
                    Height::new(3),
                    6,
                )
                .with_payload::<Sha256, TestBlsVariant, PrivateKey>(
                    NZU32!(16),
                    Payload::DealerLog(signed_log),
                ),
            );
            let detached_four = Arc::new(TestBlock::new::<Sha256>(
                genesis.context().clone(),
                detached_midpoint.digest(),
                Height::new(4),
                7,
            ));
            // Admit the detached boundary request before the actor starts. It
            // must wait until finalized reporting establishes an exact anchor.
            let mut detached_mailbox = mailbox.clone();
            let detached = detached_mailbox.epoch_info(marshal::ancestry::from_iter([
                detached_four,
                detached_midpoint,
            ]));
            futures::pin_mut!(detached);
            assert!(detached.as_mut().now_or_never().is_none());

            let inclusion = context.child("inclusion").spawn(|_| async move {
                let result = actor
                    .inclusion(Epoch::zero(), &info, &mut store, None)
                    .await;
                (result, store)
            });

            // A verification candidate without its parent is truncated before
            // the actor can reconstruct the boundary view.
            let mut malformed_mailbox = mailbox.clone();
            let malformed =
                malformed_mailbox.epoch_info(marshal::ancestry::from_iter([final_block.clone()]));
            futures::pin_mut!(malformed);
            assert!(malformed.as_mut().now_or_never().is_none());

            context.sleep(Duration::from_millis(1)).await;
            assert!(
                detached.as_mut().now_or_never().is_none(),
                "unanchored ancestry completed before the canonical prefix arrived"
            );

            // Finalizing the canonical midpoint establishes the conflicting
            // anchor and resolves the detached request as unavailable.
            let (midpoint_ack, midpoint_waiter) = Exact::handle();
            assert_eq!(
                mailbox.report(marshal::Update::<TestBlock, Exact>::Block(
                    canonical_midpoint,
                    midpoint_ack,
                )),
                Feedback::Ok
            );
            midpoint_waiter
                .await
                .expect("canonical midpoint should be acknowledged");
            assert!(matches!(detached.await, EpochInfoResponse::Unavailable));
            assert!(matches!(malformed.await, EpochInfoResponse::Unavailable));

            // The actor owns the request while its selected scan waits for the
            // parent, so finalized reporting must remain independent.
            let (release, gate) = oneshot::channel();
            let (ancestry, ancestry_started) = GatedAncestry::new([canonical_four.clone()], gate);
            let mut canonical_mailbox = mailbox.clone();
            let canonical = canonical_mailbox.epoch_info(ancestry);
            futures::pin_mut!(canonical);
            assert!(canonical.as_mut().now_or_never().is_none());
            ancestry_started
                .await
                .expect("request should await the delayed parent");

            let (parent_ack, parent_waiter) = Exact::handle();
            assert_eq!(
                mailbox.report(marshal::Update::Block(canonical_four.clone(), parent_ack)),
                Feedback::Ok
            );
            parent_waiter
                .await
                .expect("canonical parent should be acknowledged");
            assert!(canonical.as_mut().now_or_never().is_none());

            // Once the ancestry yields the canonical parent, the actor can
            // answer from the finalized state without walking any farther.
            release.send(()).expect("ancestry should still be waiting");
            let response = select! {
                response = canonical.as_mut() => response,
                _ = context.sleep(Duration::from_secs(1)) => {
                    panic!("delayed ancestry did not resume");
                },
            };
            assert!(matches!(response, EpochInfoResponse::Available(None)));

            // Finalization cannot classify an ancestry that has not yielded its
            // parent. Leave that verification pending instead of blocking the
            // reporter or manufacturing a stable verdict.
            let (terminal_release, terminal_gate) = oneshot::channel();
            let (terminal_ancestry, terminal_started) =
                GatedAncestry::new([canonical_four.clone()], terminal_gate);
            let mut terminal_mailbox = mailbox.clone();
            let terminal = terminal_mailbox.epoch_info(terminal_ancestry);
            futures::pin_mut!(terminal);
            assert!(terminal.as_mut().now_or_never().is_none());
            terminal_started
                .await
                .expect("terminal ancestry scan should start");

            let (final_ack, final_waiter) = Exact::handle();
            assert_eq!(
                mailbox.report(marshal::Update::Block(final_block, final_ack)),
                Feedback::Ok
            );
            final_waiter
                .await
                .expect("final block should be acknowledged");
            assert!(matches!(terminal.await, EpochInfoResponse::Pending));
            assert!(terminal_release.send(()).is_err());
            let (result, store) = inclusion.await.expect("inclusion should finish");
            assert!(result.is_continue());
            assert!(store.current().is_none());
        });
    }

    #[test]
    fn ready_scan_yields_to_admitted_finalization() {
        let executor = deterministic::Runner::timed(Duration::from_secs(30));
        executor.start(|mut context| async move {
            let InclusionHarness {
                _network,
                mut actor,
                mut mailbox,
                mut store,
                info,
                signed_log,
                public_key,
            } = setup_inclusion_harness(&mut context, "ready-scan", NZU64!(8)).await;

            // Build canonical and competing inclusion histories. Only the
            // competing history carries a valid dealer log.
            let genesis = mocks::genesis_block(public_key);
            let common_parent = TestBlock::new::<Sha256>(
                genesis.context().clone(),
                genesis.digest(),
                Height::new(1),
                1,
            );
            let canonical_two = TestBlock::new::<Sha256>(
                genesis.context().clone(),
                common_parent.digest(),
                Height::new(2),
                2,
            );
            let canonical_three = TestBlock::new::<Sha256>(
                genesis.context().clone(),
                canonical_two.digest(),
                Height::new(3),
                3,
            );
            let canonical_midpoint = Arc::new(TestBlock::new::<Sha256>(
                genesis.context().clone(),
                canonical_three.digest(),
                Height::new(4),
                4,
            ));
            let canonical_five = Arc::new(TestBlock::new::<Sha256>(
                genesis.context().clone(),
                canonical_midpoint.digest(),
                Height::new(5),
                5,
            ));
            let canonical_six = Arc::new(TestBlock::new::<Sha256>(
                genesis.context().clone(),
                canonical_five.digest(),
                Height::new(6),
                6,
            ));
            let canonical_final = Arc::new(TestBlock::new::<Sha256>(
                genesis.context().clone(),
                canonical_six.digest(),
                Height::new(7),
                7,
            ));
            let losing_five = Arc::new(
                TestBlock::new::<Sha256>(
                    genesis.context().clone(),
                    canonical_midpoint.digest(),
                    Height::new(5),
                    8,
                )
                .with_payload::<Sha256, TestBlsVariant, PrivateKey>(
                    NZU32!(16),
                    Payload::DealerLog(signed_log),
                ),
            );
            let losing_six = Arc::new(TestBlock::new::<Sha256>(
                genesis.context().clone(),
                losing_five.digest(),
                Height::new(6),
                9,
            ));

            // Establish the midpoint before requesting speculative boundary
            // artifacts so scans can anchor to the canonical durable prefix.
            let inclusion = context.child("inclusion").spawn(|_| async move {
                let result = actor
                    .inclusion(Epoch::zero(), &info, &mut store, None)
                    .await;
                (result, store)
            });
            let (midpoint_ack, midpoint_waiter) = Exact::handle();
            assert_eq!(
                mailbox.report(marshal::Update::<TestBlock, Exact>::Block(
                    canonical_midpoint,
                    midpoint_ack,
                )),
                Feedback::Ok
            );
            midpoint_waiter
                .await
                .expect("canonical midpoint should be acknowledged");

            // Prime the exact losing-view cache, then hold a second scan of that
            // view at its first stream poll.
            let mut prime_mailbox = mailbox.clone();
            let primed = prime_mailbox
                .epoch_info(marshal::ancestry::from_iter([
                    losing_six.clone(),
                    losing_five.clone(),
                ]))
                .await;
            assert!(matches!(
                primed,
                EpochInfoResponse::Available(Some(Payload::EpochInfo(_)))
            ));

            let (release, gate) = oneshot::channel();
            let (tail, scan_started) = GatedAncestry::new([losing_five], gate);
            let ancestry = marshal::ancestry::with_prefix([losing_six], tail);
            let mut raced_mailbox = mailbox.clone();
            let raced = raced_mailbox.epoch_info(ancestry);
            futures::pin_mut!(raced);
            assert!(raced.as_mut().now_or_never().is_none());
            scan_started.await.expect("scan should start");
            assert!(raced.as_mut().now_or_never().is_none());

            // Make the canonical finalization and the stale scan ready in the
            // same scheduler turn. Finalization must invalidate the unmaterialized
            // scan before its cached losing-view result can escape.
            let (five_ack, five_waiter) = Exact::handle();
            assert_eq!(
                mailbox.report(marshal::Update::Block(canonical_five, five_ack)),
                Feedback::Ok
            );
            release.send(()).expect("scan should still be active");
            five_waiter
                .await
                .expect("canonical inclusion block should be acknowledged");
            assert!(matches!(raced.await, EpochInfoResponse::Unavailable));

            let (six_ack, six_waiter) = Exact::handle();
            assert_eq!(
                mailbox.report(marshal::Update::Block(canonical_six, six_ack)),
                Feedback::Ok
            );
            six_waiter
                .await
                .expect("canonical parent should be acknowledged");

            let (final_ack, final_waiter) = Exact::handle();
            assert_eq!(
                mailbox.report(marshal::Update::Block(canonical_final, final_ack)),
                Feedback::Ok
            );
            final_waiter
                .await
                .expect("canonical final block should be acknowledged");
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
    fn artifact_scan_cancels_stalled_ancestry_when_response_closes() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let info = info();
            let (response, receiver) = oneshot::channel::<TestResponse>();
            let request = ArtifactRequest {
                span: Span::none(),
                ancestry: BoxedAncestry::new(StalledAncestry),
                response,
            };
            let mut artifact_scan = ArtifactScan::default();
            artifact_scan.start(scan(&info), request, context.stopped());
            assert!((&mut artifact_scan).now_or_never().is_none());

            drop(receiver);

            assert!((&mut artifact_scan).await.is_none());
            assert!(artifact_scan.take_request().is_some());
        });
    }

    #[test]
    fn pending_logs_cancels_stalled_ancestry_when_runtime_stops() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let info = info();
            let pending = pending_logs(scan(&info), StalledAncestry, context.stopped());
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
    fn pending_logs_rejects_ancestry_truncated_before_inclusion_start() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let info = info();
            let genesis = mocks::genesis_block(signers()[0].public_key());
            let block_four = TestBlock::new::<Sha256>(
                genesis.context().clone(),
                genesis.digest(),
                Height::new(4),
                4,
            );
            let block_five = TestBlock::new::<Sha256>(
                genesis.context().clone(),
                block_four.digest(),
                Height::new(5),
                5,
            );
            let block_six = TestBlock::new::<Sha256>(
                genesis.context().clone(),
                block_five.digest(),
                Height::new(6),
                6,
            );
            let ancestry = Box::pin(stream::iter([Arc::new(block_six), Arc::new(block_five)]));
            let scan = PendingLogScan {
                epoch: Epoch::zero(),
                info: &info,
                epocher: FixedEpocher::new(NZU64!(8)),
                finalized_tip: None,
                final_height: Height::new(7),
            };

            assert!(
                pending_logs(scan, ancestry, context.stopped())
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
            let block_four = TestBlock::new::<Sha256>(
                genesis.context().clone(),
                genesis.digest(),
                Height::new(4),
                4,
            );
            let block_five = TestBlock::new::<Sha256>(
                genesis.context().clone(),
                block_four.digest(),
                Height::new(5),
                5,
            );
            let block_six = TestBlock::new::<Sha256>(
                genesis.context().clone(),
                block_five.digest(),
                Height::new(6),
                6,
            );
            let ancestry = Box::pin(
                stream::iter([Arc::new(block_six), Arc::new(block_five)]).chain(stream::pending()),
            );
            let scan = PendingLogScan {
                epoch: Epoch::zero(),
                info: &info,
                epocher: FixedEpocher::new(NZU64!(8)),
                finalized_tip: Some(FinalizedTip {
                    height: Height::new(4),
                    digest: block_four.digest(),
                }),
                final_height: Height::new(7),
            };

            assert!(
                pending_logs(scan, ancestry, context.stopped())
                    .now_or_never()
                    .is_some_and(|logs| logs.is_some_and(|logs| logs.is_empty()))
            );
        });
    }

    #[test]
    fn pending_logs_authenticates_a_fully_finalized_parent() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let info = info();
            let genesis = mocks::genesis_block(signers()[0].public_key());
            let canonical = Arc::new(TestBlock::new::<Sha256>(
                genesis.context().clone(),
                genesis.digest(),
                Height::new(6),
                6,
            ));
            let detached = Arc::new(TestBlock::new::<Sha256>(
                genesis.context().clone(),
                genesis.digest(),
                Height::new(6),
                7,
            ));
            assert_ne!(canonical.digest(), detached.digest());

            let scan = |digest| PendingLogScan {
                epoch: Epoch::zero(),
                info: &info,
                epocher: FixedEpocher::new(NZU64!(8)),
                finalized_tip: Some(FinalizedTip {
                    height: Height::new(6),
                    digest,
                }),
                final_height: Height::new(7),
            };

            assert!(
                pending_logs(
                    scan(canonical.digest()),
                    Box::pin(stream::iter([canonical.clone()])),
                    context.stopped(),
                )
                .await
                .is_some_and(|logs| logs.is_empty())
            );
            assert!(
                pending_logs(
                    scan(canonical.digest()),
                    Box::pin(stream::iter([detached])),
                    context.stopped(),
                )
                .await
                .is_none()
            );
        });
    }

    #[test]
    fn pending_logs_accepts_verification_candidate_before_parent() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let info = info();
            let genesis = mocks::genesis_block(signers()[0].public_key());
            let canonical = Arc::new(TestBlock::new::<Sha256>(
                genesis.context().clone(),
                genesis.digest(),
                Height::new(6),
                6,
            ));
            let candidate = Arc::new(TestBlock::new::<Sha256>(
                genesis.context().clone(),
                canonical.digest(),
                Height::new(7),
                7,
            ));
            let scan = PendingLogScan {
                epoch: Epoch::zero(),
                info: &info,
                epocher: FixedEpocher::new(NZU64!(8)),
                finalized_tip: Some(FinalizedTip {
                    height: Height::new(6),
                    digest: canonical.digest(),
                }),
                final_height: Height::new(7),
            };

            assert!(
                pending_logs(
                    scan,
                    Box::pin(stream::iter([candidate, canonical])),
                    context.stopped(),
                )
                .await
                .is_some_and(|logs| logs.is_empty())
            );
        });
    }

    #[test]
    fn pending_logs_rejects_view_detached_by_finalization() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let info = info();
            let genesis = mocks::genesis_block(signers()[0].public_key());
            let canonical_four = TestBlock::new::<Sha256>(
                genesis.context().clone(),
                genesis.digest(),
                Height::new(4),
                4,
            );
            let losing_four = TestBlock::new::<Sha256>(
                genesis.context().clone(),
                genesis.digest(),
                Height::new(4),
                5,
            );
            assert_ne!(canonical_four.digest(), losing_four.digest());
            let block_five = TestBlock::new::<Sha256>(
                genesis.context().clone(),
                losing_four.digest(),
                Height::new(5),
                6,
            );
            let block_six = TestBlock::new::<Sha256>(
                genesis.context().clone(),
                block_five.digest(),
                Height::new(6),
                7,
            );
            let ancestry = Box::pin(stream::iter([Arc::new(block_six), Arc::new(block_five)]));
            let scan = PendingLogScan {
                epoch: Epoch::zero(),
                info: &info,
                epocher: FixedEpocher::new(NZU64!(8)),
                finalized_tip: Some(FinalizedTip {
                    height: Height::new(4),
                    digest: canonical_four.digest(),
                }),
                final_height: Height::new(7),
            };

            assert!(
                pending_logs(scan, ancestry, context.stopped())
                    .await
                    .is_none()
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
        let (response_tx, response_rx) = oneshot::channel();
        let mut requests = TestRequests::default();
        requests.push(Span::none(), empty_ancestry(), response_tx);
        drop(response_rx);

        assert!(requests.pop().is_none());
    }

    #[test]
    fn requests_are_selected_in_arrival_order() {
        let (earlier_tx, earlier_rx) = oneshot::channel();
        let (later_tx, later_rx) = oneshot::channel();
        let mut requests = TestRequests::default();
        requests.push(Span::none(), empty_ancestry(), earlier_tx);
        requests.push(Span::none(), empty_ancestry(), later_tx);

        requests
            .pop()
            .expect("earlier request")
            .response
            .send_lossy(EpochInfoResponse::Pending);
        assert!(matches!(
            earlier_rx.now_or_never(),
            Some(Ok(EpochInfoResponse::Pending))
        ));
        assert!(later_rx.now_or_never().is_none());
    }

    #[test]
    fn draining_unmaterialized_requests_returns_pending() {
        let (response_tx, response_rx) = oneshot::channel::<TestResponse>();
        let mut requests = TestRequests::default();
        requests.push(Span::none(), empty_ancestry(), response_tx);

        requests.drain_pending();
        assert!(matches!(
            response_rx.now_or_never(),
            Some(Ok(EpochInfoResponse::Pending))
        ));
    }

    struct FinalizationFixture {
        info: Info<TestBlsVariant, PublicKey>,
        current: EpochInfo<TestBlsVariant, PublicKey>,
        share: Share,
        logs: BTreeMap<PublicKey, DealerLog<TestBlsVariant, PublicKey>>,
        dealings: BTreeMap<PublicKey, (DealerPubMsg<TestBlsVariant>, DealerPrivMsg)>,
    }

    fn finalization_fixture(seed: u64) -> FinalizationFixture {
        // Build a prior sharing and a reshare round with the same dealer and player set.
        let signers = signers();
        let participants = players();
        let (previous, shares) = deal::<TestBlsVariant, _, N3f1>(
            TestRng::new(0),
            SharingMode::NonZeroCounter,
            participants.clone(),
        )
        .expect("trusted previous sharing");
        let info = Info::new::<N3f1>(
            TEST_NAMESPACE,
            0,
            Some(previous.clone()),
            SharingMode::NonZeroCounter,
            Reveal::V1,
            participants.clone(),
            participants.clone(),
        )
        .expect("valid reshare info");

        // Finalize an N3f1 quorum of dealer logs and retain each private dealing for the target.
        let mut logs = BTreeMap::new();
        let mut dealings = BTreeMap::new();

        for (dealer_index, dealer_signer) in signers.iter().take(3).enumerate() {
            let dealer_key = dealer_signer.public_key();
            let previous_share = shares
                .get_value(&dealer_key)
                .cloned()
                .expect("dealer has previous share");
            let (mut dealer, public, private) = CryptoDealer::<TestBlsVariant, _>::start::<N3f1>(
                TestRng::new(seed + dealer_index as u64),
                info.clone(),
                dealer_signer.clone(),
                Some(previous_share),
            )
            .expect("dealer should start");
            let target_private = private
                .iter()
                .find_map(|(recipient, private)| {
                    (recipient == &signers[0].public_key()).then(|| private.clone())
                })
                .expect("target dealing");
            dealings.insert(dealer_key.clone(), (public.clone(), target_private));

            for player_signer in signers.iter().take(3) {
                let player_key = player_signer.public_key();
                let private = private
                    .iter()
                    .find_map(|(recipient, private)| {
                        (recipient == &player_key).then(|| private.clone())
                    })
                    .expect("player dealing");
                let mut player =
                    CryptoPlayer::new(info.clone(), player_signer.clone()).expect("player");
                let ack = player
                    .dealer_message::<N3f1>(dealer_key.clone(), public.clone(), private)
                    .expect("valid dealing")
                    .expect("new dealing");
                dealer
                    .receive_player_ack(player_key, ack)
                    .expect("valid acknowledgement");
            }

            let signed = dealer.finalize::<N3f1>();
            let (checked_dealer, log) = signed.check(&info).expect("valid dealer log");
            logs.insert(checked_dealer, log);
        }

        // Preserve the prior successful output and target share for artifact recovery tests.
        let share = shares
            .get_value(&signers[0].public_key())
            .cloned()
            .expect("target has previous share");
        FinalizationFixture {
            info,
            current: EpochInfo {
                outcome: EpochOutcome::Success,
                epoch: Epoch::zero(),
                output: previous,
                players: participants.clone(),
                next_players: participants,
                directory: Unit,
            },
            share,
            logs,
            dealings,
        }
    }

    async fn setup_finalization_actor(
        context: deterministic::Context,
        signer: PrivateKey,
        participants: Set<PublicKey>,
        partition: &str,
    ) -> mocks::TestReshareActor {
        let (_network, oracle) = Network::new_with_peers(
            context.child("network"),
            NetworkConfig {
                max_size: 1024,
                max_peers_per_set: NZUsize!(participants.len()),
                disconnect_on_block: true,
                tracked_peer_sets: NZUsize!(1),
            },
            participants.iter().cloned(),
        )
        .await;
        let (actor, _mailbox) = utils::new_actor(
            context.child("actor_fixture"),
            signer,
            participants,
            &oracle,
            TEST_NAMESPACE,
            partition,
            NZU64!(8),
        )
        .await;
        actor
    }

    /// Recovered public logs remain usable when their private dealing snapshot is absent.
    #[test]
    fn missing_dealing_recovery_produces_shareless_success_artifact() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Persist a verified quorum of public logs and the target's matching private dealings.
            let fixture = finalization_fixture(10);
            let target = signers()[0].clone();
            let mut store: TestInclusionStore = mocks::store(
                context.child("store"),
                "missing-dealing-artifact",
                MemorySecretStore::default(),
            )
            .await;
            let mut player = store
                .create_player::<PrivateKey, N3f1>(
                    Epoch::zero(),
                    target.clone(),
                    fixture.info.clone(),
                )
                .expect("target is a player");
            for (dealer, (public, private)) in &fixture.dealings {
                player
                    .handle(
                        &mut store,
                        Epoch::zero(),
                        dealer.clone(),
                        public.clone(),
                        private.clone(),
                    )
                    .await
                    .expect("valid dealing");
            }
            for (dealer, log) in &fixture.logs {
                store
                    .append_log(Epoch::zero(), dealer.clone(), log.clone())
                    .await;
            }
            drop(store);

            // Replay the public journal against an empty secret store, omitting private dealings.
            let mut store: TestInclusionStore = mocks::store(
                context.child("restart"),
                "missing-dealing-artifact",
                MemorySecretStore::default(),
            )
            .await;

            // Reconstruct the ceremony as an observer with the prior successful epoch available.
            store
                .commit_epoch(
                    fixture.current,
                    Summary::random(TestRng::new(1)),
                    Some(fixture.share),
                )
                .await;
            let mut actor = setup_finalization_actor(
                context.child("artifact_actor"),
                target,
                players(),
                "missing-dealing-artifact-actor",
            )
            .await;
            let log_map = Arc::new(store.logs(Epoch::zero()));
            let task =
                actor.verification_task(Epoch::zero(), &fixture.info, &store, log_map.as_ref());
            let ceremony = task
                .run::<deterministic::Context, commonware_cryptography::ed25519::Batch>(
                    context.child("verification"),
                )
                .expect("observer should verify the public ceremony");
            assert!(ceremony.share.is_none());
            let expected = ceremony.output.clone();
            let mut artifacts = ArtifactCache::default();

            // Preserve the verified output while leaving the unavailable local share absent.
            let artifact = actor
                .artifact(
                    Epoch::zero(),
                    &mut store,
                    log_map,
                    Some(&ceremony),
                    &mut artifacts,
                )
                .await
                .expect("observer should produce a successful artifact");

            assert_eq!(artifact.info.outcome, EpochOutcome::Success);
            assert_eq!(artifact.info.output, expected);
            assert!(artifact.share.is_none());
        });
    }

    /// A protocol-level finalization failure carries the prior output and local share.
    #[test]
    fn finalization_failure_produces_failure_artifact() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Commit the last successful output and share without logs for the next ceremony.
            let fixture = finalization_fixture(20);
            let expected_output = fixture.current.output.clone();
            let expected_share = fixture.share.clone();
            let mut store: TestInclusionStore = mocks::store(
                context.child("store"),
                "finalization-failure-artifact",
                MemorySecretStore::default(),
            )
            .await;
            store
                .commit_epoch(
                    fixture.current,
                    Summary::random(TestRng::new(2)),
                    Some(fixture.share),
                )
                .await;

            // An empty dealer-log view cannot produce a ceremony result.
            let mut actor = setup_finalization_actor(
                context.child("artifact_actor"),
                signers()[0].clone(),
                players(),
                "finalization-failure-artifact-actor",
            )
            .await;
            let log_map = Arc::new(BTreeMap::new());
            let task =
                actor.verification_task(Epoch::zero(), &fixture.info, &store, log_map.as_ref());
            let ceremony = task
                .run::<deterministic::Context, commonware_cryptography::ed25519::Batch>(
                    context.child("verification"),
                );
            assert!(ceremony.is_none());
            let mut artifacts = ArtifactCache::default();

            // Continuous resharing carries the prior successful state into a failure artifact.
            let artifact = actor
                .artifact(
                    Epoch::zero(),
                    &mut store,
                    log_map,
                    ceremony.as_ref(),
                    &mut artifacts,
                )
                .await
                .expect("continuous reshare should carry forward a failed epoch");

            assert_eq!(artifact.info.outcome, EpochOutcome::Failure);
            assert_eq!(artifact.info.output, expected_output);
            assert_eq!(artifact.share, Some(expected_share));
        });
    }

    /// A selected dealing that conflicts with durable logs is invalid local state.
    #[test]
    #[should_panic(
        expected = "invalid local state while finalizing reshare player: InvalidPersistedDealing"
    )]
    fn finalization_error_panics() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Two valid ceremonies for the same round provide conflicting messages from one dealer.
            let persisted = finalization_fixture(30);
            let finalized = finalization_fixture(40);
            let target = signers()[0].clone();
            let mismatched_dealer = signers()[0].public_key();
            let mut store: TestInclusionStore = mocks::store(
                context.child("store"),
                "finalization-error-artifact",
                MemorySecretStore::default(),
            )
            .await;
            store
                .commit_epoch(
                    finalized.current,
                    Summary::random(TestRng::new(3)),
                    Some(finalized.share),
                )
                .await;
            let mut player = store
                .create_player::<PrivateKey, N3f1>(
                    Epoch::zero(),
                    target.clone(),
                    finalized.info.clone(),
                )
                .expect("target is a player");

            // Persist one private dealing from the alternate ceremony and the remaining finalized
            // dealings.
            for (dealer, (public, private)) in &finalized.dealings {
                let (public, private) = if dealer == &mismatched_dealer {
                    persisted
                        .dealings
                        .get(dealer)
                        .cloned()
                        .expect("alternate persisted dealing")
                } else {
                    (public.clone(), private.clone())
                };
                player
                    .handle(&mut store, Epoch::zero(), dealer.clone(), public, private)
                    .await
                    .expect("persisted dealing is valid for the round");
            }

            // The finalized public logs bind the resumed player to the conflicting dealer message.
            for (dealer, log) in &finalized.logs {
                store
                    .append_log(Epoch::zero(), dealer.clone(), log.clone())
                    .await;
            }
            let mut actor = setup_finalization_actor(
                context.child("artifact_actor"),
                target,
                players(),
                "finalization-error-artifact-actor",
            )
            .await;
            let log_map = Arc::new(store.logs(Epoch::zero()));
            let task =
                actor.verification_task(Epoch::zero(), &finalized.info, &store, log_map.as_ref());

            task.run::<deterministic::Context, commonware_cryptography::ed25519::Batch>(
                context.child("verification"),
            );
        });
    }
}
