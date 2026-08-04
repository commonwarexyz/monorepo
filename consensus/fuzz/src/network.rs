//! Helpers for preferential delivery of Byzantine messages in fuzz tests emulating
//! a faulty messaging layer (`FuzzMode::FaultyMessaging`).
//!
//! This module provides a simple wrapper around the simulated p2p receiver split
//! functionality.
//!
//! Messages originating from a configured set of Byzantine public keys are routed to the
//! "primary" receiver; all other messages are routed to the "secondary" receiver and may be dropped.
//! A [`ByzantineFirstReceiver`] then uses a biased select to always service the primary
//! receiver first when both have buffered messages.
//! [`NotarizeOmissionReceiver`] models one correct node that receives every
//! vote except notarize votes. [`WedgeReceiver`] holds the phase-gated rules of
//! the split-notarization scenario.
//!
//! Note: this is not a global total-order guarantee (the underlying network can still deliver
//! honest messages before Byzantine messages arrive). It does guarantee that, whenever both a
//! Byzantine message and an honest message are simultaneously available to be received, the
//! Byzantine message is delivered first.

use commonware_codec::{Decode, DecodeExt, Encode};
use commonware_consensus::{
    Block, Viewable,
    marshal::resolver::handler::Key as MarshalKey,
    simplex::{
        scheme::Scheme,
        types::{Certificate, Notarization, Notarize, Proposal, Vote},
    },
    types::{Epoch, Round, View},
};
use commonware_cryptography::{Digest, PublicKey};
use commonware_macros::select;
use commonware_p2p::{Message, Receiver, simulated::SplitTarget};
use commonware_parallel::Sequential;
use commonware_resolver::p2p::mocks::{Message as ResolverMessage, Payload as ResolverPayload};
use commonware_runtime::{Clock, deterministic};
use commonware_utils::{sequence::U64, sync::Mutex};
use rand::RngExt as _;
use rand_core::CryptoRng;
use std::{
    collections::{BTreeMap, HashSet},
    fmt,
    marker::PhantomData,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    time::{Duration, SystemTime},
};

/// Shared cell holding the currently-active honest-message drop rate (0..=90).
/// Updated by the `FaultyMessaging` scheduler on view boundaries; read on every
/// routing decision via [`Router::route`].
pub type DropRateCell = Arc<Mutex<u8>>;

/// Construct a fresh drop-rate cell initialized to 0 (no drop).
pub fn drop_rate_cell() -> DropRateCell {
    Arc::new(Mutex::new(0))
}

/// A filtering split-router that routes messages by origin public key, with a
/// shared cell controlling the per-view honest-message drop rate.
pub struct Router<P: PublicKey, E: CryptoRng + Send + 'static> {
    byzantine: Arc<HashSet<P>>,
    drop_rate: DropRateCell,
    context: Arc<Mutex<E>>,
}

impl<P: PublicKey, E: CryptoRng + Send + 'static> Router<P, E> {
    pub fn new(
        context: E,
        byzantine: impl IntoIterator<Item = P>,
        drop_rate: DropRateCell,
    ) -> Self {
        Self {
            byzantine: Arc::new(byzantine.into_iter().collect()),
            drop_rate,
            context: Arc::new(Mutex::new(context)),
        }
    }

    /// Route by message sender.
    pub fn route(&self, message: &Message<P>) -> SplitTarget {
        let (sender, _) = message;
        if self.byzantine.contains(sender) {
            SplitTarget::Primary
        } else {
            let rate = *self.drop_rate.lock();
            if rate > 0 && self.should_drop_honest_message(rate) {
                return SplitTarget::None;
            }
            SplitTarget::Secondary
        }
    }

    fn should_drop_honest_message(&self, rate: u8) -> bool {
        let mut context = self.context.lock();
        let sample = context.random_range(0..100u8);
        sample < rate
    }
}

impl<P: PublicKey, E: CryptoRng + Send + 'static> Clone for Router<P, E> {
    fn clone(&self) -> Self {
        Self {
            byzantine: self.byzantine.clone(),
            drop_rate: self.drop_rate.clone(),
            context: self.context.clone(),
        }
    }
}

/// A receiver that preferentially yields messages from the "primary" (Byzantine) lane.
#[derive(Debug)]
pub struct ByzantineFirstReceiver<P, R>
where
    P: PublicKey,
    R: Receiver<PublicKey = P>,
{
    primary: R,
    secondary: R,
}

impl<P, R> ByzantineFirstReceiver<P, R>
where
    P: PublicKey,
    R: Receiver<PublicKey = P>,
{
    pub const fn new(primary: R, secondary: R) -> Self {
        Self { primary, secondary }
    }
}

impl<P, R> Receiver for ByzantineFirstReceiver<P, R>
where
    P: PublicKey,
    R: Receiver<PublicKey = P>,
    R::Error: Send + Sync,
{
    type Error = R::Error;
    type PublicKey = P;

    async fn recv(&mut self) -> Result<Message<Self::PublicKey>, Self::Error> {
        select! {
            msg = self.primary.recv() => msg,
            msg = self.secondary.recv() => msg,
        }
    }
}

/// A receiver for a correct node in notarize-vote omission mode.
///
/// Validly encoded non-proposal votes and malformed messages are forwarded
/// unchanged. Every validly encoded notarize vote is omitted, regardless of
/// sender. Notarization certificates use a separate channel and are unaffected.
pub struct NotarizeOmissionReceiver<S, D, R>
where
    D: Digest,
    S: Scheme<D>,
    R: Receiver<PublicKey = S::PublicKey>,
{
    inner: R,
    omitted: Arc<AtomicUsize>,
    _scheme: PhantomData<fn() -> (S, D)>,
}

impl<S, D, R> NotarizeOmissionReceiver<S, D, R>
where
    D: Digest,
    S: Scheme<D>,
    R: Receiver<PublicKey = S::PublicKey>,
{
    pub const fn new(inner: R, omitted: Arc<AtomicUsize>) -> Self {
        Self {
            inner,
            omitted,
            _scheme: PhantomData,
        }
    }

    fn should_omit(&self, (_, message): &Message<S::PublicKey>) -> bool {
        matches!(Vote::<S, D>::decode(message.clone()), Ok(Vote::Notarize(_)))
    }
}

impl<S, D, R> std::fmt::Debug for NotarizeOmissionReceiver<S, D, R>
where
    D: Digest,
    S: Scheme<D>,
    R: Receiver<PublicKey = S::PublicKey>,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NotarizeOmissionReceiver").finish()
    }
}

impl<S, D, R> Receiver for NotarizeOmissionReceiver<S, D, R>
where
    D: Digest,
    S: Scheme<D>,
    R: Receiver<PublicKey = S::PublicKey>,
{
    type Error = R::Error;
    type PublicKey = S::PublicKey;

    async fn recv(&mut self) -> Result<Message<Self::PublicKey>, Self::Error> {
        loop {
            let message = self.inner.recv().await?;
            if self.should_omit(&message) {
                self.omitted.fetch_add(1, Ordering::Relaxed);
                continue;
            }
            return Ok(message);
        }
    }
}

/// Network path carrying an incoming finalization.
#[derive(Clone, Copy, Debug)]
pub enum FinalizationOmissionChannel {
    /// Direct Simplex certificate broadcast.
    Certificate,
    /// Resolver response whose payload is an encoded Simplex certificate.
    Resolver,
}

/// A receiver that omits incoming finalization certificates.
///
/// Malformed messages and every non-finalization message are forwarded
/// unchanged. Resolver requests and errors are also forwarded unchanged.
pub struct FinalizationOmissionReceiver<S, D, R>
where
    D: Digest,
    S: Scheme<D>,
    R: Receiver<PublicKey = S::PublicKey>,
{
    inner: R,
    scheme: S,
    channel: FinalizationOmissionChannel,
    omitted: Arc<AtomicUsize>,
    _digest: PhantomData<fn() -> D>,
}

impl<S, D, R> FinalizationOmissionReceiver<S, D, R>
where
    D: Digest,
    S: Scheme<D>,
    R: Receiver<PublicKey = S::PublicKey>,
{
    pub const fn new(
        inner: R,
        scheme: S,
        channel: FinalizationOmissionChannel,
        omitted: Arc<AtomicUsize>,
    ) -> Self {
        Self {
            inner,
            scheme,
            channel,
            omitted,
            _digest: PhantomData,
        }
    }

    fn is_finalization(&self, (_, message): &Message<S::PublicKey>) -> bool {
        let certificate = match self.channel {
            FinalizationOmissionChannel::Certificate => Certificate::<S, D>::decode_cfg(
                message.clone(),
                &self.scheme.certificate_codec_config(),
            )
            .ok(),
            FinalizationOmissionChannel::Resolver => {
                let Ok(message) = ResolverMessage::<U64>::decode(message.clone()) else {
                    return false;
                };
                let ResolverPayload::Response(response) = message.payload else {
                    return false;
                };
                Certificate::<S, D>::decode_cfg(response, &self.scheme.certificate_codec_config())
                    .ok()
            }
        };
        matches!(certificate, Some(Certificate::Finalization(_)))
    }
}

impl<S, D, R> std::fmt::Debug for FinalizationOmissionReceiver<S, D, R>
where
    D: Digest,
    S: Scheme<D>,
    R: Receiver<PublicKey = S::PublicKey>,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FinalizationOmissionReceiver")
            .field("channel", &self.channel)
            .finish()
    }
}

impl<S, D, R> Receiver for FinalizationOmissionReceiver<S, D, R>
where
    D: Digest,
    S: Scheme<D>,
    R: Receiver<PublicKey = S::PublicKey>,
{
    type Error = R::Error;
    type PublicKey = S::PublicKey;

    async fn recv(&mut self) -> Result<Message<Self::PublicKey>, Self::Error> {
        loop {
            let message = self.inner.recv().await?;
            if self.is_finalization(&message) {
                self.omitted.fetch_add(1, Ordering::Relaxed);
                continue;
            }
            return Ok(message);
        }
    }
}

/// Record of a poisoned certificate backfill response.
///
/// [`CertificatePoisonReceiver`] fills `view` with the view whose covering
/// nullification it replaced, and then counts the answers that could retire
/// that fetch: a response is only counted when it matches a request the
/// poisoned node actually sent for that view, identified by the
/// `(responder, request id)` pair the resolver itself matches on. Unsolicited
/// traffic and answers to other views cannot satisfy it, so a node that
/// re-fetched the poisoned view stays distinguishable from one whose fetch was
/// never retried.
///
/// Request ids are per-requester counters, so the ledger only ever holds the
/// poisoned node's requests: mixing requesters into one `(responder, id)` key
/// would let one node's request answer for another's.
#[derive(Clone, Debug)]
pub struct CertificatePoison<P: PublicKey> {
    view: Arc<Mutex<Option<View>>>,
    /// Requests seen in flight, keyed the way the resolver matches responses.
    requests: Arc<Mutex<BTreeMap<(P, u64), View>>>,
    retries_answered: Arc<AtomicUsize>,
}

impl<P: PublicKey> Default for CertificatePoison<P> {
    fn default() -> Self {
        Self {
            view: Arc::new(Mutex::new(None)),
            requests: Arc::new(Mutex::new(BTreeMap::new())),
            retries_answered: Arc::new(AtomicUsize::new(0)),
        }
    }
}

impl<P: PublicKey> CertificatePoison<P> {
    pub fn new() -> Self {
        Self::default()
    }

    /// View whose covering nullification was replaced, if the poison fired.
    pub fn view(&self) -> Option<View> {
        *self.view.lock()
    }

    /// Answers to a re-fetch of the poisoned view.
    pub fn retries_answered(&self) -> usize {
        self.retries_answered.load(Ordering::Relaxed)
    }

    /// Records a request `responder` was asked to serve.
    fn observe_request(&self, responder: &P, id: u64, view: View) {
        self.requests.lock().insert((responder.clone(), id), view);
    }

    /// Consumes the request a response answers, the way the resolver matches it.
    fn match_response(&self, responder: &P, id: u64) -> Option<View> {
        self.requests.lock().remove(&(responder.clone(), id))
    }
}

/// A receiver that answers one certificate backfill request with a valid
/// notarization for a proposal no node can supply.
///
/// Models the byzantine peer of the backfill attack: asked for the certificate
/// of a view the cluster nullified, it serves a genuine notarization instead of
/// the covering nullification. The notarization verifies, so the requester
/// accepts it and waits for its proposal to certify, but no node holds that
/// block, so certification never completes. Every later response is forwarded
/// unchanged: a node that re-fetches the view is answered honestly, which is
/// what separates a recoverable stall from a permanent one.
///
/// A node in `observer` mode never rewrites anything: it only records the
/// requests the poisoned node asks it to serve, which is how that node's
/// outbound fetches are tracked without reaching into its sender.
///
/// With `poison` unset the receiver forwards everything untouched.
pub struct CertificatePoisonReceiver<S, D, R>
where
    D: Digest,
    S: Scheme<D>,
    R: Receiver<PublicKey = S::PublicKey>,
{
    inner: R,
    /// Material for the replacement certificate; absent in observer mode.
    forge: Option<PoisonForge<S, D>>,
    poison: Option<CertificatePoison<S::PublicKey>>,
    /// Set when this node only observes the requests sent to it.
    observer: Option<RequestObserver<S::PublicKey>>,
}

/// Identity a receiver needs to record requests on the poisoned node's behalf.
struct RequestObserver<P> {
    /// The observing node, which is the responder the ledger is keyed on.
    me: P,
    /// The only requester whose fetches are recorded.
    tracked: P,
}

/// Signing material for the notarization a poisoned response carries.
struct PoisonForge<S, D> {
    schemes: Vec<S>,
    epoch: Epoch,
    payload: D,
}

impl<S, D, R> CertificatePoisonReceiver<S, D, R>
where
    D: Digest,
    S: Scheme<D>,
    R: Receiver<PublicKey = S::PublicKey>,
{
    pub const fn new(
        inner: R,
        schemes: Vec<S>,
        epoch: Epoch,
        payload: D,
        poison: Option<CertificatePoison<S::PublicKey>>,
    ) -> Self {
        Self {
            inner,
            forge: Some(PoisonForge {
                schemes,
                epoch,
                payload,
            }),
            poison,
            observer: None,
        }
    }

    /// Records the requests `tracked` asks `me` to serve, and rewrites nothing.
    pub const fn observer(
        inner: R,
        me: S::PublicKey,
        tracked: S::PublicKey,
        poison: Option<CertificatePoison<S::PublicKey>>,
    ) -> Self {
        Self {
            inner,
            forge: None,
            poison,
            observer: Some(RequestObserver { me, tracked }),
        }
    }

    /// Decodes a resolver request.
    fn request(&self, message: &commonware_runtime::IoBuf) -> Option<(u64, View)> {
        let resolver = ResolverMessage::<U64>::decode(message.clone()).ok()?;
        let ResolverPayload::Request(key) = resolver.payload else {
            return None;
        };
        Some((resolver.id, View::new(u64::from(&key))))
    }

    /// Decodes a resolver response carrying a Simplex certificate.
    fn response(&self, message: &commonware_runtime::IoBuf) -> Option<(u64, Certificate<S, D>)> {
        let resolver = ResolverMessage::<U64>::decode(message.clone()).ok()?;
        let ResolverPayload::Response(response) = resolver.payload else {
            return None;
        };
        let forge = self.forge.as_ref()?;
        let certificate = Certificate::<S, D>::decode_cfg(
            response,
            &forge.schemes.first()?.certificate_codec_config(),
        )
        .ok()?;
        Some((resolver.id, certificate))
    }

    /// A quorum notarization for `view` over a payload no node proposed. The
    /// requester cannot tell it from one the byzantine peer collected honestly.
    fn unavailable_notarization(&self, id: u64, view: View) -> Option<commonware_runtime::IoBuf> {
        let forge = self.forge.as_ref()?;
        let parent = View::new(view.get().checked_sub(1)?);
        let proposal = Proposal::new(Round::new(forge.epoch, view), parent, forge.payload);
        let quorum = crate::bounds::quorum(u32::try_from(forge.schemes.len()).ok()?) as usize;
        let notarizes = forge
            .schemes
            .iter()
            .take(quorum)
            .map(|scheme| Notarize::sign(scheme, proposal.clone()))
            .collect::<Option<Vec<_>>>()?;
        let notarization =
            Notarization::from_notarizes(forge.schemes.first()?, &notarizes, &Sequential)?;
        Some(
            ResolverMessage::<U64> {
                id,
                payload: ResolverPayload::Response(
                    Certificate::<S, D>::Notarization(notarization).encode(),
                ),
            }
            .encode()
            .into(),
        )
    }
}

impl<S, D, R> std::fmt::Debug for CertificatePoisonReceiver<S, D, R>
where
    D: Digest,
    S: Scheme<D>,
    R: Receiver<PublicKey = S::PublicKey>,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CertificatePoisonReceiver")
            .field("armed", &self.poison.is_some())
            .field("observer", &self.observer.is_some())
            .finish()
    }
}

impl<S, D, R> Receiver for CertificatePoisonReceiver<S, D, R>
where
    D: Digest,
    S: Scheme<D>,
    R: Receiver<PublicKey = S::PublicKey>,
{
    type Error = R::Error;
    type PublicKey = S::PublicKey;

    async fn recv(&mut self) -> Result<Message<Self::PublicKey>, Self::Error> {
        let (peer, message) = self.inner.recv().await?;
        let Some(poison) = self.poison.as_ref() else {
            return Ok((peer, message));
        };
        if let Some(observer) = self.observer.as_ref() {
            if peer == observer.tracked
                && let Some((id, view)) = self.request(&message)
            {
                poison.observe_request(&observer.me, id, view);
            }
            return Ok((peer, message));
        }
        let Some((id, certificate)) = self.response(&message) else {
            return Ok((peer, message));
        };
        let requested = poison.match_response(&peer, id);
        if let Some(poisoned_view) = poison.view() {
            // Only an answer to a fresh request for the poisoned view can
            // retire that fetch; anything else leaves it deduplicated.
            if requested == Some(poisoned_view) {
                poison.retries_answered.fetch_add(1, Ordering::Relaxed);
            }
            return Ok((peer, message));
        }
        let Certificate::Nullification(nullification) = certificate else {
            return Ok((peer, message));
        };
        let view = nullification.view();
        // Rewriting an answer to a request this node never sent attacks
        // nothing: the resolver discards it as unsolicited.
        if requested != Some(view) {
            return Ok((peer, message));
        }
        let Some(poisoned) = self.unavailable_notarization(id, view) else {
            return Ok((peer, message));
        };
        *poison.view.lock() = Some(view);
        Ok((peer, poisoned))
    }
}

/// Phase of the split-notarization scenario driven by [`WedgeReceiver`].
///
/// One shared flag gates every honest-message rule: they are armed before GST
/// and disarmed at it. Byzantine withholding is not phase-gated.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum WedgePhase {
    /// The victim is unreachable from every peer.
    Isolated,
    /// Links are restored while holder answers are still slow.
    Asynchronous,
    /// Every link is healed and every honest-message rule is disarmed.
    PostGst,
}

impl WedgePhase {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Isolated => "isolated",
            Self::Asynchronous => "async",
            Self::PostGst => "post-gst",
        }
    }

    const fn is_post_gst(self) -> bool {
        matches!(self, Self::PostGst)
    }
}

/// A node's part in the split-notarization scenario.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WedgeRole {
    /// Correct node that stores the attack block and notarizes it.
    Holder,
    /// Attack-view leader that alone assembles the attack notarization.
    Byzantine,
    /// Correct node that ends up holding the notarization and nothing else.
    Victim,
}

/// Network path a [`WedgeReceiver`] is wrapped around.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum WedgeChannel {
    /// Simplex votes.
    Vote,
    /// Simplex certificate broadcast.
    Certificate,
    /// Simplex certificate backfill.
    Resolver,
    /// Marshal block/certificate backfill.
    MarshalBackfill,
    /// Marshal block gossip.
    MarshalBroadcast,
}

impl WedgeChannel {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Vote => "vote",
            Self::Certificate => "certificate",
            Self::Resolver => "resolver",
            Self::MarshalBackfill => "marshal-backfill",
            Self::MarshalBroadcast => "marshal-broadcast",
        }
    }
}

/// Why a message was withheld.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum WedgeDrop {
    /// Attack-view notarize vote between the two holders.
    HolderNotarizeSplit,
    /// The victim's single latched attack-view notarization broadcast.
    VictimNotarizationRebroadcast,
    /// A notarize vote the byzantine node declines to cast.
    ByzantineNotarizeWithhold,
    /// A notarization certificate the byzantine node declines to announce.
    ByzantineNotarizationWithhold,
    /// A notarize vote the byzantine node declines to process.
    ByzantineIgnoreNotarize,
    /// A marshal backfill request the byzantine node declines to serve.
    ByzantineServeWithhold,
}

impl WedgeDrop {
    const fn as_str(self) -> &'static str {
        match self {
            Self::HolderNotarizeSplit => "holder-notarize-split",
            Self::VictimNotarizationRebroadcast => "victim-notarization-rebroadcast",
            Self::ByzantineNotarizeWithhold => "byzantine-notarize-withhold",
            Self::ByzantineNotarizationWithhold => "byzantine-notarization-withhold",
            Self::ByzantineIgnoreNotarize => "byzantine-ignore-notarize",
            Self::ByzantineServeWithhold => "byzantine-serve-withhold",
        }
    }

    /// Whether the withheld message belongs to a correct node.
    const fn is_honest(self) -> bool {
        matches!(
            self,
            Self::HolderNotarizeSplit | Self::VictimNotarizationRebroadcast
        )
    }
}

/// One observation recorded at a node's receive boundary.
#[derive(Clone, Debug)]
pub struct WedgeEvent {
    /// Global arrival order.
    pub seq: u64,
    /// Time since the scenario started.
    pub at: Duration,
    /// Phase the observation was made in.
    pub phase: WedgePhase,
    /// Node that observed it.
    pub node: String,
    /// Channel it was observed on.
    pub channel: WedgeChannel,
    /// Peer the message came from.
    pub peer: String,
    /// What the message was.
    pub detail: String,
}

impl fmt::Display for WedgeEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "#{:04} t={:>8.3}s [{}] {} <- {} {:<16} {}",
            self.seq,
            self.at.as_secs_f64(),
            self.phase.as_str(),
            self.node,
            self.peer,
            self.channel.as_str(),
            self.detail
        )
    }
}

/// A resolver request the victim sent, recorded by the peer asked to serve it.
#[derive(Clone, Debug)]
pub struct WedgeRequest {
    /// Peer the request was sent to.
    pub responder: String,
    /// Request id, which is what the requester matches responses on.
    pub id: u64,
    /// View requested.
    pub view: View,
    /// Time the request arrived at the responder.
    pub at: Duration,
}

/// Shared control and ledger for the split-notarization scenario.
///
/// Holds the phase flag, the per-category withholding counters, the observation
/// log, and the two recovery controls.
pub struct Wedge<P: PublicKey, D: Digest> {
    state: Arc<WedgeState<P, D>>,
}

impl<P: PublicKey, D: Digest> Clone for Wedge<P, D> {
    fn clone(&self) -> Self {
        Self {
            state: self.state.clone(),
        }
    }
}

struct WedgeState<P: PublicKey, D: Digest> {
    clock: deterministic::Context,
    origin: SystemTime,
    byzantine: P,
    victim: P,
    labels: BTreeMap<P, String>,
    attack_round: Round,
    phase: Mutex<WedgePhase>,
    serve_notarized: AtomicBool,
    inject_nullification: AtomicBool,
    injected: AtomicBool,
    seq: AtomicU64,
    drops: Mutex<BTreeMap<(WedgeDrop, WedgePhase), usize>>,
    channel_drops: Mutex<BTreeMap<WedgeChannel, usize>>,
    events: Mutex<Vec<WedgeEvent>>,
    attack_payload: Mutex<Option<D>>,
    recorded_nullification: Mutex<Option<(P, commonware_runtime::IoBuf)>>,
    victim_requests: Mutex<Vec<WedgeRequest>>,
}

impl<P: PublicKey, D: Digest> Wedge<P, D> {
    /// Builds the shared state. `labels` names each participant in the log.
    pub fn new(
        clock: deterministic::Context,
        byzantine: P,
        victim: P,
        labels: impl IntoIterator<Item = (P, String)>,
        attack_round: Round,
    ) -> Self {
        let origin = clock.current();
        Self {
            state: Arc::new(WedgeState {
                clock,
                origin,
                byzantine,
                victim,
                labels: labels.into_iter().collect(),
                attack_round,
                phase: Mutex::new(WedgePhase::Isolated),
                serve_notarized: AtomicBool::new(false),
                inject_nullification: AtomicBool::new(false),
                injected: AtomicBool::new(false),
                seq: AtomicU64::new(0),
                drops: Mutex::new(BTreeMap::new()),
                channel_drops: Mutex::new(BTreeMap::new()),
                events: Mutex::new(Vec::new()),
                attack_payload: Mutex::new(None),
                recorded_nullification: Mutex::new(None),
                victim_requests: Mutex::new(Vec::new()),
            }),
        }
    }

    /// Current phase.
    pub fn phase(&self) -> WedgePhase {
        *self.state.phase.lock()
    }

    /// Advances the phase flag every rule reads.
    pub fn set_phase(&self, phase: WedgePhase) {
        *self.state.phase.lock() = phase;
    }

    /// Control 1: the byzantine node serves its attack-round block after GST.
    pub fn enable_serve_after_gst(&self) {
        self.state.serve_notarized.store(true, Ordering::Relaxed);
    }

    /// Control 2: the recorded attack-view nullification is delivered to the
    /// victim once after GST.
    pub fn enable_nullification_injection(&self) {
        self.state
            .inject_nullification
            .store(true, Ordering::Relaxed);
    }

    /// Attack-view proposal payload, learned from the notarization the victim
    /// is served.
    pub fn attack_payload(&self) -> Option<D> {
        *self.state.attack_payload.lock()
    }

    /// Withheld messages of one category in one phase.
    pub fn drops(&self, drop: WedgeDrop, phase: WedgePhase) -> usize {
        self.state
            .drops
            .lock()
            .get(&(drop, phase))
            .copied()
            .unwrap_or(0)
    }

    /// Withheld messages belonging to correct nodes, in one phase.
    pub fn honest_drops(&self, phase: WedgePhase) -> usize {
        self.state
            .drops
            .lock()
            .iter()
            .filter(|((drop, at), _)| drop.is_honest() && *at == phase)
            .map(|(_, count)| *count)
            .sum()
    }

    /// Withheld messages belonging to the byzantine node, across all phases.
    pub fn byzantine_withholds(&self) -> usize {
        self.state
            .drops
            .lock()
            .iter()
            .filter(|((drop, _), _)| !drop.is_honest())
            .map(|(_, count)| *count)
            .sum()
    }

    /// Messages withheld on one channel, across all phases and categories.
    pub fn channel_drops(&self, channel: WedgeChannel) -> usize {
        self.state
            .channel_drops
            .lock()
            .get(&channel)
            .copied()
            .unwrap_or(0)
    }

    /// Per-category, per-phase withholding ledger.
    pub fn drop_ledger(&self) -> Vec<(WedgeDrop, WedgePhase, usize)> {
        self.state
            .drops
            .lock()
            .iter()
            .map(|((drop, phase), count)| (*drop, *phase, *count))
            .collect()
    }

    /// Every observation, in arrival order.
    pub fn events(&self) -> Vec<WedgeEvent> {
        self.state.events.lock().clone()
    }

    /// Attack-view resolver requests the victim sent, as seen by the peers it
    /// asked.
    pub fn victim_requests(&self) -> Vec<WedgeRequest> {
        self.state.victim_requests.lock().clone()
    }

    fn label(&self, key: &P) -> String {
        self.state
            .labels
            .get(key)
            .cloned()
            .unwrap_or_else(|| "?".into())
    }

    fn elapsed(&self) -> Duration {
        self.state
            .clock
            .current()
            .duration_since(self.state.origin)
            .unwrap_or_default()
    }

    fn record(&self, node: &P, channel: WedgeChannel, peer: &P, detail: String) {
        let event = WedgeEvent {
            seq: self.state.seq.fetch_add(1, Ordering::Relaxed),
            at: self.elapsed(),
            phase: self.phase(),
            node: self.label(node),
            channel,
            peer: self.label(peer),
            detail,
        };
        self.state.events.lock().push(event);
    }

    fn withhold(&self, node: &P, channel: WedgeChannel, peer: &P, drop: WedgeDrop, detail: String) {
        let phase = self.phase();
        *self.state.drops.lock().entry((drop, phase)).or_insert(0) += 1;
        *self.state.channel_drops.lock().entry(channel).or_insert(0) += 1;
        self.record(
            node,
            channel,
            peer,
            format!("DROP[{}] {detail}", drop.as_str()),
        );
    }
}

/// Identity a [`WedgeReceiver`] needs to apply the scenario's rules.
pub struct WedgeNode<S: Scheme<D>, D: Digest> {
    wedge: Wedge<S::PublicKey, D>,
    me: S::PublicKey,
    role: WedgeRole,
    scheme: S,
}

impl<S: Scheme<D>, D: Digest> WedgeNode<S, D> {
    pub const fn new(
        wedge: Wedge<S::PublicKey, D>,
        me: S::PublicKey,
        role: WedgeRole,
        scheme: S,
    ) -> Self {
        Self {
            wedge,
            me,
            role,
            scheme,
        }
    }
}

impl<S: Scheme<D>, D: Digest> Clone for WedgeNode<S, D> {
    fn clone(&self) -> Self {
        Self {
            wedge: self.wedge.clone(),
            me: self.me.clone(),
            role: self.role,
            scheme: self.scheme.clone(),
        }
    }
}

/// The receive-side rules of the split-notarization scenario.
///
/// One wrapper serves every node and every channel; the rules that fire are
/// selected by [`WedgeRole`], [`WedgeChannel`] and the shared [`WedgePhase`].
/// With `node` unset it forwards everything untouched.
///
/// Honest-message rules, armed before GST only:
/// - a holder does not receive the other holder's attack-view notarize vote, so
///   no correct node assembles the attack notarization;
/// - a holder does not receive the victim's one latched attack-view
///   notarization broadcast.
///
/// Byzantine withholding, armed for the whole run:
/// - nobody receives a notarize vote the byzantine node casts outside the
///   attack view;
/// - the byzantine node does not receive the victim's marshal request for the
///   attack round, so it never serves the block behind its notarization.
///
/// Nothing is ever withheld on the certificate-backfill channel: the answers
/// the victim's peers send it are delivered and the protocol decides what to do
/// with them.
pub struct WedgeReceiver<S, D, BL, R>
where
    D: Digest,
    S: Scheme<D>,
    R: Receiver<PublicKey = S::PublicKey>,
{
    inner: R,
    channel: WedgeChannel,
    node: Option<WedgeNode<S, D>>,
    _block: PhantomData<fn() -> BL>,
}

impl<S, D, BL, R> WedgeReceiver<S, D, BL, R>
where
    D: Digest,
    S: Scheme<D>,
    BL: Block<Digest = D> + Decode<Cfg = ()>,
    R: Receiver<PublicKey = S::PublicKey>,
{
    pub const fn new(inner: R, node: Option<WedgeNode<S, D>>, channel: WedgeChannel) -> Self {
        Self {
            inner,
            channel,
            node,
            _block: PhantomData,
        }
    }

    /// Control 2: hands the victim the recorded attack-view nullification once.
    fn injection(&self) -> Option<Message<S::PublicKey>> {
        let node = self.node.as_ref()?;
        if node.role != WedgeRole::Victim || self.channel != WedgeChannel::Certificate {
            return None;
        }
        let wedge = &node.wedge;
        if !wedge.state.inject_nullification.load(Ordering::Relaxed) || !wedge.phase().is_post_gst()
        {
            return None;
        }
        let (peer, message) = wedge.state.recorded_nullification.lock().clone()?;
        if wedge.state.injected.swap(true, Ordering::Relaxed) {
            return None;
        }
        wedge.record(
            &node.me,
            WedgeChannel::Certificate,
            &peer,
            format!(
                "INJECT nullification view={} (control)",
                wedge.state.attack_round.view()
            ),
        );
        Some((peer, message))
    }

    fn certificate(&self, message: &commonware_runtime::IoBuf) -> Option<Certificate<S, D>> {
        let node = self.node.as_ref()?;
        Certificate::<S, D>::decode_cfg(message.clone(), &node.scheme.certificate_codec_config())
            .ok()
    }

    /// Applies the scenario's rules to one message, returning true if it is
    /// withheld.
    fn apply(&self, peer: &S::PublicKey, message: &commonware_runtime::IoBuf) -> bool {
        let Some(node) = self.node.as_ref() else {
            return false;
        };
        let wedge = &node.wedge;
        let attack_view = wedge.state.attack_round.view();
        let pre_gst = !wedge.phase().is_post_gst();
        match self.channel {
            WedgeChannel::Vote => {
                let Ok(vote) = Vote::<S, D>::decode(message.clone()) else {
                    return false;
                };
                let view = vote.view();
                let notarize = matches!(vote, Vote::Notarize(_));
                if notarize && node.role == WedgeRole::Byzantine && view != attack_view {
                    wedge.withhold(
                        &node.me,
                        self.channel,
                        peer,
                        WedgeDrop::ByzantineIgnoreNotarize,
                        format!("notarize view={view}"),
                    );
                    return true;
                }
                if notarize && *peer == wedge.state.byzantine && view != attack_view {
                    wedge.withhold(
                        &node.me,
                        self.channel,
                        peer,
                        WedgeDrop::ByzantineNotarizeWithhold,
                        format!("notarize view={view}"),
                    );
                    return true;
                }
                if notarize
                    && view == attack_view
                    && pre_gst
                    && node.role == WedgeRole::Holder
                    && *peer != wedge.state.byzantine
                {
                    wedge.withhold(
                        &node.me,
                        self.channel,
                        peer,
                        WedgeDrop::HolderNotarizeSplit,
                        format!("notarize view={view}"),
                    );
                    return true;
                }
                if node.role == WedgeRole::Victim && view == attack_view {
                    let kind = match vote {
                        Vote::Notarize(_) => "notarize",
                        Vote::Nullify(_) => "nullify",
                        Vote::Finalize(_) => "finalize",
                    };
                    wedge.record(
                        &node.me,
                        self.channel,
                        peer,
                        format!("{kind} vote view={view}"),
                    );
                }
                false
            }
            WedgeChannel::Certificate => {
                let Some(certificate) = self.certificate(message) else {
                    return false;
                };
                if *peer == wedge.state.byzantine
                    && let Certificate::Notarization(notarization) = &certificate
                {
                    wedge.withhold(
                        &node.me,
                        self.channel,
                        peer,
                        WedgeDrop::ByzantineNotarizationWithhold,
                        format!("notarization view={}", notarization.view()),
                    );
                    return true;
                }
                match &certificate {
                    Certificate::Notarization(notarization)
                        if notarization.view() == attack_view =>
                    {
                        if node.role == WedgeRole::Holder && *peer == wedge.state.victim && pre_gst
                        {
                            wedge.withhold(
                                &node.me,
                                self.channel,
                                peer,
                                WedgeDrop::VictimNotarizationRebroadcast,
                                format!("notarization view={attack_view}"),
                            );
                            return true;
                        }
                        wedge.record(
                            &node.me,
                            self.channel,
                            peer,
                            format!("notarization view={attack_view}"),
                        );
                    }
                    Certificate::Nullification(nullification)
                        if nullification.view() == attack_view =>
                    {
                        if node.role != WedgeRole::Victim {
                            let mut recorded = wedge.state.recorded_nullification.lock();
                            if recorded.is_none() {
                                *recorded = Some((peer.clone(), message.clone()));
                            }
                        } else {
                            wedge.record(
                                &node.me,
                                self.channel,
                                peer,
                                format!("nullification view={attack_view}"),
                            );
                        }
                    }
                    _ => {}
                }
                false
            }
            WedgeChannel::Resolver => {
                let Ok(resolver) = ResolverMessage::<U64>::decode(message.clone()) else {
                    return false;
                };
                match resolver.payload {
                    ResolverPayload::Request(key) => {
                        let view = View::new(u64::from(&key));
                        if *peer == wedge.state.victim && view == attack_view {
                            let request = WedgeRequest {
                                responder: wedge.label(&node.me),
                                id: resolver.id,
                                view,
                                at: wedge.elapsed(),
                            };
                            wedge.state.victim_requests.lock().push(request);
                            wedge.record(
                                &node.me,
                                self.channel,
                                peer,
                                format!("REQUEST view={view} id={}", resolver.id),
                            );
                        }
                    }
                    ResolverPayload::Response(response) => {
                        let Ok(certificate) = Certificate::<S, D>::decode_cfg(
                            response,
                            &node.scheme.certificate_codec_config(),
                        ) else {
                            return false;
                        };
                        if node.role != WedgeRole::Victim {
                            return false;
                        }
                        let detail = match &certificate {
                            Certificate::Notarization(notarization) => {
                                if notarization.view() == attack_view {
                                    *wedge.state.attack_payload.lock() =
                                        Some(notarization.proposal.payload);
                                }
                                format!("ANSWER notarization view={}", notarization.view())
                            }
                            Certificate::Nullification(nullification) => {
                                format!("ANSWER nullification view={}", nullification.view())
                            }
                            Certificate::Finalization(finalization) => {
                                format!("ANSWER finalization view={}", finalization.view())
                            }
                        };
                        if certificate.view() <= attack_view {
                            wedge.record(
                                &node.me,
                                self.channel,
                                peer,
                                format!("{detail} id={}", resolver.id),
                            );
                        }
                    }
                    ResolverPayload::Error => {}
                }
                false
            }
            WedgeChannel::MarshalBackfill => {
                let Ok(resolver) = ResolverMessage::<MarshalKey<D>>::decode(message.clone()) else {
                    return false;
                };
                match resolver.payload {
                    ResolverPayload::Request(MarshalKey::Notarized { round }) => {
                        let control = wedge.state.serve_notarized.load(Ordering::Relaxed)
                            && wedge.phase().is_post_gst();
                        if node.role == WedgeRole::Byzantine
                            && round == wedge.state.attack_round
                            && !control
                        {
                            wedge.withhold(
                                &node.me,
                                self.channel,
                                peer,
                                WedgeDrop::ByzantineServeWithhold,
                                format!("request notarized round={round}"),
                            );
                            return true;
                        }
                        wedge.record(
                            &node.me,
                            self.channel,
                            peer,
                            format!("request notarized round={round}"),
                        );
                    }
                    ResolverPayload::Request(MarshalKey::Block(commitment))
                        if *peer == wedge.state.victim =>
                    {
                        wedge.record(
                            &node.me,
                            self.channel,
                            peer,
                            format!("request block commitment={commitment}"),
                        );
                    }
                    ResolverPayload::Response(response) if node.role == WedgeRole::Victim => {
                        wedge.record(
                            &node.me,
                            self.channel,
                            peer,
                            format!("ANSWER bytes={} id={}", response.len(), resolver.id),
                        );
                    }
                    _ => {}
                }
                false
            }
            WedgeChannel::MarshalBroadcast => {
                if node.role != WedgeRole::Victim {
                    return false;
                }
                let Ok(block) = BL::decode(message.clone()) else {
                    return false;
                };
                let digest = block.digest();
                let attack = wedge.attack_payload();
                let marker = if attack == Some(digest) {
                    "ATTACK BLOCK"
                } else {
                    "block"
                };
                wedge.record(
                    &node.me,
                    self.channel,
                    peer,
                    format!("{marker} height={} digest={digest}", block.height()),
                );
                false
            }
        }
    }
}

impl<S, D, BL, R> fmt::Debug for WedgeReceiver<S, D, BL, R>
where
    D: Digest,
    S: Scheme<D>,
    R: Receiver<PublicKey = S::PublicKey>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WedgeReceiver")
            .field("channel", &self.channel)
            .field("armed", &self.node.is_some())
            .finish()
    }
}

impl<S, D, BL, R> Receiver for WedgeReceiver<S, D, BL, R>
where
    D: Digest,
    S: Scheme<D>,
    BL: Block<Digest = D> + Decode<Cfg = ()>,
    R: Receiver<PublicKey = S::PublicKey>,
{
    type Error = R::Error;
    type PublicKey = S::PublicKey;

    async fn recv(&mut self) -> Result<Message<Self::PublicKey>, Self::Error> {
        loop {
            if let Some(message) = self.injection() {
                return Ok(message);
            }
            let (peer, message) = self.inner.recv().await?;
            if self.apply(&peer, &message) {
                continue;
            }
            return Ok((peer, message));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EPOCH, id_mock};
    use commonware_codec::Encode;
    use commonware_consensus::{
        simplex::types::{Finalization, Finalize, Nullification, Nullify},
        types::{Epoch, Round, View},
    };
    use commonware_cryptography::{certificate::Verifier as _, sha256::Digest as Sha256Digest};
    use commonware_parallel::Sequential;
    use commonware_runtime::IoBuf;
    use std::{collections::VecDeque, io};

    #[derive(Debug)]
    struct QueueReceiver<P: PublicKey> {
        messages: VecDeque<Message<P>>,
    }

    impl<P: PublicKey> Receiver for QueueReceiver<P> {
        type Error = io::Error;
        type PublicKey = P;

        async fn recv(&mut self) -> Result<Message<Self::PublicKey>, Self::Error> {
            self.messages
                .pop_front()
                .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "queue exhausted"))
        }
    }

    #[test]
    fn notarize_omission_forwards_other_vote_traffic() {
        let mut rng = commonware_utils::test_rng();
        let (participants, schemes) = id_mock::fixture(&mut rng, b"notarize_omission", 4);
        let round = Round::new(Epoch::new(EPOCH), View::new(1));
        let proposal = Proposal::new(round, View::zero(), Sha256Digest([7; 32]));
        let first = 0;
        let second = 1;

        let first_notarize = Vote::<id_mock::Scheme, Sha256Digest>::Notarize(
            Notarize::sign(&schemes[first], proposal.clone()).unwrap(),
        )
        .encode();
        let second_notarize = Vote::<id_mock::Scheme, Sha256Digest>::Notarize(
            Notarize::sign(&schemes[second], proposal.clone()).unwrap(),
        )
        .encode();
        let finalize = Vote::<id_mock::Scheme, Sha256Digest>::Finalize(
            Finalize::sign(&schemes[first], proposal).unwrap(),
        )
        .encode();
        let malformed = IoBuf::from(vec![0xff]);
        let receiver = QueueReceiver {
            messages: VecDeque::from([
                (participants[first].clone(), first_notarize.into()),
                (participants[second].clone(), second_notarize.into()),
                (participants[first].clone(), finalize.clone().into()),
                (participants[first].clone(), malformed.clone()),
            ]),
        };
        let omitted = Arc::new(AtomicUsize::new(0));
        let mut receiver = NotarizeOmissionReceiver::<id_mock::Scheme, Sha256Digest, _>::new(
            receiver,
            omitted.clone(),
        );

        let (_, received) = futures::executor::block_on(receiver.recv()).unwrap();
        assert_eq!(received.as_ref(), finalize.as_ref());
        let (_, received) = futures::executor::block_on(receiver.recv()).unwrap();
        assert_eq!(received, malformed);
        assert_eq!(omitted.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn finalization_omission_covers_certificate_and_resolver_channels() {
        let mut rng = commonware_utils::test_rng();
        let (participants, schemes) = id_mock::fixture(&mut rng, b"finalization_omission", 4);
        let proposal = Proposal::new(
            Round::new(Epoch::new(EPOCH), View::new(3)),
            View::new(2),
            Sha256Digest([9; 32]),
        );
        let finalizes: Vec<_> = schemes[..3]
            .iter()
            .map(|scheme| Finalize::sign(scheme, proposal.clone()).unwrap())
            .collect();
        let finalization = Certificate::Finalization(
            Finalization::from_finalizes(&schemes[0], &finalizes, &Sequential).unwrap(),
        )
        .encode();
        let notarizes: Vec<_> = schemes[..3]
            .iter()
            .map(|scheme| Notarize::sign(scheme, proposal.clone()).unwrap())
            .collect();
        let notarization = Certificate::Notarization(
            Notarization::from_notarizes(&schemes[0], &notarizes, &Sequential).unwrap(),
        )
        .encode();
        let omitted = Arc::new(AtomicUsize::new(0));

        let receiver = QueueReceiver {
            messages: VecDeque::from([
                (participants[1].clone(), finalization.clone().into()),
                (participants[1].clone(), notarization.clone().into()),
            ]),
        };
        let mut receiver = FinalizationOmissionReceiver::<id_mock::Scheme, Sha256Digest, _>::new(
            receiver,
            schemes[0].clone(),
            FinalizationOmissionChannel::Certificate,
            omitted.clone(),
        );
        let (_, received) = futures::executor::block_on(receiver.recv()).unwrap();
        assert_eq!(received.as_ref(), notarization.as_ref());

        let finalization_response = ResolverMessage::<U64> {
            id: 1,
            payload: ResolverPayload::Response(finalization),
        }
        .encode();
        let notarization_response = ResolverMessage::<U64> {
            id: 2,
            payload: ResolverPayload::Response(notarization),
        }
        .encode();
        let request = ResolverMessage::<U64> {
            id: 3,
            payload: ResolverPayload::Request(U64::from(3u64)),
        }
        .encode();
        let receiver = QueueReceiver {
            messages: VecDeque::from([
                (
                    participants[1].clone(),
                    finalization_response.clone().into(),
                ),
                (
                    participants[1].clone(),
                    notarization_response.clone().into(),
                ),
                (participants[1].clone(), request.clone().into()),
            ]),
        };
        let mut receiver = FinalizationOmissionReceiver::<id_mock::Scheme, Sha256Digest, _>::new(
            receiver,
            schemes[0].clone(),
            FinalizationOmissionChannel::Resolver,
            omitted.clone(),
        );
        let (_, received) = futures::executor::block_on(receiver.recv()).unwrap();
        assert_eq!(received.as_ref(), notarization_response.as_ref());
        let (_, received) = futures::executor::block_on(receiver.recv()).unwrap();
        assert_eq!(received.as_ref(), request.as_ref());
        assert_eq!(omitted.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn certificate_poison_counts_only_matched_retries() {
        let mut rng = commonware_utils::test_rng();
        let (participants, schemes) = id_mock::fixture(&mut rng, b"certificate_poison", 4);
        let view = View::new(3);
        let nullifies: Vec<_> = schemes[..3]
            .iter()
            .map(|scheme| {
                Nullify::sign::<Sha256Digest>(scheme, Round::new(Epoch::new(EPOCH), view)).unwrap()
            })
            .collect();
        let nullification = Certificate::<id_mock::Scheme, Sha256Digest>::Nullification(
            Nullification::from_nullifies(&schemes[0], &nullifies, &Sequential).unwrap(),
        )
        .encode();
        let response = |id: u64| {
            ResolverMessage::<U64> {
                id,
                payload: ResolverPayload::Response(nullification.clone()),
            }
            .encode()
        };
        let request = |id: u64, view: u64| {
            ResolverMessage::<U64> {
                id,
                payload: ResolverPayload::Request(U64::from(view)),
            }
            .encode()
        };
        let poison = CertificatePoison::new();

        // The peer that serves the retry records the requests it was asked
        // for. Request ids are per-requester counters, so node 2 asking for
        // the same view under an id node 0 never used must not answer for it.
        let observer = QueueReceiver {
            messages: VecDeque::from([
                (participants[0].clone(), request(7, 3).into()),
                (participants[2].clone(), request(8, 3).into()),
                (participants[0].clone(), request(9, 3).into()),
                (participants[0].clone(), request(10, 4).into()),
            ]),
        };
        let mut observer = CertificatePoisonReceiver::<id_mock::Scheme, Sha256Digest, _>::observer(
            observer,
            participants[1].clone(),
            participants[0].clone(),
            Some(poison.clone()),
        );
        for _ in 0..4 {
            futures::executor::block_on(observer.recv()).unwrap();
        }

        let receiver = QueueReceiver {
            messages: VecDeque::from([
                (participants[1].clone(), response(7).into()),
                (participants[1].clone(), response(99).into()),
                (participants[1].clone(), response(8).into()),
                (participants[1].clone(), response(10).into()),
                (participants[1].clone(), response(9).into()),
            ]),
        };
        let mut receiver = CertificatePoisonReceiver::<id_mock::Scheme, Sha256Digest, _>::new(
            receiver,
            schemes.clone(),
            Epoch::new(EPOCH),
            Sha256Digest([0xEE; 32]),
            Some(poison.clone()),
        );

        // The nullification answering this node's own request is replaced by a
        // notarization for a proposal no node proposed.
        let (_, received) = futures::executor::block_on(receiver.recv()).unwrap();
        let decoded = ResolverMessage::<U64>::decode(received).unwrap();
        assert_eq!(decoded.id, 7);
        let ResolverPayload::Response(payload) = decoded.payload else {
            panic!("poisoned message must stay a response");
        };
        let certificate = Certificate::<id_mock::Scheme, Sha256Digest>::decode_cfg(
            payload,
            &schemes[0].certificate_codec_config(),
        )
        .unwrap();
        let Certificate::Notarization(notarization) = certificate else {
            panic!("nullification response must be replaced by a notarization");
        };
        assert_eq!(notarization.view(), view);
        assert_eq!(notarization.proposal.payload, Sha256Digest([0xEE; 32]));
        assert_eq!(poison.view(), Some(view));

        // Unsolicited traffic, another node's request, and answers to other
        // views cannot retire the poisoned fetch; only an answer to a fresh
        // request this node sent for it does.
        for _ in 0..3 {
            futures::executor::block_on(receiver.recv()).unwrap();
        }
        assert_eq!(poison.retries_answered(), 0);
        futures::executor::block_on(receiver.recv()).unwrap();
        assert_eq!(poison.retries_answered(), 1);
    }
}
