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
//! vote except notarize votes.
//!
//! Note: this is not a global total-order guarantee (the underlying network can still deliver
//! honest messages before Byzantine messages arrive). It does guarantee that, whenever both a
//! Byzantine message and an honest message are simultaneously available to be received, the
//! Byzantine message is delivered first.

use commonware_codec::{Decode, DecodeExt, Encode};
use commonware_consensus::{
    Viewable,
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
use commonware_utils::{sequence::U64, sync::Mutex};
use rand::RngExt as _;
use rand_core::CryptoRng;
use std::{
    collections::{BTreeMap, HashSet},
    marker::PhantomData,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
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
