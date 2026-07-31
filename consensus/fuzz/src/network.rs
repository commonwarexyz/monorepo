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

use commonware_codec::{Decode, DecodeExt};
use commonware_consensus::simplex::{
    scheme::Scheme,
    types::{Certificate, Vote},
};
use commonware_cryptography::{Digest, PublicKey};
use commonware_macros::select;
use commonware_p2p::{Message, Receiver, simulated::SplitTarget};
use commonware_resolver::p2p::mocks::{Message as ResolverMessage, Payload as ResolverPayload};
use commonware_utils::{sequence::U64, sync::Mutex};
use rand::RngExt as _;
use rand_core::CryptoRng;
use std::{
    collections::HashSet,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EPOCH, id_mock};
    use commonware_codec::Encode;
    use commonware_consensus::{
        simplex::types::{Finalization, Finalize, Notarization, Notarize, Proposal},
        types::{Epoch, Round, View},
    };
    use commonware_cryptography::sha256::Digest as Sha256Digest;
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
}
