//! Cross-task plumbing between forwarders and the injector.
//!
//! The forwarders run synchronously inside the simulated p2p split-sender
//! plumbing; the injector runs on its own async task. This module defines
//! the small, pure data types that cross that boundary:
//!
//! - [`Intercept`] -- one captured byzantine outgoing message paired with one
//!   matching `procFault` (the unit of work the injector handles);
//! - [`InterceptChannel`] -- which p2p channel the message came from;
//! - [`SenderViewCell`] -- per-sender atomic implementing the paper's
//!   `rnd(m)` ("max round in which the sender has sent or received a
//!   message"). Outgoing forwarders fold each transmitted view in; the
//!   [`RoundTrackingReceiver`] wrapper folds in each *received* view, so
//!   the cell reflects the sender's true current round and old-view
//!   retransmissions are not tagged with old-round faults;
//! - [`RoundTrackingReceiver`] -- decode-and-update wrapper installed on
//!   each validator's incoming vote / cert / resolver receivers. Resolver
//!   inbound also carries round-relevant data: [`commonware_resolver`]'s
//!   wire `Payload::Request` is keyed by `U64` view (Simplex sets
//!   `Resolver::Key = U64`), and `Payload::Response` is the serialized
//!   [`Certificate`] whose `view()` we can recover. The resolver wire
//!   module is private, so we hand-decode the small fixed prefix and reuse
//!   the [`Certificate`] codec for the response payload.

use commonware_codec::{Decode, DecodeExt, RangeCfg, Read};
use commonware_consensus::{
    simplex::{
        scheme::Scheme,
        types::{Certificate, Vote},
    },
    Viewable,
};
use commonware_cryptography::{sha256::Digest as Sha256Digest, PublicKey};
use commonware_p2p::{Message, Receiver};
use commonware_utils::channel::mpsc::{self, UnboundedReceiver, UnboundedSender};
use std::{
    fmt::{self, Debug},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

/// Channel an intercepted message came from. Determines which mutator the
/// injector applies (vote -> decode + re-sign; cert / resolver -> byte-level
/// strategy mutation) and which sender clone it sends the result through.
#[derive(Clone, Copy, Debug)]
pub enum InterceptChannel {
    Vote,
    Cert,
    Resolver,
}

/// One intercepted byzantine message paired with one matching procFault.
/// Pushed by a forwarder, consumed by [`super::injector::ByzzFuzzInjector`].
///
/// `targets` is already partition-filtered (the forwarder applies network
/// faults before enqueuing), so the injector can deliver directly without
/// re-checking.
#[derive(Clone, Debug)]
pub struct Intercept<P: PublicKey> {
    pub channel: InterceptChannel,
    pub view: u64,
    pub bytes: Vec<u8>,
    pub fault_seed: u64,
    pub omit: bool,
    pub targets: Vec<P>,
}

/// Cell holding the byzantine sender's most-recently-seen consensus view.
/// Updated monotonically by vote/cert forwarders on every successful decode;
/// read by the resolver forwarder to derive a round attribution for
/// view-less recovery traffic.
///
/// Cheap to clone (Arc).
#[derive(Clone, Default)]
pub struct SenderViewCell(Arc<AtomicU64>);

impl SenderViewCell {
    pub fn new() -> Self {
        Self(Arc::new(AtomicU64::new(0)))
    }

    /// Monotonically advance the cell to `view` (no-op if `view <= current`).
    pub fn update(&self, view: u64) {
        let mut current = self.0.load(Ordering::Relaxed);
        while view > current {
            match self
                .0
                .compare_exchange_weak(current, view, Ordering::Relaxed, Ordering::Relaxed)
            {
                Ok(_) => return,
                Err(c) => current = c,
            }
        }
    }

    pub fn get(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

/// Construct an unbounded intercept channel. Sender side is sync (matches
/// the [`commonware_p2p::simulated::SplitForwarder`] closure contract);
/// receiver side is async.
pub fn channel<P: PublicKey>() -> (
    UnboundedSender<Intercept<P>>,
    UnboundedReceiver<Intercept<P>>,
) {
    mpsc::unbounded_channel()
}

/// Receiver wrapper that, for every incoming message, decodes the protocol
/// view and folds it into a shared [`SenderViewCell`]. Used on each
/// validator's vote and certificate inbound channels so the cell tracks the
/// "received" half of the paper's `rnd(m) = max round sent or received`.
///
/// `extract` returns `Some(view)` when the bytes decode to the channel's
/// expected type and `None` otherwise (undecodable bytes leave the cell
/// alone). The wrapper is decode-only -- the message is forwarded to the
/// engine unchanged.
pub struct RoundTrackingReceiver<P, R, F>
where
    P: PublicKey,
    R: Receiver<PublicKey = P>,
    F: Fn(&[u8]) -> Option<u64> + Send + 'static,
{
    inner: R,
    cell: SenderViewCell,
    extract: F,
}

impl<P, R, F> RoundTrackingReceiver<P, R, F>
where
    P: PublicKey,
    R: Receiver<PublicKey = P>,
    F: Fn(&[u8]) -> Option<u64> + Send + 'static,
{
    pub fn new(inner: R, cell: SenderViewCell, extract: F) -> Self {
        Self {
            inner,
            cell,
            extract,
        }
    }
}

impl<P, R, F> Debug for RoundTrackingReceiver<P, R, F>
where
    P: PublicKey,
    R: Receiver<PublicKey = P> + Debug,
    F: Fn(&[u8]) -> Option<u64> + Send + 'static,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RoundTrackingReceiver")
            .field("cell", &self.cell.get())
            .finish_non_exhaustive()
    }
}

impl<P, R, F> Receiver for RoundTrackingReceiver<P, R, F>
where
    P: PublicKey,
    R: Receiver<PublicKey = P>,
    R::Error: Send + Sync,
    F: Fn(&[u8]) -> Option<u64> + Send + Sync + 'static,
{
    type Error = R::Error;
    type PublicKey = P;

    async fn recv(&mut self) -> Result<Message<Self::PublicKey>, Self::Error> {
        let msg = self.inner.recv().await?;
        if let Some(view) = (self.extract)(msg.1.as_ref()) {
            self.cell.update(view);
        }
        Ok(msg)
    }
}

/// Build a `Vote`-decoding extractor. Also populates the observed-value pool.
pub fn vote_view_extractor<S: Scheme<Sha256Digest>>(
    pool: std::sync::Arc<crate::byzzfuzz::observed::ObservedState>,
) -> impl Fn(&[u8]) -> Option<u64> + Send + Sync + 'static {
    move |bytes: &[u8]| {
        let v = Vote::<S, Sha256Digest>::decode(bytes).ok()?;
        pool.observe_vote::<S, S::PublicKey>(&v);
        Some(v.view().get())
    }
}

/// Build a `Certificate`-decoding extractor. Also populates the
/// observed-value pool with the raw cert bytes for later replay.
pub fn certificate_view_extractor<S: Scheme<Sha256Digest>>(
    cert_codec: <S::Certificate as Read>::Cfg,
    pool: std::sync::Arc<crate::byzzfuzz::observed::ObservedState>,
) -> impl Fn(&[u8]) -> Option<u64> + Send + Sync + 'static
where
    <S::Certificate as Read>::Cfg: Clone + Send + Sync + 'static,
{
    move |bytes: &[u8]| {
        let c = Certificate::<S, Sha256Digest>::decode_cfg(&mut &bytes[..], &cert_codec).ok()?;
        pool.observe_certificate::<S, S::PublicKey>(&c, bytes);
        Some(c.view().get())
    }
}

/// Build a resolver-wire extractor for [`RoundTrackingReceiver`].
///
/// Decodes [`commonware_resolver::p2p`]'s on-wire `Message<U64>` shape and
/// returns the carried view -- `Request`'s `U64` view, or the
/// `Response`'s embedded [`Certificate`]'s view. This closes the resolver
/// inbound rnd(m) attribution loop: a node receiving a fetch request for
/// view `v` (without ever having voted on `v` itself) raises its
/// [`SenderViewCell`] to `v`, so any subsequent outbound forwarding is
/// attributed to `max(v, prior)` rather than the stale prior round.
///
/// The wire format (`commonware_resolver::p2p::wire::Message`) is private
/// to that crate; we hand-decode the small fixed prefix here and only
/// invoke the canonical [`Certificate`] codec on the response payload, so
/// no cross-crate visibility change is required.
///
/// Wire layout decoded:
///   bytes 0..8   -- `id: u64` (BE) -- ignored;
///   byte  8      -- payload tag (0 = Request, 1 = Response, 2 = Error);
///   tag 0:  bytes 9..17 -- `Key = U64` (BE) view;
///   tag 1:  varint length + Bytes -- length-prefixed serialized
///                                    [`Certificate`];
///   tag 2:  no payload.
pub fn resolver_view_extractor<S: Scheme<Sha256Digest>>(
    cert_codec: <S::Certificate as Read>::Cfg,
    pool: std::sync::Arc<crate::byzzfuzz::observed::ObservedState>,
) -> impl Fn(&[u8]) -> Option<u64> + Send + Sync + 'static
where
    <S::Certificate as Read>::Cfg: Clone + Send + Sync + 'static,
{
    move |bytes: &[u8]| {
        // The real p2p decode wrapper goes through `V::decode_cfg`, which
        // rejects messages with trailing bytes. We mirror that strictness
        // here so the cell never advances on a payload the resolver engine
        // would itself reject -- otherwise a mutated `Request(view) || junk`
        // could move `rnd(m)` ahead of what the protocol observes.
        //
        // 8-byte id + 1-byte tag minimum.
        if bytes.len() < 9 {
            return None;
        }
        let tag = bytes[8];
        let payload = &bytes[9..];
        match tag {
            0 => {
                // Request(U64) -- exactly 8 BE bytes, no trailing data.
                if payload.len() != 8 {
                    return None;
                }
                let mut be = [0u8; 8];
                be.copy_from_slice(payload);
                let view = u64::from_be_bytes(be);
                pool.observe_resolver_request(view);
                Some(view)
            }
            1 => {
                // Response(Bytes) -- varint usize length, then exactly that
                // many bytes (no trailing data after the inner Bytes).
                // `Certificate::decode_cfg` then enforces exact consumption
                // of the certificate within those bytes.
                let mut buf = payload;
                let range: RangeCfg<usize> = (..).into();
                let len = usize::read_cfg(&mut buf, &range).ok()?;
                if buf.len() != len {
                    return None;
                }
                let cert_slice = &buf[..len];
                let c =
                    Certificate::<S, Sha256Digest>::decode_cfg(&mut &cert_slice[..], &cert_codec)
                        .ok()?;
                pool.observe_certificate::<S, S::PublicKey>(&c, cert_slice);
                Some(c.view().get())
            }
            // Error: no payload -- mirror Decode strictness on trailing bytes.
            2 if payload.is_empty() => None,
            // Anything else (including Error with junk, or unknown tag) is
            // rejected by the canonical decoder; do not advance rnd(m).
            _ => None,
        }
    }
}
