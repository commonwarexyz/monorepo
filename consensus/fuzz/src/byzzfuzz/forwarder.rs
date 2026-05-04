//! Per-channel `SplitForwarder` factories implementing the *interception* half
//! of Algorithm 1 (paper) at the network layer.
//!
//! Each factory produces a closure installed via `Sender::split_with` on a
//! validator's outgoing channel. The closure recovers `rnd(m)` from the
//! shared per-sender [`SenderViewCell`] -- the paper's "max round in which
//! the sender has sent or received a message". All three outgoing
//! forwarders (vote, cert, resolver) fold the message's carried view into
//! the cell *before* reading it: vote/cert from `m.view()`, resolver from
//! the wire `Request(U64)` key or the embedded `Certificate` of a
//! `Response`. A retransmission of an old view at a later sender round
//! therefore inherits the sender's current round (matching the paper's
//! "we apply the same faults to retransmissions sent in the same protocol
//! round, but allow their nonfaulty delivery if they are repeated in a
//! later round"). Received vote/cert/resolver traffic feeds the cell via
//! [`super::intercept::RoundTrackingReceiver`].
//!
//! Per recipient the closure then decides:
//!
//! 1. **drop** -- if the partition active at `rnd(m)` isolates the sender
//!    from that recipient (Algorithm 1 line 15);
//! 2. **enqueue** -- if the sender is byzantine and the recipient lies in a
//!    matching `procFault.receivers` set: push an `Intercept` for the
//!    `ByzzFuzzInjector` and remove the recipient from the residual original
//!    send (Algorithm 1 line 16-18, *replace* half of which lives in the
//!    injector);
//! 3. **deliver** -- otherwise.
//!
//! Honest senders pass an empty procFault schedule and a `None` intercept
//! sender, degenerating the closure to partition-only filtering. Same closure
//! type for all four senders -> no opaque-type mismatch in `runner::run`.

use crate::{
    byzzfuzz::{
        fault::{NetworkFault, ProcessFault},
        intercept::{Intercept, InterceptChannel, SenderViewCell},
        log,
        observed::ObservedState,
        scope::{self, FaultScope},
    },
    utils::SetPartition,
};
use commonware_codec::{Decode, DecodeExt, RangeCfg, Read};
use commonware_consensus::{
    simplex::{
        scheme::Scheme,
        types::{Certificate, Vote},
    },
    Viewable,
};
use commonware_cryptography::{sha256::Digest as Sha256Digest, PublicKey};
use commonware_p2p::{
    simulated::{SplitForwarder, SplitOrigin},
    Recipients,
};
use commonware_runtime::IoBuf;
use commonware_utils::channel::mpsc::UnboundedSender;
use std::{fmt::Write as _, sync::Arc};

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

/// Expand a [`Recipients`] into an explicit list against the participant set.
fn expand<P: PublicKey>(recipients: &Recipients<P>, participants: &[P]) -> Vec<P> {
    match recipients {
        Recipients::All => participants.to_vec(),
        Recipients::Some(v) => v.clone(),
        Recipients::One(p) => vec![p.clone()],
    }
}

/// Drop receivers not in `sender_idx`'s partition block at `view`, considering
/// only partitions whose scope matches the current channel/kind. Returns
/// `None` (= drop entirely) when nothing is left.
fn filter_by_partition<P: PublicKey>(
    recipients: Vec<P>,
    participants: &[P],
    sender_idx: usize,
    schedule: &[NetworkFault],
    view: u64,
    scope_matches: impl Fn(FaultScope) -> bool,
) -> Option<Vec<P>> {
    // With-replacement sampling allows multiple partitions per view; a
    // receiver is kept iff *every* matching partition keeps sender/receiver
    // in the same block.
    let actives: Vec<SetPartition> = schedule
        .iter()
        .filter(|f| f.view.get() == view && scope_matches(f.scope))
        .map(|f| f.partition)
        .collect();
    let kept: Vec<P> = if actives.is_empty() {
        recipients
    } else {
        recipients
            .into_iter()
            .filter(|pk| {
                let Some(idx) = participants.iter().position(|q| q == pk) else {
                    return true;
                };
                actives.iter().all(|p| p.connected(sender_idx, idx))
            })
            .collect()
    };
    if kept.is_empty() {
        None
    } else {
        Some(kept)
    }
}

/// Compact log representation for a recipient set.
fn idx_of<P: PublicKey>(set: &[P], participants: &[P]) -> Vec<usize> {
    set.iter()
        .filter_map(|pk| participants.iter().position(|q| q == pk))
        .collect()
}

/// Apply procFault interception to `recipients`: enqueue an [`Intercept`] per
/// matching fault (view *and* scope) and remove its targets from the list.
#[allow(clippy::too_many_arguments)]
fn apply_proc_faults<P: PublicKey>(
    channel: InterceptChannel,
    sender_idx: usize,
    view: u64,
    bytes: &[u8],
    mut recipients: Vec<P>,
    proc_schedule: &[ProcessFault<P>],
    intercept_tx: &UnboundedSender<Intercept<P>>,
    participants: &[P],
    scope_matches: impl Fn(FaultScope) -> bool,
) -> Vec<P> {
    for fault in proc_schedule
        .iter()
        .filter(|f| f.view == view && scope_matches(f.scope))
    {
        let targets: Vec<P> = recipients
            .iter()
            .filter(|r| fault.receivers.contains(r))
            .cloned()
            .collect();
        if targets.is_empty() {
            continue;
        }
        let target_idx = idx_of(&targets, participants);
        let mut line = String::new();
        let _ = write!(
            line,
            "byzzfuzz: intercept channel={:?} view={} sender={} targets={:?} seed={} omit={} scope={:?}",
            channel, view, sender_idx, target_idx, fault.seed, fault.omit, fault.scope,
        );
        log::push(line);
        let _ = intercept_tx.send(Intercept {
            channel,
            view,
            bytes: bytes.to_vec(),
            fault_seed: fault.seed,
            omit: fault.omit,
            targets: targets.clone(),
        });
        recipients.retain(|r| !targets.contains(r));
    }
    recipients
}

// -----------------------------------------------------------------------------
// Factories
// -----------------------------------------------------------------------------

/// Per-message forwarder for a sender's vote channel. See module docs.
#[allow(clippy::too_many_arguments)]
pub fn make_vote<S: Scheme<Sha256Digest>>(
    participants: Arc<[S::PublicKey]>,
    sender_idx: usize,
    network_schedule: Arc<Vec<NetworkFault>>,
    proc_schedule: Arc<Vec<ProcessFault<S::PublicKey>>>,
    sender_view: SenderViewCell,
    intercept_tx: Option<UnboundedSender<Intercept<S::PublicKey>>>,
    pool: Arc<ObservedState>,
) -> impl SplitForwarder<S::PublicKey> {
    move |_origin: SplitOrigin, recipients: &Recipients<S::PublicKey>, message: &IoBuf| {
        let Ok(msg) = Vote::<S, Sha256Digest>::decode(message.clone()) else {
            // Undecodable: bypass scope filtering (no kind to match) and
            // leave the network-layer behavior unchanged.
            return Some(recipients.clone());
        };
        pool.observe_vote::<S, S::PublicKey>(&msg);
        sender_view.update(msg.view().get());
        let kind = scope::vote_kind::<S, S::PublicKey>(&msg);
        let view = sender_view.get();
        let expanded = expand(recipients, &participants);
        let kept = match filter_by_partition(
            expanded.clone(),
            &participants,
            sender_idx,
            &network_schedule,
            view,
            |s| s.matches_vote(kind),
        ) {
            None => {
                log::push(format!(
                    "byzzfuzz: drop channel=Vote kind={:?} view={view} sender={sender_idx} recipients={:?} reason=partition",
                    kind, idx_of(&expanded, &participants),
                ));
                return None;
            }
            Some(k) => k,
        };
        let kept = match intercept_tx.as_ref() {
            Some(tx) => apply_proc_faults(
                InterceptChannel::Vote,
                sender_idx,
                view,
                message.as_ref(),
                kept,
                &proc_schedule,
                tx,
                &participants,
                |s| s.matches_vote(kind),
            ),
            None => kept,
        };
        if kept.is_empty() {
            None
        } else {
            Some(Recipients::Some(kept))
        }
    }
}

/// Per-message forwarder for a sender's certificate channel.
#[allow(clippy::too_many_arguments)]
pub fn make_certificate<S: Scheme<Sha256Digest>>(
    cert_codec: <S::Certificate as Read>::Cfg,
    participants: Arc<[S::PublicKey]>,
    sender_idx: usize,
    network_schedule: Arc<Vec<NetworkFault>>,
    proc_schedule: Arc<Vec<ProcessFault<S::PublicKey>>>,
    sender_view: SenderViewCell,
    intercept_tx: Option<UnboundedSender<Intercept<S::PublicKey>>>,
    pool: Arc<ObservedState>,
) -> impl SplitForwarder<S::PublicKey>
where
    <S::Certificate as Read>::Cfg: Clone + Send + Sync + 'static,
{
    move |_origin: SplitOrigin, recipients: &Recipients<S::PublicKey>, message: &IoBuf| {
        let Ok(msg) =
            Certificate::<S, Sha256Digest>::decode_cfg(&mut message.as_ref(), &cert_codec)
        else {
            return Some(recipients.clone());
        };
        pool.observe_certificate::<S, S::PublicKey>(&msg, message.as_ref());
        sender_view.update(msg.view().get());
        let kind = scope::certificate_kind::<S, S::PublicKey>(&msg);
        let view = sender_view.get();
        let expanded = expand(recipients, &participants);
        let kept = match filter_by_partition(
            expanded.clone(),
            &participants,
            sender_idx,
            &network_schedule,
            view,
            |s| s.matches_certificate(kind),
        ) {
            None => {
                log::push(format!(
                    "byzzfuzz: drop channel=Cert kind={:?} view={view} sender={sender_idx} recipients={:?} reason=partition",
                    kind, idx_of(&expanded, &participants),
                ));
                return None;
            }
            Some(k) => k,
        };
        let kept = match intercept_tx.as_ref() {
            Some(tx) => apply_proc_faults(
                InterceptChannel::Cert,
                sender_idx,
                view,
                message.as_ref(),
                kept,
                &proc_schedule,
                tx,
                &participants,
                |s| s.matches_certificate(kind),
            ),
            None => kept,
        };
        if kept.is_empty() {
            None
        } else {
            Some(Recipients::Some(kept))
        }
    }
}

// Resolver-specific scopes are not yet sampled; only `FaultScope::Any`
// applies on this channel.
#[allow(clippy::too_many_arguments)]
pub fn make_resolver<S: Scheme<Sha256Digest>>(
    cert_codec: <S::Certificate as Read>::Cfg,
    participants: Arc<[S::PublicKey]>,
    sender_idx: usize,
    network_schedule: Arc<Vec<NetworkFault>>,
    proc_schedule: Arc<Vec<ProcessFault<S::PublicKey>>>,
    sender_view: SenderViewCell,
    intercept_tx: Option<UnboundedSender<Intercept<S::PublicKey>>>,
    pool: Arc<ObservedState>,
) -> impl SplitForwarder<S::PublicKey>
where
    <S::Certificate as Read>::Cfg: Clone + Send + Sync + 'static,
{
    move |_origin: SplitOrigin, recipients: &Recipients<S::PublicKey>, message: &IoBuf| {
        // Decode the wire shape (8-byte id + 1-byte tag + payload) and fold
        // any extracted view into the sender's round cell *before* reading
        // it -- otherwise the resolver send would be filtered against a
        // stale rnd(m).
        let bytes = message.as_ref();
        if bytes.len() >= 9 {
            let tag = bytes[8];
            let payload = &bytes[9..];
            match tag {
                // Request(U64): exactly 8 BE bytes.
                0 if payload.len() == 8 => {
                    let mut be = [0u8; 8];
                    be.copy_from_slice(payload);
                    let v = u64::from_be_bytes(be);
                    pool.observe_resolver_request(v);
                    sender_view.update(v);
                }
                // Response(Bytes): varint length, then exactly that many
                // certificate bytes.
                1 => {
                    let mut buf = payload;
                    let range: RangeCfg<usize> = (..).into();
                    if let Ok(len) = usize::read_cfg(&mut buf, &range) {
                        if buf.len() == len {
                            let cert_slice = &buf[..len];
                            if let Ok(c) = Certificate::<S, Sha256Digest>::decode_cfg(
                                &mut &cert_slice[..],
                                &cert_codec,
                            ) {
                                pool.observe_certificate::<S, S::PublicKey>(&c, cert_slice);
                                sender_view.update(c.view().get());
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        let view = sender_view.get();
        let expanded = expand(recipients, &participants);
        let kept = match filter_by_partition(
            expanded.clone(),
            &participants,
            sender_idx,
            &network_schedule,
            view,
            FaultScope::matches_resolver,
        ) {
            None => {
                log::push(format!(
                    "byzzfuzz: drop channel=Resolver view={view} sender={sender_idx} recipients={:?} reason=partition",
                    idx_of(&expanded, &participants),
                ));
                return None;
            }
            Some(k) => k,
        };
        let kept = match intercept_tx.as_ref() {
            Some(tx) => apply_proc_faults(
                InterceptChannel::Resolver,
                sender_idx,
                view,
                message.as_ref(),
                kept,
                &proc_schedule,
                tx,
                &participants,
                FaultScope::matches_resolver,
            ),
            None => kept,
        };
        if kept.is_empty() {
            None
        } else {
            Some(Recipients::Some(kept))
        }
    }
}
