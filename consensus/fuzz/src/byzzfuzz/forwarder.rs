//! Per-channel `SplitForwarder` factories implementing the *interception* half
//! of Algorithm 1 (paper) at the network layer.
//!
//! Each factory produces a closure installed via `Sender::split_with` on a
//! validator's outgoing channel. The closure recovers `rnd(m)` from the
//! shared per-sender [`SenderViewCell`] -- the paper's "max round in which
//! the sender has sent or received a message". When the outgoing bytes
//! carry a decodable view (vote/cert via `m.view()`; resolver via the
//! wire `Request(U64)` key or the `Certificate` embedded in a `Response`),
//! the forwarder folds that view into the cell *before* reading it; on
//! undecodable bytes the cell's existing value stands. A retransmission
//! of an old view at a later sender round therefore inherits the sender's
//! current round (matching the paper's "we apply the same faults to
//! retransmissions sent in the same protocol round, but allow their
//! nonfaulty delivery if they are repeated in a later round"). Received
//! vote/cert/resolver traffic feeds the cell via
//! [`super::intercept::RoundTrackingReceiver`].
//!
//! Per recipient the closure then decides:
//!
//! 1. **drop** -- if the partition active at `rnd(m)` isolates the sender
//!    from that recipient (Algorithm 1 line 15). Network partitions are
//!    total at their view: every channel (vote, cert, resolver, even
//!    undecodable bytes) consults the same partition schedule.
//! 2. **enqueue** -- if the sender is byzantine and the recipient lies in a
//!    matching `procFault.receivers` set whose [`super::scope::FaultScope`]
//!    matches this channel/kind: push an `Intercept` for the
//!    `ByzzFuzzInjector` and remove the recipient from the residual
//!    original send (Algorithm 1 line 16-18; *replace* half lives in the
//!    injector);
//! 3. **deliver** -- otherwise.
//!
//! Honest senders pass an empty procFault schedule and a `None` intercept
//! sender, degenerating the closure to partition-only filtering. Same closure
//! type for all four senders -> no opaque-type mismatch in `runner::run`.

use crate::{
    byzzfuzz::{
        fault::{NetworkFault, ProcessFault},
        intercept::{self, FaultGate, Intercept, InterceptChannel, SenderViewCell},
        log,
        observed::ObservedState,
        scope::{self, FaultScope},
    },
    utils::SetPartition,
};
use commonware_codec::{Decode, DecodeExt, Read};
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

/// Expand a [`Recipients`] into an explicit list against the participant
/// set, excluding the sender. The simulated network drops self-delivery
/// later in the pipeline, but ByzzFuzz makes partition / proc-fault
/// decisions on this list -- including the sender here would let a
/// partition that isolates every real peer still appear as a non-empty
/// kept set (`[sender]`), masking what is effectively a full drop.
fn expand<P: PublicKey>(
    recipients: &Recipients<P>,
    participants: &[P],
    sender_idx: usize,
) -> Vec<P> {
    let sender = participants.get(sender_idx);
    match recipients {
        Recipients::All => participants
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != sender_idx)
            .map(|(_, p)| p.clone())
            .collect(),
        Recipients::Some(v) => v.iter().filter(|p| Some(*p) != sender).cloned().collect(),
        Recipients::One(p) => {
            if Some(p) == sender {
                Vec::new()
            } else {
                vec![p.clone()]
            }
        }
    }
}

/// Drop receivers not in `sender_idx`'s partition block at `view`. Network
/// partitions are total at their view -- no per-channel/kind filter -- so
/// every channel (vote, cert, resolver, undecodable) consults this same
/// function with no scope predicate. Returns `None` (= drop entirely)
/// when nothing is left.
fn filter_by_partition<P: PublicKey>(
    recipients: Vec<P>,
    participants: &[P],
    sender_idx: usize,
    schedule: &[NetworkFault],
    view: u64,
) -> Option<Vec<P>> {
    // Without-replacement sampling makes per-view duplicates impossible
    // for network faults, but we still iterate to be robust.
    let actives: Vec<SetPartition> = schedule
        .iter()
        .filter(|f| f.view.get() == view)
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
            "byzzfuzz: intercept channel={:?} view={} sender={} targets={:?} scheduled_omit={} scope={:?}",
            channel, view, sender_idx, target_idx, fault.omit, fault.scope,
        );
        log::push(line);
        let _ = intercept_tx.send(Intercept {
            channel,
            view,
            bytes: bytes.to_vec(),
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
    gate: FaultGate,
) -> impl SplitForwarder<S::PublicKey> {
    move |_origin: SplitOrigin, recipients: &Recipients<S::PublicKey>, message: &IoBuf| {
        let decoded = Vote::<S, Sha256Digest>::decode(message.clone()).ok();
        let Some(msg) = decoded else {
            // Undecodable: still apply the network partition (partitions
            // are total per their view) using sender_view.get(); skip
            // proc faults because there is no kind to match. After GST,
            // pass through unchanged.
            if gate.gst_reached() {
                return Some(recipients.clone());
            }
            let view = sender_view.get();
            let expanded = expand(recipients, &participants, sender_idx);
            return match filter_by_partition(
                expanded.clone(),
                &participants,
                sender_idx,
                &network_schedule,
                view,
            ) {
                None => {
                    log::push(format!(
                        "byzzfuzz: drop channel=Vote view={view} sender={sender_idx} recipients={:?} reason=partition_undecodable",
                        idx_of(&expanded, &participants),
                    ));
                    None
                }
                Some(kept) => Some(Recipients::Some(kept)),
            };
        };
        pool.observe_vote::<S, S::PublicKey>(&msg);
        sender_view.update(msg.view().get());
        // After GST, decode + observe + sender_view
        // updates still happen (rnd(m) attribution stays accurate), but
        // no faults are applied -- the message passes through.
        if gate.gst_reached() {
            return Some(recipients.clone());
        }
        let kind = scope::vote_kind::<S, S::PublicKey>(&msg);
        let view = sender_view.get();
        let expanded = expand(recipients, &participants, sender_idx);
        let kept = match filter_by_partition(
            expanded.clone(),
            &participants,
            sender_idx,
            &network_schedule,
            view,
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
    gate: FaultGate,
) -> impl SplitForwarder<S::PublicKey>
where
    <S::Certificate as Read>::Cfg: Clone + Send + Sync + 'static,
{
    move |_origin: SplitOrigin, recipients: &Recipients<S::PublicKey>, message: &IoBuf| {
        let decoded =
            Certificate::<S, Sha256Digest>::decode_cfg(&mut message.as_ref(), &cert_codec).ok();
        let Some(msg) = decoded else {
            // Undecodable: still apply the network partition (total per
            // its view) using sender_view.get(); skip proc faults
            // because there is no kind to match. After GST, pass through
            // unchanged.
            if gate.gst_reached() {
                return Some(recipients.clone());
            }
            let view = sender_view.get();
            let expanded = expand(recipients, &participants, sender_idx);
            return match filter_by_partition(
                expanded.clone(),
                &participants,
                sender_idx,
                &network_schedule,
                view,
            ) {
                None => {
                    log::push(format!(
                        "byzzfuzz: drop channel=Cert view={view} sender={sender_idx} recipients={:?} reason=partition_undecodable",
                        idx_of(&expanded, &participants),
                    ));
                    None
                }
                Some(kept) => Some(Recipients::Some(kept)),
            };
        };
        pool.observe_certificate::<S, S::PublicKey>(&msg);
        sender_view.update(msg.view().get());
        if gate.gst_reached() {
            return Some(recipients.clone());
        }
        let kind = scope::certificate_kind::<S, S::PublicKey>(&msg);
        let view = sender_view.get();
        let expanded = expand(recipients, &participants, sender_idx);
        let kept = match filter_by_partition(
            expanded.clone(),
            &participants,
            sender_idx,
            &network_schedule,
            view,
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

// Resolver-specific process-fault scopes are not yet sampled; only
// `FaultScope::Any` matches on this channel.
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
    gate: FaultGate,
) -> impl SplitForwarder<S::PublicKey>
where
    <S::Certificate as Read>::Cfg: Clone + Send + Sync + 'static,
{
    move |_origin: SplitOrigin, recipients: &Recipients<S::PublicKey>, message: &IoBuf| {
        // Fold any view carried by the outgoing wire bytes into the
        // sender's round cell *before* reading it; otherwise the resolver
        // send would be filtered against a stale rnd(m). Wire decode +
        // pool observation is shared with the inbound extractor via
        // `observe_resolver_wire_view` so a future wire-format change has
        // a single update site.
        if let Some(v) =
            intercept::observe_resolver_wire_view::<S>(message.as_ref(), &cert_codec, &pool)
        {
            sender_view.update(v);
        }
        if gate.gst_reached() {
            return Some(recipients.clone());
        }
        let view = sender_view.get();
        let expanded = expand(recipients, &participants, sender_idx);
        let kept = match filter_by_partition(
            expanded.clone(),
            &participants,
            sender_idx,
            &network_schedule,
            view,
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
