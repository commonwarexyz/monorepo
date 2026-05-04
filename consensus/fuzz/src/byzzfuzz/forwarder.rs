//! Per-channel `SplitForwarder` factories implementing the *interception* half
//! of Algorithm 1 (paper) at the network layer.
//!
//! Each factory produces a closure installed via `Sender::split_with` on a
//! validator's outgoing channel. The closure recovers `rnd(m)` from the
//! shared per-sender [`SenderViewCell`] -- the paper's "max round in which
//! the sender has sent or received a message". Outgoing vote / cert
//! forwarders also fold `m.view()` into the cell *before* reading it, so
//! a fresh transmission's view is included in `rnd(m)` while a
//! retransmission of an old view at a later sender round still sees the
//! sender's current round (matching the paper's "we apply the same faults
//! to retransmissions sent in the same protocol round, but allow their
//! nonfaulty delivery if they are repeated in a later round"). The
//! resolver forwarder reads the cell directly; received resolver, vote,
//! and cert traffic feed it via [`super::intercept::RoundTrackingReceiver`].
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
        fault::ProcessFault,
        intercept::{Intercept, InterceptChannel, SenderViewCell},
        log,
    },
    utils::SetPartition,
};
use commonware_codec::{Decode, DecodeExt, Read};
use commonware_consensus::{
    simplex::{
        scheme::Scheme,
        types::{Certificate, Vote},
    },
    types::View,
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

/// Drop receivers not in `sender_idx`'s partition block at `view`. Returns
/// `None` (= drop entirely) when nothing is left.
fn filter_by_partition<P: PublicKey>(
    recipients: Vec<P>,
    participants: &[P],
    sender_idx: usize,
    schedule: &[(View, SetPartition)],
    view: u64,
) -> Option<Vec<P>> {
    let active = schedule
        .iter()
        .find_map(|(v, p)| (v.get() == view).then_some(*p));
    let kept: Vec<P> = match active {
        None => recipients,
        Some(partition) => recipients
            .into_iter()
            .filter(|pk| {
                let Some(idx) = participants.iter().position(|q| q == pk) else {
                    return true;
                };
                partition.connected(sender_idx, idx)
            })
            .collect(),
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
/// matching fault and remove its targets from the list. Returns the residual
/// to which the *original* message should still be delivered.
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
) -> Vec<P> {
    for fault in proc_schedule.iter().filter(|f| f.view == view) {
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
            "byzzfuzz: intercept channel={:?} view={} sender={} targets={:?} seed={} omit={}",
            channel, view, sender_idx, target_idx, fault.seed, fault.omit,
        );
        log::push(line);
        // tokio mpsc UnboundedSender::send is sync (returns Err on closed).
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
    network_schedule: Arc<Vec<(View, SetPartition)>>,
    proc_schedule: Arc<Vec<ProcessFault<S::PublicKey>>>,
    sender_view: SenderViewCell,
    intercept_tx: Option<UnboundedSender<Intercept<S::PublicKey>>>,
) -> impl SplitForwarder<S::PublicKey> {
    move |_origin: SplitOrigin, recipients: &Recipients<S::PublicKey>, message: &IoBuf| {
        // Best-effort decode to fold the message's own view into the sender's
        // max-round cell -- the cell is the round attribution per the paper:
        // "rnd(m) = max round in which the sender has sent or received a
        // message". A retransmission of an old view at a later sender round
        // therefore does NOT pick up the old round's faults.
        if let Ok(msg) = Vote::<S, Sha256Digest>::decode(message.clone()) {
            sender_view.update(msg.view().get());
        }
        let view = sender_view.get();
        let expanded = expand(recipients, &participants);
        let kept = match filter_by_partition(
            expanded.clone(),
            &participants,
            sender_idx,
            &network_schedule,
            view,
        ) {
            None => {
                log::push(format!(
                    "byzzfuzz: drop channel=Vote view={view} sender={sender_idx} recipients={:?} reason=partition",
                    idx_of(&expanded, &participants),
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

/// Per-message forwarder for a sender's certificate channel. Same shape as
/// [`make_vote`] but decodes [`Certificate`] to update the round cell.
#[allow(clippy::too_many_arguments)]
pub fn make_certificate<S: Scheme<Sha256Digest>>(
    cert_codec: <S::Certificate as Read>::Cfg,
    participants: Arc<[S::PublicKey]>,
    sender_idx: usize,
    network_schedule: Arc<Vec<(View, SetPartition)>>,
    proc_schedule: Arc<Vec<ProcessFault<S::PublicKey>>>,
    sender_view: SenderViewCell,
    intercept_tx: Option<UnboundedSender<Intercept<S::PublicKey>>>,
) -> impl SplitForwarder<S::PublicKey>
where
    <S::Certificate as Read>::Cfg: Clone + Send + Sync + 'static,
{
    move |_origin: SplitOrigin, recipients: &Recipients<S::PublicKey>, message: &IoBuf| {
        if let Ok(msg) =
            Certificate::<S, Sha256Digest>::decode_cfg(&mut message.as_ref(), &cert_codec)
        {
            sender_view.update(msg.view().get());
        }
        let view = sender_view.get();
        let expanded = expand(recipients, &participants);
        let kept = match filter_by_partition(
            expanded.clone(),
            &participants,
            sender_idx,
            &network_schedule,
            view,
        ) {
            None => {
                log::push(format!(
                    "byzzfuzz: drop channel=Cert view={view} sender={sender_idx} recipients={:?} reason=partition",
                    idx_of(&expanded, &participants),
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

/// Per-message forwarder for a sender's resolver channel.
///
/// Resolver traffic carries no protocol view; like vote/cert it uses
/// [`SenderViewCell`] -- which by then reflects the union of "any view this
/// sender has sent or received", per the paper's `rnd(m)` definition.
#[allow(clippy::too_many_arguments)]
pub fn make_resolver<P: PublicKey>(
    participants: Arc<[P]>,
    sender_idx: usize,
    network_schedule: Arc<Vec<(View, SetPartition)>>,
    proc_schedule: Arc<Vec<ProcessFault<P>>>,
    sender_view: SenderViewCell,
    intercept_tx: Option<UnboundedSender<Intercept<P>>>,
) -> impl SplitForwarder<P> {
    move |_origin: SplitOrigin, recipients: &Recipients<P>, message: &IoBuf| {
        let view = sender_view.get();
        let expanded = expand(recipients, &participants);
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
