//! Joining a network by state-syncing from a sampled checkpoint.

use super::Mailbox;
use crate::executor;
use commonware_consensus::{
    Block, Roundable as _,
    aggregation::scheme::Scheme,
    marshal::Floors,
    types::{OutputIndex, Round},
};
use commonware_runtime::Clock;
use commonware_utils::NonZeroDuration;
use std::{future::Future, sync::Arc};
use tracing::{debug, warn};

/// Resumes `marshal` from the newest floor the validators serve that it accepts, then offers
/// `chain` the block of a newly sampled checkpoint every `resample`, until the chain has a base.
///
/// Peers may prune what marshal needs to resume from a floor before it does, so until marshal
/// delivers an input after its floor, each sample installs a newer floor in its place and no
/// checkpoint is offered. A checkpoint is offered only once it is at or above the index marshal
/// resumes after, so that no input after the base is missing. A chain that already has a state
/// sync target or a base, as after a restart, keeps marshal where it is and is only offered newer
/// checkpoints. Returns once the chain has a base, or the probe stopped.
///
/// Each sample asks every validator for a full checkpoint, so `resample` bounds that cost for as
/// long as the sync runs. A state sync only progresses toward a checkpoint whose state peers still
/// retain, so `resample` should not exceed how long validators retain it. The floor comes from whichever replier served the newest round, so a
/// single faulty validator can pick a genuine floor above every sampled checkpoint, which delays
/// the first offer until a checkpoint passes it. Installing a floor has no timeout, because an
/// abandoned install may still complete.
pub async fn join<E, S, B, M>(
    context: E,
    probe: Mailbox<S, B, M::Floor>,
    marshal: M,
    chain: executor::Mailbox<B>,
    resample: NonZeroDuration,
) where
    E: Clock,
    S: Scheme<B::Digest>,
    B: Block,
    M: Floors,
{
    drive(context, probe, marshal, chain, resample).await;
}

/// The executed chain a joining node state-syncs.
pub(super) trait Chain<B>: Send + Sync {
    /// Returns whether the chain has neither a base nor a state sync target.
    fn awaits_floor(&self) -> impl Future<Output = bool> + Send;

    /// Returns whether the chain has a base.
    fn has_base(&self) -> impl Future<Output = bool> + Send;

    /// Returns whether marshal delivered the chain an input after `index`, or the chain has a
    /// base.
    fn resumed_after(&self, index: OutputIndex) -> impl Future<Output = bool> + Send;

    /// Offers `block` as a state sync target, and returns `false` once the chain has a base.
    fn sync_to(&self, block: Arc<B>) -> impl Future<Output = bool> + Send;
}

impl<B: Block> Chain<B> for executor::Mailbox<B> {
    fn awaits_floor(&self) -> impl Future<Output = bool> + Send {
        Self::awaits_floor(self)
    }

    fn has_base(&self) -> impl Future<Output = bool> + Send {
        Self::has_base(self)
    }

    fn resumed_after(&self, index: OutputIndex) -> impl Future<Output = bool> + Send {
        Self::resumed_after(self, index)
    }

    fn sync_to(&self, block: Arc<B>) -> impl Future<Output = bool> + Send {
        Self::sync_to(self, block)
    }
}

/// Runs [`join`] over any [`Chain`].
pub(super) async fn drive<E, S, B, M, C>(
    context: E,
    probe: Mailbox<S, B, M::Floor>,
    marshal: M,
    chain: C,
    resample: NonZeroDuration,
) where
    E: Clock,
    S: Scheme<B::Digest>,
    B: Block,
    M: Floors,
    C: Chain<B>,
{
    let mut installing = chain.awaits_floor().await;
    let mut floor = None;
    loop {
        if chain.has_base().await {
            return;
        }
        let Some(sampled) = probe.sample().await else {
            warn!("probe stopped before the chain has a base");
            return;
        };
        if installing && !resumed(&chain, floor).await {
            let above = floor.map(|(round, _)| round);
            if let Some(installed) = install(&marshal, sampled.floors, above).await {
                floor = Some(installed);
            }
        }
        installing = installing && !resumed(&chain, floor).await;
        let height = sampled.block.height();
        match floor {
            _ if installing => {}
            Some((_, index)) if height.get() < index.get() => {
                debug!(%height, %index, "sampled checkpoint is below marshal's floor");
            }
            _ => {
                if !chain.sync_to(sampled.block).await {
                    return;
                }
            }
        }
        context.sleep(resample.get()).await;
    }
}

/// Returns whether marshal delivered `chain` an input after the installed `floor`.
async fn resumed<B, C: Chain<B>>(chain: &C, floor: Option<(Round, OutputIndex)>) -> bool {
    match floor {
        Some((_, index)) => chain.resumed_after(index).await,
        None => false,
    }
}

/// Installs the newest of `floors`, ordered newest first, that is of a round after `above` and
/// that marshal accepts. Returns its round and the index it resumes after.
///
/// Returns `None` if marshal rejects every such floor, or cannot serve the request.
async fn install<M: Floors>(
    marshal: &M,
    floors: Vec<M::Floor>,
    above: Option<Round>,
) -> Option<(Round, OutputIndex)> {
    if floors.is_empty() {
        debug!("no sampled validator served a floor");
    }
    for floor in floors {
        let round = floor.round();
        if above.is_some_and(|above| round <= above) {
            break;
        }
        match marshal.install(floor).await {
            Ok(Some(index)) => {
                debug!(?round, %index, "installed marshal's floor");
                return Some((round, index));
            }
            Ok(None) => debug!(?round, "marshal rejected a floor"),
            Err(error) => {
                warn!(%error, "marshal could not install a floor");
                return None;
            }
        }
    }
    None
}
