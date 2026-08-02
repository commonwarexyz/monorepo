//! Best-effort checkpoint resolution for one fixed Multimmit epoch.
//!
//! The resolver exchanges authenticated view evidence. Consensus remains responsible for
//! validating and admitting every response; application-chain history is outside this actor.

mod actor;
mod metrics;
#[cfg(test)]
mod tests;

use crate::{
    Viewable as _,
    multimmit::machine::{ResolutionJob, ViewProof},
    types::{Round, View},
};
pub use actor::{Actor, Config};
use commonware_actor::mailbox::{Overflow, Policy, UnreliablePolicy};
use commonware_cryptography::{Digest, bls12381::primitives::variant::Variant};
use commonware_utils::channel::oneshot;
use std::{
    collections::{BTreeMap, VecDeque},
    sync::Arc,
};
use tracing::Span;

/// One machine-issued resolver request.
pub struct ResolveRequest {
    /// The issuing tracing span.
    pub span: Span,
    /// The round that issued the request.
    pub round: Round,
    /// The exact machine-issued job.
    pub job: ResolutionJob,
}

/// One verified checkpoint retained for peer recovery.
pub type Served<V, D> = ViewProof<V, D>;

/// Reliable local control accepted by the resolver.
pub enum Message<V: Variant, D: Digest> {
    /// Resolve one machine-issued view request.
    Resolve(ResolveRequest),
    /// Retract one exact machine-owned request.
    Cancel { job: ResolutionJob },
    /// Reject content returned by the queried peer.
    Reject { job: ResolutionJob },
    /// Retain one machine-verified checkpoint for peers.
    Retain { proof: Served<V, D> },
    /// Retire exact view evidence no longer retained by the machine.
    Prune { through: crate::types::View },
}

/// The final resolver-custody projection within one uninterrupted control interval.
///
/// Job controls delimit intervals because moving custody across a resolve or cancellation can
/// change whether that job is served locally. Within an interval, retention is monotone: the
/// greatest L-QC covers earlier exits, V-QCs dominate nullifications at the same view, and pruning
/// discards exact exits at or below its floor.
struct RetentionDelta<V: Variant, D: Digest> {
    prune: Option<View>,
    floor: Option<Box<crate::multimmit::types::Lqc<V, D>>>,
    exits: BTreeMap<View, Served<V, D>>,
}

impl<V: Variant, D: Digest> Default for RetentionDelta<V, D> {
    fn default() -> Self {
        Self {
            prune: None,
            floor: None,
            exits: BTreeMap::new(),
        }
    }
}

impl<V: Variant, D: Digest> RetentionDelta<V, D> {
    fn retain(&mut self, proof: Served<V, D>) {
        match proof {
            ViewProof::Lqc(proof) => {
                if self
                    .floor
                    .as_ref()
                    .is_none_or(|current| proof.view() > current.view())
                {
                    self.exits.retain(|view, _| *view > proof.view());
                    self.floor = Some(proof);
                }
            }
            proof @ ViewProof::Vqc(_) => {
                let view = proof.view();
                if self.accepts_exit(view) {
                    self.exits.insert(view, proof);
                }
            }
            proof @ ViewProof::Nullification(_) => {
                let view = proof.view();
                if self.accepts_exit(view)
                    && !matches!(self.exits.get(&view), Some(ViewProof::Vqc(_)))
                {
                    self.exits.insert(view, proof);
                }
            }
        }
    }

    fn prune(&mut self, through: View) {
        if self.prune.is_some_and(|current| through <= current) {
            return;
        }
        self.prune = Some(through);
        self.exits.retain(|view, _| *view > through);
    }

    fn accepts_exit(&self, view: View) -> bool {
        self.prune.is_none_or(|through| view > through)
            && self.floor.as_ref().is_none_or(|floor| view > floor.view())
    }

    fn drain<F>(&mut self, push: &mut F) -> bool
    where
        F: FnMut(Message<V, D>) -> Option<Message<V, D>>,
    {
        if let Some(through) = self.prune.take()
            && let Some(Message::Prune { through }) = push(Message::Prune { through })
        {
            self.prune = Some(through);
            return false;
        }
        if let Some(proof) = self.floor.take() {
            let message = Message::Retain {
                proof: ViewProof::Lqc(proof),
            };
            if let Some(Message::Retain { proof }) = push(message) {
                let ViewProof::Lqc(proof) = proof else {
                    unreachable!("rejected resolver retention preserves its variant")
                };
                self.floor = Some(proof);
                return false;
            }
        }
        while let Some((view, proof)) = self.exits.pop_first() {
            if let Some(Message::Retain { proof }) = push(Message::Retain { proof }) {
                self.exits.insert(view, proof);
                return false;
            }
        }
        true
    }
}

enum OverflowChunk<V: Variant, D: Digest> {
    Job(Message<V, D>),
    Retention(RetentionDelta<V, D>),
}

/// Reliable overflow that preserves exact job controls and collapses custody projections.
#[doc(hidden)]
pub struct ControlOverflow<V: Variant, D: Digest> {
    chunks: VecDeque<OverflowChunk<V, D>>,
}

impl<V: Variant, D: Digest> Default for ControlOverflow<V, D> {
    fn default() -> Self {
        Self {
            chunks: VecDeque::new(),
        }
    }
}

impl<V: Variant, D: Digest> Overflow<Message<V, D>> for ControlOverflow<V, D> {
    fn is_empty(&self) -> bool {
        self.chunks.is_empty()
    }

    fn drain<F>(&mut self, mut push: F)
    where
        F: FnMut(Message<V, D>) -> Option<Message<V, D>>,
    {
        while let Some(mut chunk) = self.chunks.pop_front() {
            match &mut chunk {
                OverflowChunk::Job(_) => {
                    let OverflowChunk::Job(message) = chunk else {
                        unreachable!("matched resolver job chunk")
                    };
                    if let Some(message) = push(message) {
                        self.chunks.push_front(OverflowChunk::Job(message));
                        break;
                    }
                }
                OverflowChunk::Retention(delta) => {
                    if !delta.drain(&mut push) {
                        self.chunks.push_front(chunk);
                        break;
                    }
                }
            }
        }
    }
}

impl<V: Variant, D: Digest> Policy for Message<V, D> {
    type Overflow = ControlOverflow<V, D>;

    fn handle(overflow: &mut Self::Overflow, message: Self) {
        match message {
            Self::Resolve(_) | Self::Cancel { .. } | Self::Reject { .. } => {
                overflow.chunks.push_back(OverflowChunk::Job(message));
            }
            Self::Retain { proof } => {
                let Some(OverflowChunk::Retention(delta)) = overflow.chunks.back_mut() else {
                    let mut delta = RetentionDelta::default();
                    delta.retain(proof);
                    overflow.chunks.push_back(OverflowChunk::Retention(delta));
                    return;
                };
                delta.retain(proof);
            }
            Self::Prune { through } => {
                let Some(OverflowChunk::Retention(delta)) = overflow.chunks.back_mut() else {
                    let mut delta = RetentionDelta::default();
                    delta.prune(through);
                    overflow.chunks.push_back(OverflowChunk::Retention(delta));
                    return;
                };
                delta.prune(through);
            }
        }
    }
}

/// Best-effort queries over locally retained resolver state.
pub enum Query<V: Variant, D: Digest> {
    /// Read one locally retained checkpoint.
    Serve {
        view: View,
        responder: oneshot::Sender<Option<Arc<Served<V, D>>>>,
    },
}

impl<V: Variant, D: Digest> UnreliablePolicy for Query<V, D> {
    type Overflow = VecDeque<Self>;

    fn handle(_overflow: &mut Self::Overflow, _message: Self) -> bool {
        false
    }
}

/// Local endpoints for protocol control and best-effort queries.
pub struct Mailbox<V: Variant, D: Digest> {
    /// Reliable protocol-control endpoint.
    pub control: commonware_actor::mailbox::Sender<Message<V, D>>,
    /// Bounded best-effort query endpoint.
    pub queries: commonware_actor::mailbox::UnreliableSender<Query<V, D>>,
}
