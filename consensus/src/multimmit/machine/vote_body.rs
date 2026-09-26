//! Vote bodies and chain proposals: projecting each producer chain against this node's DA
//! choices.
//!
//! A leader proposes, for each chain, the highest certificate this node holds above the parent's
//! tip. A vote body answers a leader block chain by chain with the position this node's DA
//! choices support and any extension beyond it, bounded by the protocol's extension bound.

use super::{
    chain::{ChainError, ChainState},
    da::DaChoice,
};
use crate::{
    multimmit::types::{
        Anchor, BlockRef, ChainProposal, DigestedLeader, Extension, LeaderBlock, Position, VoteBody,
    },
    types::{Height, Round},
};
use commonware_cryptography::{Digest, Hasher, bls12381::primitives::variant::Variant};
use std::collections::BTreeMap;

/// A resumable vote-body construction for one leader block.
pub(crate) struct VoteBodyPass<V: Variant, D: Digest> {
    leader: LeaderBlock<V, D>,
    // A vote decision uses one immutable DA frontier even if later validations complete while
    // its budgeted body construction is still in progress.
    da_frontiers: Vec<Height>,
    chain: usize,
    positions: Vec<Position>,
    extensions: Vec<Extension<D>>,
    extension_bound: usize,
}

impl<V: Variant, D: Digest> VoteBodyPass<V, D> {
    /// Returns the event that reports this pass beginning.
    pub(crate) const fn started(&self) -> VoteBuild {
        VoteBuild::Started {
            round: self.leader.round(),
            extension_bound: self.extension_bound,
        }
    }
}

/// Diagnostics for one completed vote body. They never influence protocol decisions.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct VoteBuildStats {
    /// Extension entries on chains whose proposal this node endorsed in full.
    pub(crate) eligible_extensions: usize,
    /// Chains whose endorsed position stops short of the proposal.
    pub(crate) short_chains: usize,
    /// Chains whose extension reached the extension bound.
    pub(crate) extension_cap_chains: usize,
    /// Chains whose DA choices advanced past the pass's frozen frontier before it completed.
    pub(crate) late_da_chains: usize,
}

/// One step in the lifecycle of this node's vote-body pass, reported for tracing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum VoteBuild {
    /// A pass began for the leader block of `round`.
    Started {
        round: Round,
        extension_bound: usize,
    },
    /// The in-flight pass produced its body.
    Completed(VoteBuildStats),
    /// The in-flight pass was discarded before producing its body.
    Abandoned,
}

/// The most vote-pass events one poll reports: it drives the pass once, so at most one
/// abandonment, one start, and one completion.
const POLL_VOTE_BUILDS: usize = 3;

/// The vote-pass events of one poll, in the order they happened.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct VoteBuilds {
    events: [Option<VoteBuild>; POLL_VOTE_BUILDS],
}

impl VoteBuilds {
    /// Appends `build` after the events already recorded.
    pub(crate) fn push(&mut self, build: VoteBuild) {
        let slot = self.events.iter_mut().find(|event| event.is_none());
        debug_assert!(
            slot.is_some(),
            "a poll reports at most {POLL_VOTE_BUILDS} vote-pass events"
        );
        if let Some(slot) = slot {
            *slot = Some(build);
        }
    }
}

impl IntoIterator for VoteBuilds {
    type Item = VoteBuild;
    type IntoIter = core::iter::Flatten<core::array::IntoIter<Option<VoteBuild>, POLL_VOTE_BUILDS>>;

    fn into_iter(self) -> Self::IntoIter {
        self.events.into_iter().flatten()
    }
}

/// The result of advancing a vote-body pass.
pub(crate) enum VoteBodyProgress<D: Digest> {
    Pending,
    Complete {
        body: VoteBody<D>,
        stats: VoteBuildStats,
    },
}

impl<V: Variant, D: Digest> ChainState<V, D> {
    /// Builds one chain's proposal: the highest certificate this node holds above `tip`, or `tip`
    /// itself when it holds none.
    ///
    /// A proposal carries no payloads, so every voter reports the anchor itself. Fresh blocks
    /// enter a view only through vote extensions, which the protocol's extension bound limits
    /// (zero accepts none).
    pub(crate) fn propose_chain(
        &self,
        tip: BlockRef<D>,
    ) -> Result<ChainProposal<V, D>, ChainError> {
        let chain = tip.chain().index();
        let state = self.da.chains.get(chain).ok_or(ChainError::Context)?;
        let anchor = state
            .certified
            .range(..)
            .rev()
            .take_while(|(height, _)| **height > tip.height())
            .find_map(|(_, certified)| certified.certificate.clone())
            .map_or(Anchor::Tip(tip), Anchor::Certificate);
        ChainProposal::new(
            tip.chain(),
            anchor,
            Vec::new(),
            self.config.pipeline_depth(),
        )
        .map_err(|_| ChainError::Context)
    }

    /// Starts a resumable vote-body pass for `leader` against the current DA frontiers.
    pub(crate) fn begin_vote_body_pass(&self, leader: LeaderBlock<V, D>) -> VoteBodyPass<V, D> {
        VoteBodyPass {
            leader,
            da_frontiers: self
                .da
                .chains
                .iter()
                .map(|chain| {
                    chain
                        .local_da_votes
                        .last_key_value()
                        .map_or(Height::zero(), |(height, _)| *height)
                })
                .collect(),
            chain: 0,
            positions: Vec::with_capacity(self.config.chains()),
            extensions: Vec::with_capacity(self.config.chains()),
            extension_bound: self.config.extension_bound(),
        }
    }

    /// Advances one vote-body pass by one chain: the endorsed proposal prefix, then up to the
    /// extension bound of this node's DA choices above it.
    ///
    /// Each chain costs at most the pipelining depth plus the extension bound of map lookups, so a
    /// step is cheap however deep the proposal reaches, and a body for every chain completes
    /// within a single drive rather than trickling out one payload entry per credit.
    pub(crate) fn resume_vote_body_pass<H: Hasher<Digest = D>>(
        &self,
        pass: &mut VoteBodyPass<V, D>,
    ) -> Result<VoteBodyProgress<D>, ChainError> {
        if pass.chain == pass.leader.proposals().len() {
            let body = VoteBody::for_leader(
                DigestedLeader::new::<H>(&pass.leader),
                pass.positions.clone(),
                pass.extensions.clone(),
                self.config,
            )
            .map_err(|_| ChainError::Context)?;
            let stats = self.vote_build_stats(pass);
            return Ok(VoteBodyProgress::Complete { body, stats });
        }

        let proposal = &pass.leader.proposals()[pass.chain];
        let frontier = *pass
            .da_frontiers
            .get(pass.chain)
            .ok_or(ChainError::Context)?;
        let (position, extension) =
            self.chain_vote_body::<H>(proposal, pass.chain, pass.extension_bound, Some(frontier))?;
        pass.positions.push(position);
        pass.extensions.push(extension);
        pass.chain += 1;
        Ok(VoteBodyProgress::Pending)
    }

    /// Summarizes the body a completed `pass` chose.
    fn vote_build_stats(&self, pass: &VoteBodyPass<V, D>) -> VoteBuildStats {
        let mut stats = VoteBuildStats::default();
        for ((proposal, position), extension) in pass
            .leader
            .proposals()
            .iter()
            .zip(&pass.positions)
            .zip(&pass.extensions)
        {
            let full = position.get() as usize == proposal.payloads().len();
            if full {
                stats.eligible_extensions += extension.len();
            }
            stats.short_chains += usize::from(!full);
            stats.extension_cap_chains +=
                usize::from(pass.extension_bound > 0 && extension.len() == pass.extension_bound);
        }
        // A later DA choice can miss this vote's immutable snapshot even while body construction
        // is still yielding between chains.
        stats.late_da_chains = self
            .da
            .chains
            .iter()
            .zip(&pass.da_frontiers)
            .filter(|(chain, frozen)| {
                chain
                    .local_da_votes
                    .last_key_value()
                    .is_some_and(|(height, _)| height > *frozen)
            })
            .count();
        stats
    }

    /// Projects one chain against contiguous DA choices, ignoring choices above `frontier` when
    /// one is given.
    fn chain_vote_body<H: Hasher<Digest = D>>(
        &self,
        proposal: &ChainProposal<V, D>,
        chain: usize,
        extension_bound: usize,
        frontier: Option<Height>,
    ) -> Result<(Position, Extension<D>), ChainError> {
        let votes = &self
            .da
            .chains
            .get(chain)
            .ok_or(ChainError::Context)?
            .local_da_votes;
        let mut parent = proposal.anchor().block_ref::<H>();
        let mut position = 0usize;
        for payload in proposal.payloads() {
            let Some(choice) = Self::next_da_choice(votes, parent, frontier, chain) else {
                break;
            };
            if choice.header().body_digest() != *payload {
                break;
            }
            position += 1;
            parent = choice.block_ref();
        }
        let mut extension_payloads = Vec::with_capacity(extension_bound);
        while extension_payloads.len() < extension_bound {
            let Some(choice) = Self::next_da_choice(votes, parent, frontier, chain) else {
                break;
            };
            extension_payloads.push(choice.header().body_digest());
            parent = choice.block_ref();
        }
        let position = u32::try_from(position).map_err(|_| ChainError::Context)?;
        Ok((
            Position::new(position),
            Extension::new(extension_payloads, extension_bound).map_err(|_| ChainError::Context)?,
        ))
    }

    /// Returns this node's DA choice above `parent` on `chain`, if it is not above `frontier`.
    fn next_da_choice(
        votes: &BTreeMap<Height, DaChoice<D>>,
        parent: BlockRef<D>,
        frontier: Option<Height>,
        chain: usize,
    ) -> Option<&DaChoice<D>> {
        let height = Height::new(parent.height().get().checked_add(1)?);
        if frontier.is_some_and(|frontier| height > frontier) {
            return None;
        }
        let choice = votes.get(&height)?;
        (choice.header().chain().index() == chain && choice.header().parent() == parent.digest())
            .then_some(choice)
    }

    /// Builds the full vote body for `leader` in one call.
    pub(crate) fn vote_body<H: Hasher<Digest = D>>(
        &self,
        leader: &LeaderBlock<V, D>,
    ) -> Result<VoteBody<D>, ChainError> {
        let config = self.config;
        let mut positions = Vec::with_capacity(config.chains());
        let mut extensions = Vec::with_capacity(config.chains());

        for (index, proposal) in leader.proposals().iter().enumerate() {
            let (position, extension) =
                self.chain_vote_body::<H>(proposal, index, config.extension_bound(), None)?;
            positions.push(position);
            extensions.push(extension);
        }

        VoteBody::for_leader(
            DigestedLeader::new::<H>(leader),
            positions,
            extensions,
            config,
        )
        .map_err(|_| ChainError::Context)
    }
}
