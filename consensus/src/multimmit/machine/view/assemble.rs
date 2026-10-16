//! V-QC assembly: the `n - f` final votes of the current view a V-QC records, and the resolution
//! paths of their tips.
//!
//! A node holding no V-QC of its current view assembles one from the final votes it read, greedily
//! in read order. A final vote is eligible when this node holds its signature and every tip above
//! the base resolves through held headers within the tip lead `D + 2N`. The base is the tips of the
//! parent: the V-QC this node entered the view on, unless the chosen votes designate a leader block
//! naming another parent, which is then forced (and its leader block retrieved when missing).
//!
//! The paths are the canonical set [`validate_vqc`](crate::multimmit::algebra::validate_vqc)
//! accepts: one per recorded tip above the base that lies on no other recorded tip's path, each
//! from the tip's ancestor at the base height. A V-QC whose encoding exceeds `max_vqc_bytes` drops
//! the chosen vote that costs the most bytes (its deviation from the reference content plus the
//! paths only it needs) and takes the next eligible final vote instead; with `n - f` correct final
//! votes the common case never substitutes.
//!
//! The aggregation runs on the crypto pool. Its completion is staged by the forwarding drive as a
//! created certificate, unless a V-QC of the view was held meanwhile.

use crate::{
    Epochable as _,
    multimmit::{
        algebra,
        machine::{
            capability::{
                AggregateId, AttestedVote, Capabilities, Capability, CryptoJob, VqcAggregateJob,
            },
            input::{Aggregated, StepError},
            job::{IdSequence, Issued},
            reducer::machine::Machine,
            resolution::RetrievalKey,
            scheduler::ProtocolComponent,
            view::{
                proposal::{HeldVqc, Proposal},
                vqc::Identified,
            },
        },
        types::{
            Artifact, Attestation, BlockRef, CertificateId, CodecConfig, FinalTally, LeaderBlock,
            ResolutionPath, VoteContent, Vqc,
        },
    },
    types::{Attributable as _, Participant, Round, View},
};
use commonware_codec::{EncodeSize as _, FixedSize as _};
use commonware_cryptography::{Digest, Hasher, bls12381::primitives::variant::Variant};
use std::{
    collections::{BTreeMap, HashSet},
    sync::Arc,
};

/// The state of this node's V-QC assembly.
pub(crate) struct Assembly<V: Variant, D: Digest> {
    /// The signature of every final vote read, per view and sender.
    attestations: BTreeMap<(View, Participant), Attestation<V>>,
    /// The aggregation in flight and the view it is for.
    pending: Option<(Issued<AggregateId>, View)>,
    ids: IdSequence<AggregateId>,
    /// An assembled V-QC waiting to be staged, with its artifact identifier.
    pub(in crate::multimmit::machine) created: Option<Identified<V, D>>,
}

impl<V: Variant, D: Digest> Assembly<V, D> {
    pub(crate) const fn new() -> Self {
        Self {
            attestations: BTreeMap::new(),
            pending: None,
            ids: IdSequence::new(),
            created: None,
        }
    }
}

/// The path from a tip's ancestor at the base height up to the tip.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Resolution<D: Digest> {
    /// The tip's ancestor at the base height.
    pub(crate) from: BlockRef<D>,
    /// The blocks above `from` up to the tip, lowest first.
    pub(crate) blocks: Vec<BlockRef<D>>,
    /// The payload hashes of `blocks`.
    pub(crate) payloads: Vec<D>,
}

impl<D: Digest> Resolution<D> {
    fn top(&self) -> Option<&BlockRef<D>> {
        self.blocks.last()
    }
}

/// A final vote eligible for a V-QC.
#[derive(Clone, Debug)]
pub(crate) struct Candidate<V: Variant, D: Digest> {
    pub(crate) content: Arc<VoteContent<D>>,
    pub(crate) attestation: Attestation<V>,
    /// The resolution of every tip above the base.
    pub(crate) resolutions: Vec<Resolution<D>>,
}

impl<V: Variant, D: Digest> Candidate<V, D> {
    fn signer(&self) -> Participant {
        self.attestation.signer()
    }
}

/// The votes and paths of one V-QC.
#[derive(Clone, Debug)]
pub(crate) struct Selection<V: Variant, D: Digest> {
    /// The chosen final votes in ascending signer order.
    pub(crate) votes: Vec<AttestedVote<V, D>>,
    /// The canonical resolution paths of their tips.
    pub(crate) paths: Vec<ResolutionPath<D>>,
}

impl<V: Variant, D: Digest> Selection<V, D> {
    /// Returns the leader block at least `n - 3f` of the chosen votes are for, if any.
    fn designated(&self, config: CodecConfig) -> Option<D> {
        algebra::designated(
            self.votes.iter().map(|(content, _)| content.leader()),
            config,
        )
    }
}

/// Chooses the votes of a V-QC of `round` above `parent` from `candidates`, in preference order:
/// the first `n - f`, with the costliest chosen vote replaced by the next candidate while the V-QC
/// exceeds `max_vqc_bytes`. Returns `None` when the candidates run out.
pub(crate) fn select<V: Variant, D: Digest>(
    candidates: &[Candidate<V, D>],
    round: Round,
    parent: CertificateId<D>,
    config: CodecConfig,
) -> Option<Selection<V, D>> {
    let quorum = config.view_quorum();
    if candidates.len() < quorum {
        return None;
    }
    let mut chosen = (0..quorum).collect::<Vec<_>>();
    let mut next = quorum;
    loop {
        let paths = canonical_paths(chosen.iter().map(|index| &candidates[*index]), config)?;
        let tally = FinalTally::from_contents(
            chosen.iter().map(|index| {
                let candidate = &candidates[*index];
                (candidate.signer(), candidate.content.as_ref().clone())
            }),
            paths.clone(),
            config,
        )
        .ok()?;
        let size =
            round.encode_size() + parent.encode_size() + tally.encode_size() + V::Signature::SIZE;
        if size <= config.max_vqc_bytes() {
            let mut votes = chosen
                .iter()
                .map(|index| {
                    let candidate = &candidates[*index];
                    (
                        candidate.content.as_ref().clone(),
                        candidate.attestation.clone(),
                    )
                })
                .collect::<Vec<_>>();
            votes.sort_by_key(|(_, attestation)| attestation.signer());
            return Some(Selection { votes, paths });
        }
        if next == candidates.len() {
            return None;
        }
        let costliest = chosen
            .iter()
            .enumerate()
            .max_by_key(|(position, index)| {
                (
                    cost(&tally, &candidates[**index], &chosen, candidates),
                    *position,
                )
            })
            .map(|(position, _)| position)?;
        chosen.remove(costliest);
        chosen.push(next);
        next += 1;
    }
}

/// Returns the bytes `candidate` adds to a V-QC whose tally is `tally`: its deviation from the
/// reference content and the payload hashes of the paths to tips no other chosen vote names.
fn cost<V: Variant, D: Digest>(
    tally: &FinalTally<D>,
    candidate: &Candidate<V, D>,
    chosen: &[usize],
    candidates: &[Candidate<V, D>],
) -> usize {
    let signer = candidate.signer();
    let deviation = tally
        .deviations()
        .iter()
        .find(|deviation| deviation.signer() == signer)
        .map_or(0, |deviation| deviation.encode_size());
    let paths = candidate
        .resolutions
        .iter()
        .filter(|resolution| {
            let top = resolution.top();
            !chosen.iter().any(|index| {
                let other = &candidates[*index];
                other.signer() != signer
                    && top.is_some_and(|top| other.content.tips().contains(top))
            })
        })
        .map(|resolution| resolution.payloads.len() * D::SIZE)
        .sum::<usize>();
    deviation + paths
}

/// Returns the canonical resolution paths of `chosen`'s tips: one per resolved tip that lies on no
/// other resolved tip's path.
fn canonical_paths<'a, V: Variant, D: Digest>(
    chosen: impl Iterator<Item = &'a Candidate<V, D>>,
    config: CodecConfig,
) -> Option<Vec<ResolutionPath<D>>> {
    let mut resolutions = BTreeMap::new();
    for resolution in chosen.flat_map(|candidate| &candidate.resolutions) {
        if let Some(top) = resolution.top() {
            resolutions.entry(*top).or_insert(resolution);
        }
    }
    let interior = resolutions
        .values()
        .flat_map(|resolution| &resolution.blocks[..resolution.blocks.len() - 1])
        .collect::<HashSet<_>>();
    resolutions
        .iter()
        .filter(|(top, _)| !interior.contains(top))
        .map(|(_, resolution)| {
            ResolutionPath::new(resolution.from, resolution.payloads.clone(), config).ok()
        })
        .collect()
}

impl<H: Hasher, V: Variant> Machine<H, V> {
    /// Records the signature of a final vote read from `update`'s sender, which a V-QC this node
    /// assembles may aggregate, and wakes the assembly.
    pub(in crate::multimmit::machine) fn note_final(
        &mut self,
        view: View,
        attestation: &Attestation<V>,
    ) {
        if view < self.durable.state.view {
            return;
        }
        self.components
            .assembly
            .attestations
            .entry((view, attestation.signer()))
            .or_insert_with(|| attestation.clone());
        self.wake(ProtocolComponent::Forwarding);
    }

    /// Forgets the signatures of final votes of views below `view`.
    pub(in crate::multimmit::machine) fn retire_attestations_below(&mut self, view: View) {
        let assembly = &mut self.components.assembly;
        assembly.attestations = assembly
            .attestations
            .split_off(&(view, Participant::new(0)));
    }

    /// Resets the assembly at a start or restart: aggregations of earlier generations are stale and
    /// signatures return with the final votes they sign.
    pub(in crate::multimmit::machine) fn restore_assembly(&mut self) {
        self.components.assembly = Assembly::new();
    }

    /// Issues the aggregation of a V-QC of the current view when none is held, in flight, or
    /// waiting to be staged, and `n - f` eligible final votes are read.
    ///
    /// When the chosen votes designate a leader block this node does not hold as valid, the block
    /// is requested and the assembly waits for it.
    pub(in crate::multimmit::machine) fn assemble(
        &mut self,
    ) -> Result<Capabilities<V, H::Digest>, StepError> {
        let view = self.durable.state.view;
        let assembly = &self.components.assembly;
        if assembly.created.is_some()
            || assembly.pending.is_some_and(|(_, pending)| pending == view)
            || self.components.vqcs.view_len(view) > 0
        {
            return Ok(Capabilities::new());
        }
        let Some(parent) = self
            .components
            .view
            .state
            .parent
            .clone()
            .filter(|parent| parent.view.next() == view)
        else {
            return Ok(Capabilities::new());
        };
        let Some(mut selection) = self.select_finals(view, &parent) else {
            return Ok(Capabilities::new());
        };
        let codec = self.profile.codec();
        let round = Round::new(self.profile.protocol().epoch(), view);
        let mut parent_id = parent.id;
        if let Some(leader) = selection.designated(codec) {
            let own = LeaderBlock::new(round, parent.id, parent.history)
                .map_err(|_| StepError::ViewInvariant)?
                .digest::<H>();
            if own != leader {
                let Some(forced) = self.designated_parent(view, leader) else {
                    return Ok(self
                        .request(RetrievalKey::LeaderBlock(view))?
                        .into_iter()
                        .collect());
                };
                let Some(reselected) = self
                    .select_finals(view, &forced)
                    .filter(|selection| selection.designated(codec) == Some(leader))
                else {
                    return Ok(Capabilities::new());
                };
                selection = reselected;
                parent_id = forced.id;
            }
        }
        let assembly = &mut self.components.assembly;
        let id = assembly.ids.issue().ok_or(StepError::IdentifierExhausted)?;
        let issued = Issued::new(id, self.durable.state.generation);
        assembly.pending = Some((issued, view));
        Ok(vec![Capability::Crypto(CryptoJob::AggregateVqc(
            VqcAggregateJob::new(issued, view, parent_id, selection.votes, selection.paths),
        ))])
    }

    /// Returns the parent of the valid leader block `leader` of `view`, held with its chain.
    fn designated_parent(&self, view: View, leader: H::Digest) -> Option<HeldVqc<H::Digest>> {
        match self.components.view.proposals.get(&view)? {
            Proposal::Valid { block, parent, .. } if *block == leader => self.held_vqc(parent),
            _ => None,
        }
    }

    /// Chooses the final votes of `view` for a V-QC above `parent`, among those read whose
    /// signature is held and whose tips resolve above the parent's tips.
    ///
    /// Resolving a vote's tips walks every chain's path above the parent's tips, so nothing is
    /// resolved before `n - f` final votes with held signatures are read.
    fn select_finals(
        &self,
        view: View,
        parent: &HeldVqc<H::Digest>,
    ) -> Option<Selection<V, H::Digest>> {
        let attestations = &self.components.assembly.attestations;
        let signed = self
            .finals(view)
            .filter(|(sender, _)| attestations.contains_key(&(view, *sender)))
            .count();
        if signed < self.profile.codec().view_quorum() {
            return None;
        }
        let candidates = self
            .finals(view)
            .filter_map(|(sender, content)| {
                let attestation = attestations.get(&(view, sender))?;
                let resolutions = content
                    .tips()
                    .iter()
                    .zip(parent.tips.iter())
                    .map(|(tip, base)| self.resolution(base, tip))
                    .collect::<Option<Vec<_>>>()?
                    .into_iter()
                    .flatten()
                    .collect();
                Some(Candidate {
                    content: Arc::clone(content),
                    attestation: attestation.clone(),
                    resolutions,
                })
            })
            .collect::<Vec<_>>();
        select(
            &candidates,
            Round::new(self.profile.protocol().epoch(), view),
            parent.id,
            self.profile.codec(),
        )
    }

    /// Resolves `tip` above `base` through held headers: `Some(None)` when it needs no path (at or
    /// below the base height), `None` when a header is missing or the tip leads the base by more
    /// than the tip lead.
    pub(in crate::multimmit::machine) fn resolution(
        &self,
        base: &BlockRef<H::Digest>,
        tip: &BlockRef<H::Digest>,
    ) -> Option<Option<Resolution<H::Digest>>> {
        if tip.height() <= base.height() {
            return Some(None);
        }
        let lead = tip.height().get() - base.height().get();
        if lead > u64::from(self.profile.codec().window().max_tip_lead()) {
            return None;
        }
        let headers = &self.components.chain.headers;
        let mut blocks = Vec::with_capacity(lead as usize);
        let mut payloads = Vec::with_capacity(lead as usize);
        let mut current = *tip;
        while current.height() > base.height() {
            let entry = headers.get(&current)?;
            blocks.push(current);
            payloads.push(entry.header.body_digest());
            current = entry.header.parent_ref();
        }
        blocks.reverse();
        payloads.reverse();
        Some(Some(Resolution {
            from: current,
            blocks,
            payloads,
        }))
    }

    /// Parks an assembled V-QC for staging if it completes the aggregation in flight and no V-QC
    /// of its view was held meanwhile.
    pub(in crate::multimmit::machine) fn complete_vqc(
        &mut self,
        completion: Aggregated<Vqc<V, H::Digest>>,
    ) {
        let assembly = &mut self.components.assembly;
        let Some((_, view)) = assembly
            .pending
            .filter(|(issued, _)| *issued == completion.issued())
        else {
            return;
        };
        assembly.pending = None;
        if view != self.durable.state.view || self.components.vqcs.view_len(view) > 0 {
            return;
        }
        let artifact = Arc::new(Artifact::Vqc(completion.into_certificate()));
        let id = artifact.id::<H>();
        self.components.assembly.created = Some((id, artifact));
        self.wake(ProtocolComponent::Forwarding);
    }
}
