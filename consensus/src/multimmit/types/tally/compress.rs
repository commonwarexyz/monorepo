//! Building the canonical tally from expanded votes.

use super::{Deviation, ExtensionDeviation, PositionDeviation, Tally};
use crate::multimmit::types::{
    ChainId, CodecConfig, DigestedLeader, Error, Extension, LeaderBlock, Position, VoteBody,
};
use commonware_codec::Encode;
use commonware_cryptography::{
    Digest, bls12381::primitives::variant::Variant, certificate::Signers,
};
use commonware_utils::Participant;
use core::num::NonZeroUsize;
use std::collections::{BTreeMap, BTreeSet};

impl<D: Digest> Tally<D> {
    /// Builds the canonical tally for a collection of complete votes for `leader`.
    pub fn from_votes<V, I>(
        leader: DigestedLeader<'_, V, D>,
        votes: I,
        config: CodecConfig,
    ) -> Result<Self, Error>
    where
        V: Variant,
        I: IntoIterator<Item = (Participant, VoteBody<D>)>,
    {
        let block = leader.block();
        let mut votes: Vec<_> = votes.into_iter().collect();
        votes.sort_by_key(|(signer, _)| *signer);
        if votes.is_empty() {
            return Err(Error::Quorum);
        }
        if block.proposals().len() != config.chains() {
            return Err(Error::Context);
        }
        if votes.windows(2).any(|pair| pair[0].0 == pair[1].0)
            || votes
                .iter()
                .any(|(signer, _)| usize::from(*signer) >= config.participants())
            || votes.iter().any(|(_, body)| {
                body.positions().len() != config.chains()
                    || body.extensions().len() != config.chains()
            })
        {
            return Err(Error::Participants);
        }
        if votes.iter().any(|(_, body)| !body.valid_for(leader)) {
            return Err(Error::Transcript);
        }

        let reference_extensions = canonical_reference(
            block,
            votes
                .iter()
                .map(|(_, body)| (body.positions(), body.extensions())),
        );
        let extension_paths: Vec<_> = votes
            .iter()
            .flat_map(|(_, body)| body.extensions().iter().zip(&reference_extensions))
            .filter_map(|(extension, reference)| {
                (!extension.is_empty() && extension != reference).then_some(extension)
            })
            .collect::<BTreeSet<_>>()
            .into_iter()
            .cloned()
            .collect();
        let deviations = votes
            .iter()
            .filter_map(|(signer, body)| {
                deviation_for(
                    *signer,
                    body,
                    block,
                    &reference_extensions,
                    &extension_paths,
                )
            })
            .collect();

        let signers = Signers::new(
            config
                .participants()
                .try_into()
                .map_err(|_| Error::Participants)?,
            votes.iter().map(|(signer, _)| *signer),
        )
        .map_err(|_| Error::Participants)?;
        Ok(Self {
            reference_extensions,
            signers,
            deviations,
            extension_paths,
        })
    }
}

/// Returns how `body` differs from `leader`'s proposal tips and `reference`, or `None` when it
/// is a standard vote.
///
/// Every nonempty extension that differs from the reference must be one of `paths`.
fn deviation_for<V: Variant, D: Digest>(
    signer: Participant,
    body: &VoteBody<D>,
    leader: &LeaderBlock<V, D>,
    reference: &[Extension<D>],
    paths: &[Extension<D>],
) -> Option<Deviation> {
    let positions = body
        .positions()
        .iter()
        .zip(leader.proposals())
        .enumerate()
        .filter(|(_, (position, proposal))| position.get() < proposal.payloads().len() as u32)
        .map(|(chain, (position, _))| PositionDeviation::new(ChainId::new(chain as u32), *position))
        .collect::<Vec<_>>();
    let extensions = body
        .extensions()
        .iter()
        .zip(reference)
        .enumerate()
        .filter(|(_, (extension, reference))| extension != reference)
        .map(|(chain, (extension, _))| {
            let path = (!extension.is_empty()).then(|| {
                let index = paths.binary_search(extension).expect("collected extension");
                NonZeroUsize::MIN.saturating_add(index)
            });
            ExtensionDeviation::new(ChainId::new(chain as u32), path)
        })
        .collect::<Vec<_>>();
    if positions.is_empty() && extensions.is_empty() {
        return None;
    }
    Some(Deviation::new(signer, positions, extensions))
}

/// Selects the reference extension vector: the most common among votes at every proposal tip
/// (or among all votes when none is), ties broken by the smallest encoding.
pub(super) fn canonical_reference<'a, V: Variant, D: Digest>(
    leader: &LeaderBlock<V, D>,
    votes: impl IntoIterator<Item = (&'a [Position], &'a [Extension<D>])>,
) -> Vec<Extension<D>> {
    let mut standard_candidates = BTreeMap::<&[Extension<D>], usize>::new();
    let mut all_candidates = BTreeMap::<&[Extension<D>], usize>::new();
    for (positions, extensions) in votes {
        *all_candidates.entry(extensions).or_default() += 1;
        let at_tips = positions
            .iter()
            .zip(leader.proposals())
            .all(|(position, proposal)| position.get() == proposal.payloads().len() as u32);
        if at_tips {
            *standard_candidates.entry(extensions).or_default() += 1;
        }
    }

    let candidates = if standard_candidates.is_empty() {
        all_candidates
    } else {
        standard_candidates
    };
    candidates
        .into_iter()
        .max_by(|(left_value, left_count), (right_value, right_count)| {
            left_count
                .cmp(right_count)
                .then_with(|| right_value.encode().cmp(&left_value.encode()))
        })
        .map(|(extensions, _)| extensions.to_vec())
        .expect("a tally always contains at least one vote")
}
