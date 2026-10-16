//! Checks of quorum certificates beyond their canonical encoding, and the facts they certify.
//!
//! Signature verification belongs to the scheme; these checks need only the certificate, its
//! parent's facts, and the epoch's codec configuration.

use super::{
    Error,
    path::{Path, PathAncestry},
    tips::{ensure_vector, tips},
};
use crate::{
    Epochable,
    multimmit::types::{BlockRef, CodecConfig, HistoryRecord, LeaderBlock, Lqc, VoteContent, Vqc},
    types::{Epoch, Participant},
};
use commonware_cryptography::{Digest, Hasher, bls12381::primitives::variant::Variant};
use std::collections::BTreeMap;

/// A well-formed V-QC and the facts it fixes.
#[derive(Clone, Debug)]
pub(crate) struct ValidVqc<D: Digest> {
    /// The recorded final votes, in signer order.
    pub(crate) contents: Vec<(Participant, VoteContent<D>)>,
    /// The digest of the designated leader block, when at least `n - 3f` recorded votes are for
    /// one leader block.
    pub(crate) designated: Option<D>,
    /// The record `(C(parent), Tips(Q))`.
    pub(crate) record: HistoryRecord<D>,
    /// `C(Q)`, the commitment of `record`.
    pub(crate) commitment: D,
    /// The rebuilt resolution paths.
    pub(crate) ancestry: PathAncestry<D>,
}

/// Rebuilds the resolution paths of `vqc` into an ancestry, in the tally's path order.
fn vqc_ancestry<H: Hasher, V: Variant>(
    vqc: &Vqc<V, H::Digest>,
) -> Result<PathAncestry<H::Digest>, Error> {
    let paths = vqc
        .tally()
        .paths()
        .iter()
        .map(|path| Path::rebuild::<H>(vqc.epoch(), path.from(), path.payloads()))
        .collect::<Result<_, _>>()?;
    Ok(PathAncestry::new(paths))
}

/// Checks that `vqc` is well formed as a child of the V-QC whose commitment is `parent_history`
/// and whose tips are `base`, and derives its facts.
///
/// The caller supplies the facts of the V-QC that `vqc.parent()` names. Beyond the codec's
/// checks, `vqc` is well formed when:
///
/// - every resolution path starts at the base height of its chain;
/// - every recorded tip above the base lies on a path of its chain, so every recorded vote's
///   window endorsements follow from `vqc` and `base` alone (a path from an object other than the
///   base makes its tips endorse nothing in the window);
/// - every path ends at a recorded tip and that tip lies on no other path, so the paths are the
///   unique canonical set;
/// - if at least `n - 3f` recorded votes are for one leader block, it is the block of
///   `vqc`'s round that names `vqc.parent()` and `parent_history`.
pub(crate) fn validate_vqc<H: Hasher, V: Variant>(
    vqc: &Vqc<V, H::Digest>,
    parent_history: H::Digest,
    base: &[BlockRef<H::Digest>],
    config: CodecConfig,
) -> Result<ValidVqc<H::Digest>, Error> {
    ensure_vector(base, config)?;
    let ancestry = vqc_ancestry::<H, V>(vqc)?;
    for path in ancestry.paths() {
        let chain = path.from().chain();
        let base = base.get(chain.index()).ok_or(Error::ChainOrder)?;
        if path.from().height() != base.height() {
            return Err(Error::PathHeight(chain));
        }
    }

    let contents = vqc.contents();
    if contents.len() != config.view_quorum() {
        return Err(Error::Quorum);
    }
    // The distinct recorded tips above the base, chain by chain: chain `i`'s are
    // `recorded[offsets[i]..offsets[i + 1]]`. Votes mostly agree, so each chain holds few.
    let mut recorded = Vec::new();
    let mut offsets = Vec::with_capacity(base.len() + 1);
    offsets.push(0);
    for (index, base) in base.iter().enumerate() {
        let start = recorded.len();
        for (_, content) in &contents {
            let Some(tip) = content.tips().get(index) else {
                continue;
            };
            if tip.height() <= base.height() || recorded[start..].contains(tip) {
                continue;
            }
            if !ancestry.contains(tip) {
                return Err(Error::Unresolved(tip.chain()));
            }
            recorded.push(*tip);
        }
        offsets.push(recorded.len());
    }
    for path in ancestry.paths() {
        let top = path.top();
        let chain = top.chain().index();
        if !recorded[offsets[chain]..offsets[chain + 1]].contains(&top) {
            return Err(Error::UnusedPath(top.chain()));
        }
        if ancestry.holders(&top) > 1 {
            return Err(Error::RedundantPath(top.chain()));
        }
    }

    let designated = designated(contents.iter().map(|(_, content)| content.leader()), config);
    if let Some(leader) = designated {
        let expected = LeaderBlock::new(vqc.round(), vqc.parent(), parent_history)?;
        if leader != expected.digest::<H>() {
            return Err(Error::Designation);
        }
    }

    let tips = tips(base, &contents, config, &ancestry)?;
    let record = HistoryRecord::new(parent_history, tips)?;
    Ok(ValidVqc {
        contents,
        designated,
        commitment: record.commitment::<H>(),
        record,
        ancestry,
    })
}

/// Returns the leader-block digest that at least `n - 3f` of the final votes of a V-QC, given by
/// their `leaders`, are for, if any.
///
/// Two such digests would need `2(n - 3f)` votes, more than the `n - f` a V-QC holds, so at most
/// one exists.
pub(crate) fn designated<D: Digest>(
    leaders: impl IntoIterator<Item = Option<D>>,
    config: CodecConfig,
) -> Option<D> {
    let mut counts = BTreeMap::<D, usize>::new();
    for leader in leaders.into_iter().flatten() {
        *counts.entry(leader).or_default() += 1;
    }
    counts
        .into_iter()
        .find(|(_, count)| *count >= config.designation_quorum())
        .map(|(leader, _)| leader)
}

/// Checks the finalization certificate `(lqc, opening)` for `epoch` and returns its resume index,
/// the number of producer blocks every correct log holds once it contains the opened tips.
///
/// The certificate is well formed when the leader block belongs to `epoch` (its view is live by
/// construction), the tally holds exactly `n - f` signers, and `opening` (one tip per chain, in
/// chain order) hashes to the leader block's history commitment. The aggregate signature is not
/// checked here.
pub(crate) fn validate_floor<H: Hasher, V: Variant>(
    lqc: &Lqc<V, H::Digest>,
    opening: &HistoryRecord<H::Digest>,
    epoch: Epoch,
    config: CodecConfig,
) -> Result<u64, Error> {
    let leader = lqc.leader();
    if leader.epoch() != epoch {
        return Err(Error::Epoch);
    }
    let signers = lqc.tally().signers();
    if signers.len() != config.participants() || signers.count() != config.view_quorum() {
        return Err(Error::Quorum);
    }
    ensure_vector(opening.tips(), config)?;
    if opening.commitment::<H>() != leader.history() {
        return Err(Error::History);
    }
    opening.output_index().ok_or(Error::IndexOverflow)
}
