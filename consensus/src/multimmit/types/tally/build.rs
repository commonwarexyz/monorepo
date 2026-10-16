//! Building canonical tallies from vote contents, checking decoded tallies, and expanding them.

use super::{Core, Deviation, Entry, FinalTally, Kind, ResolutionPath, VoteTally};
use crate::{
    multimmit::types::{CodecConfig, Error, VoteContent},
    types::{Participant, Round},
};
use commonware_cryptography::{Digest, certificate::Signers};
use std::collections::{BTreeMap, HashMap};

impl<D: Digest> VoteTally<D> {
    /// Builds the canonical tally of exactly `n - f` votes for the leader block with digest
    /// `leader`, all in one round.
    pub fn from_contents(
        leader: D,
        contents: impl IntoIterator<Item = (Participant, VoteContent<D>)>,
        config: CodecConfig,
    ) -> Result<Self, Error> {
        let entries = entries(contents, |content| {
            (content.leader() == Some(leader)).then(|| Entry {
                leader: None,
                final_: content.is_final(),
                endorsement: content.endorsement().clone(),
            })
        })?;
        Core::from_entries(Kind::Vote, entries, config).map(Self)
    }
}

impl<D: Digest> FinalTally<D> {
    /// Builds the canonical tally of exactly `n - f` final votes of one round, with resolution
    /// `paths` for the tips above the base.
    pub fn from_contents(
        contents: impl IntoIterator<Item = (Participant, VoteContent<D>)>,
        mut paths: Vec<ResolutionPath<D>>,
        config: CodecConfig,
    ) -> Result<Self, Error> {
        let entries = entries(contents, |content| {
            content.is_final().then(|| Entry {
                leader: content.leader(),
                final_: true,
                endorsement: content.endorsement().clone(),
            })
        })?;
        paths.sort();
        paths.dedup();
        let tally = Self {
            core: Core::from_entries(Kind::Final, entries, config)?,
            paths,
        };
        tally.validate_paths(config)?;
        Ok(tally)
    }
}

/// Converts contents of one round to tally entries, rejecting any content `entry` refuses.
fn entries<D: Digest>(
    contents: impl IntoIterator<Item = (Participant, VoteContent<D>)>,
    entry: impl Fn(&VoteContent<D>) -> Option<Entry<D>>,
) -> Result<Vec<(Participant, Entry<D>)>, Error> {
    let mut round: Option<Round> = None;
    contents
        .into_iter()
        .map(|(signer, content)| {
            if *round.get_or_insert(content.round()) != content.round() {
                return Err(Error::Context);
            }
            Ok((signer, entry(&content).ok_or(Error::Transcript)?))
        })
        .collect()
}

impl<D: Digest> Core<D> {
    fn from_entries(
        kind: Kind,
        mut entries: Vec<(Participant, Entry<D>)>,
        config: CodecConfig,
    ) -> Result<Self, Error> {
        entries.sort_by_key(|(signer, _)| *signer);
        if entries.len() != config.view_quorum() {
            return Err(Error::Quorum);
        }
        let signers = Signers::new(
            u32::try_from(config.participants()).map_err(|_| Error::Participants)?,
            entries.iter().map(|(signer, _)| *signer),
        )
        .map_err(|_| Error::Participants)?;
        let reference_signer = canonical_reference(&entries);
        let reference = entries
            .iter()
            .find(|(signer, _)| *signer == reference_signer)
            .map(|(_, entry)| entry.clone())
            .expect("the reference signer is a signer");
        let deviations = entries
            .iter()
            .filter_map(|(signer, entry)| deviation(kind, *signer, &reference, entry))
            .collect();
        Ok(Self {
            signers,
            reference_signer,
            reference,
            deviations,
        })
    }

    /// Checks that a decoded core is the canonical transcript of exactly `n - f` entries.
    pub(super) fn validate(&self, kind: Kind, config: CodecConfig) -> Result<(), Error> {
        if self.signers.len() != config.participants()
            || self.signers.count() != config.view_quorum()
        {
            return Err(Error::Quorum);
        }
        if !self
            .signers
            .iter()
            .any(|signer| signer == self.reference_signer)
        {
            return Err(Error::Participants);
        }
        if self
            .deviations
            .windows(2)
            .any(|pair| pair[0].signer >= pair[1].signer)
        {
            return Err(Error::Transcript);
        }
        for deviation in &self.deviations {
            let canonical = deviation.signer != self.reference_signer
                && self.signers.iter().any(|signer| signer == deviation.signer)
                && match kind {
                    Kind::Vote => deviation.leader.is_none(),
                    Kind::Final => !deviation.flip_final,
                }
                && deviation.leader != Some(self.reference.leader)
                && deviation
                    .declared
                    .as_ref()
                    .is_none_or(|declared| !declared.is_empty())
                && deviation
                    .tips
                    .windows(2)
                    .all(|pair| pair[0].chain() < pair[1].chain())
                && deviation.tips.iter().all(|tip| {
                    self.reference
                        .endorsement
                        .tip(tip.chain())
                        .is_some_and(|reference| reference != tip)
                })
                && (deviation.leader.is_some()
                    || deviation.flip_final
                    || deviation.declared.is_some()
                    || !deviation.tips.is_empty());
            if !canonical {
                return Err(Error::Transcript);
            }
            if deviation
                .declared
                .as_ref()
                .is_some_and(|declared| declared.chains() != config.chains())
            {
                return Err(Error::Declared);
            }
        }
        // Canonical deviations describe equal entries exactly when their bodies are equal, and
        // none describes the reference entry. So the reference is the lowest signer without a
        // deviation, and no group of equal deviations may outnumber its holders, or tie with
        // them from a lower signer.
        let mut deviations = self.deviations.iter().peekable();
        let lowest_holder = self
            .signers
            .iter()
            .find(|signer| deviations.next_if(|d| d.signer == *signer).is_none());
        if lowest_holder != Some(self.reference_signer) {
            return Err(Error::Transcript);
        }
        let holders = config.view_quorum() - self.deviations.len();
        let mut groups = HashMap::<_, (usize, Participant)>::new();
        for deviation in &self.deviations {
            let body = (
                &deviation.leader,
                deviation.flip_final,
                &deviation.declared,
                deviation.tips.as_slice(),
            );
            groups.entry(body).or_insert((0, deviation.signer)).0 += 1;
        }
        if groups.values().any(|(count, lowest)| {
            *count > holders || (*count == holders && *lowest < self.reference_signer)
        }) {
            return Err(Error::Transcript);
        }
        Ok(())
    }

    /// Rebuilds every signer's entry, in signer order.
    pub(super) fn entries(&self) -> Vec<(Participant, Entry<D>)> {
        let mut deviations = self.deviations.iter().peekable();
        self.signers
            .iter()
            .map(|signer| {
                let entry = deviations
                    .next_if(|deviation| deviation.signer == signer)
                    .map_or_else(
                        || self.reference.clone(),
                        |deviation| apply(&self.reference, deviation),
                    );
                (signer, entry)
            })
            .collect()
    }

    /// Rebuilds every signer's content in `round`, with `leader` overriding the entries' leader.
    pub(super) fn contents(
        &self,
        round: Round,
        leader: Option<D>,
    ) -> Vec<(Participant, VoteContent<D>)> {
        self.entries()
            .into_iter()
            .map(|(signer, entry)| {
                let content = VoteContent::new(
                    round,
                    leader.or(entry.leader),
                    entry.final_,
                    entry.endorsement,
                )
                .expect("a certificate's round is a live view");
                (signer, content)
            })
            .collect()
    }
}

/// Returns the lowest signer whose entry occurs most often.
fn canonical_reference<D: Digest>(entries: &[(Participant, Entry<D>)]) -> Participant {
    let mut counts = BTreeMap::<&Entry<D>, usize>::new();
    for (_, entry) in entries {
        *counts.entry(entry).or_default() += 1;
    }
    let most = counts.values().copied().max().unwrap_or_default();
    entries
        .iter()
        .find(|(_, entry)| counts[entry] == most)
        .map(|(signer, _)| *signer)
        .expect("a tally holds at least one entry")
}

/// Returns how `entry` differs from `reference`, or `None` when they are equal.
fn deviation<D: Digest>(
    kind: Kind,
    signer: Participant,
    reference: &Entry<D>,
    entry: &Entry<D>,
) -> Option<Deviation<D>> {
    if entry == reference {
        return None;
    }
    let declared = reference
        .endorsement
        .declared()
        .symmetric_difference(entry.endorsement.declared())
        .filter(|difference| !difference.is_empty());
    let tips = entry
        .endorsement
        .tips()
        .iter()
        .zip(reference.endorsement.tips())
        .filter(|(tip, reference)| tip != reference)
        .map(|(tip, _)| *tip)
        .collect();
    Some(Deviation {
        signer,
        leader: (kind == Kind::Final && entry.leader != reference.leader).then_some(entry.leader),
        flip_final: kind == Kind::Vote && entry.final_ != reference.final_,
        declared,
        tips,
    })
}

/// Applies `deviation` to `reference`.
fn apply<D: Digest>(reference: &Entry<D>, deviation: &Deviation<D>) -> Entry<D> {
    let mut endorsement = reference
        .endorsement
        .with_tips(deviation.tips.iter().copied());
    if let Some(difference) = &deviation.declared {
        let declared = reference
            .endorsement
            .declared()
            .symmetric_difference(difference)
            .expect("validated declared sets range over the epoch's chains");
        endorsement = endorsement.with_declared(declared);
    }
    Entry {
        leader: deviation.leader.unwrap_or(reference.leader),
        final_: reference.final_ != deviation.flip_final,
        endorsement,
    }
}
