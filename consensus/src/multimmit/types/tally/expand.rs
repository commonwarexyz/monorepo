//! Reconstructing each signer's vote from a tally and checking that a tally is canonical.

use super::{Deviation, Tally, compress::canonical_reference};
use crate::multimmit::types::{
    CodecConfig, DigestedLeader, Error, Extension, LeaderBlock, Position, VoteBody,
    vote::paths_valid_for,
};
use commonware_cryptography::{Digest, bls12381::primitives::variant::Variant};
use commonware_utils::Participant;

/// One signer's positions and extensions reconstructed from a tally.
struct Paths<D: Digest> {
    positions: Vec<Position>,
    extensions: Vec<Extension<D>>,
}

impl<D: Digest> Tally<D> {
    /// Expands one signer's vote body for `leader`.
    pub fn vote<V: Variant>(
        &self,
        leader: DigestedLeader<'_, V, D>,
        signer: Participant,
        config: CodecConfig,
    ) -> Result<VoteBody<D>, Error> {
        let block = leader.block();
        if block.proposals().len() != config.chains()
            || self.reference_extensions.len() != config.chains()
            || self.signers.len() != config.participants()
        {
            return Err(Error::Context);
        }
        if !self.signers.iter().any(|candidate| candidate == signer) {
            return Err(Error::Participants);
        }
        let paths = self.expand(block, signer, config)?;
        VoteBody::for_leader(leader, paths.positions, paths.extensions, config)
    }

    /// Applies `signer`'s deviation, if any, to the proposal tips and reference extensions.
    fn expand<V: Variant>(
        &self,
        leader: &LeaderBlock<V, D>,
        signer: Participant,
        config: CodecConfig,
    ) -> Result<Paths<D>, Error> {
        let mut positions = leader
            .proposals()
            .iter()
            .map(|proposal| Position::new(proposal.payloads().len() as u32))
            .collect::<Vec<_>>();
        let mut extensions = self.reference_extensions.clone();
        if let Ok(index) = self
            .deviations
            .binary_search_by_key(&signer, Deviation::signer)
        {
            let deviation = &self.deviations[index];
            for position in &deviation.positions {
                let Some(current) = positions.get_mut(position.chain.get() as usize) else {
                    return Err(Error::Transcript);
                };
                *current = position.position;
            }
            for replacement in &deviation.extensions {
                let Some(current) = extensions.get_mut(replacement.chain.get() as usize) else {
                    return Err(Error::Transcript);
                };
                *current = Extension::new(
                    self.extension(replacement.extension)?.to_vec(),
                    config.extension_bound(),
                )?;
            }
        }
        Ok(Paths {
            positions,
            extensions,
        })
    }

    /// Checks that this tally is the canonical transcript of valid votes for `leader`.
    pub(crate) fn validate<V: Variant>(
        &self,
        leader: &LeaderBlock<V, D>,
        config: CodecConfig,
    ) -> Result<(), Error> {
        if self.reference_extensions.len() != config.chains()
            || self
                .reference_extensions
                .iter()
                .any(|extension| extension.len() > config.extension_bound())
            || self.signers.len() != config.participants()
            || self.signers.count() == 0
        {
            return Err(Error::Transcript);
        }
        if self
            .deviations
            .windows(2)
            .any(|pair| pair[0].signer >= pair[1].signer)
        {
            return Err(Error::Transcript);
        }

        if self
            .extension_paths
            .iter()
            .any(|path| path.is_empty() || path.len() > config.extension_bound())
            || self
                .extension_paths
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
        {
            return Err(Error::Transcript);
        }
        let mut used = vec![false; self.extension_paths.len()];
        for deviation in &self.deviations {
            if !self.signers.iter().any(|signer| signer == deviation.signer)
                || deviation.positions.is_empty() && deviation.extensions.is_empty()
                || deviation
                    .positions
                    .windows(2)
                    .any(|pair| pair[0].chain >= pair[1].chain)
                || deviation
                    .extensions
                    .windows(2)
                    .any(|pair| pair[0].chain >= pair[1].chain)
            {
                return Err(Error::Transcript);
            }
            for position in &deviation.positions {
                let Some(proposal) = leader.proposals().get(position.chain.get() as usize) else {
                    return Err(Error::Transcript);
                };
                if position.position.get() >= proposal.payloads().len() as u32 {
                    return Err(Error::Transcript);
                }
            }
            for replacement in &deviation.extensions {
                let Some(reference) = self
                    .reference_extensions
                    .get(replacement.chain.get() as usize)
                else {
                    return Err(Error::Transcript);
                };
                let path = self.extension(replacement.extension)?;
                if path == reference.payloads() {
                    return Err(Error::Transcript);
                }
                if let Some(index) = replacement.extension {
                    used[index.get() - 1] = true;
                }
            }
        }
        if used.iter().any(|used| !used) {
            return Err(Error::Transcript);
        }

        let expanded = self
            .signers
            .iter()
            .map(|signer| self.expand(leader, signer, config))
            .collect::<Result<Vec<_>, _>>()?;
        if expanded
            .iter()
            .any(|paths| !paths_valid_for(leader, &paths.positions, &paths.extensions))
        {
            return Err(Error::Transcript);
        }
        if canonical_reference(
            leader,
            expanded
                .iter()
                .map(|paths| (paths.positions.as_slice(), paths.extensions.as_slice())),
        ) != self.reference_extensions
        {
            return Err(Error::Transcript);
        }
        Ok(())
    }
}
