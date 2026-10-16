//! Signed vote contents and the vote updates that carry them.
//!
//! A [`VoteContent`] is the statement a validator signs: per producer chain, the tip of the path
//! it endorses, plus the set of chains it declares final and whether it votes for a leader block
//! or closes the view. A validator's content grows during a view, so it sends [`VoteUpdate`]s
//! naming only the chains whose tips changed since one of its two previous updates; a reader
//! rebuilds the full content before checking the signature.

use super::{
    Attestation, BlockRef, ChainId, ChainSet, Error,
    bounds::{MAX_U64_VARINT_SIZE, block_ref_size, checked_sum, encoded_vec, max_index_width},
    ensure_canonical_chains,
};
use crate::{
    Epochable, Viewable,
    multimmit::types::CodecConfig,
    types::{Attributable, Epoch, Participant, Round, View},
};
use bytes::BufMut;
use commonware_codec::{
    Buf, EncodeSize, Error as CodecError, FixedSize as _, RangeCfg, Read, ReadExt, Write,
    varint::UInt,
};
use commonware_cryptography::{Digest, bls12381::primitives::variant::Variant};
use std::sync::Arc;

/// What a vote endorses: the tip of the endorsed path on every producer chain, and the chains the
/// voter declares final for the view.
///
/// A vote endorses a block when the block is its tip on that chain or an ancestor of it. Tips at
/// height zero name the chain's genesis object.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Endorsement<D: Digest> {
    declared: ChainSet,
    tips: Arc<[BlockRef<D>]>,
}

impl<D: Digest> Endorsement<D> {
    /// Creates an endorsement with one tip per chain of `config`, in chain order.
    pub fn new(
        declared: ChainSet,
        tips: impl Into<Arc<[BlockRef<D>]>>,
        config: CodecConfig,
    ) -> Result<Self, Error> {
        let endorsement = Self {
            declared,
            tips: tips.into(),
        };
        endorsement.validate(config)?;
        Ok(endorsement)
    }

    fn validate(&self, config: CodecConfig) -> Result<(), Error> {
        if self.declared.chains() != config.chains() {
            return Err(Error::Declared);
        }
        if self.tips.len() != config.chains() {
            return Err(Error::ChainCount);
        }
        ensure_canonical_chains(self.tips.iter().map(BlockRef::chain)).map_err(|_| Error::Chain)
    }

    /// Returns the chains declared final.
    pub const fn declared(&self) -> &ChainSet {
        &self.declared
    }

    /// Returns the endorsed tip of every chain, in chain order.
    pub fn tips(&self) -> &[BlockRef<D>] {
        &self.tips
    }

    /// Returns the endorsed tip of `chain`.
    pub fn tip(&self, chain: ChainId) -> Option<&BlockRef<D>> {
        self.tips.get(chain.index())
    }

    /// Returns a copy with the tips of the chains named in `changes` replaced.
    pub(crate) fn with_tips(&self, changes: impl IntoIterator<Item = BlockRef<D>>) -> Self {
        let mut tips = self.tips.to_vec();
        for tip in changes {
            tips[tip.chain().index()] = tip;
        }
        Self {
            declared: self.declared.clone(),
            tips: tips.into(),
        }
    }

    /// Returns a copy with `declared` replaced.
    pub(crate) fn with_declared(&self, declared: ChainSet) -> Self {
        Self {
            declared,
            tips: self.tips.clone(),
        }
    }

    pub(super) fn max_encode_size(codec: CodecConfig) -> Option<usize> {
        checked_sum(&[
            ChainSet::encoded_size(codec.chains()),
            encoded_vec(codec.chains(), block_ref_size::<D>(codec)?)?,
        ])
    }
}

impl<D: Digest> Write for Endorsement<D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.declared.write(buf);
        self.tips.as_ref().write(buf);
    }
}

impl<D: Digest> EncodeSize for Endorsement<D> {
    fn encode_size(&self) -> usize {
        self.declared.encode_size() + self.tips.as_ref().encode_size()
    }
}

impl<D: Digest> Read for Endorsement<D> {
    type Cfg = CodecConfig;

    fn read_cfg(buf: &mut impl Buf, config: &Self::Cfg) -> Result<Self, CodecError> {
        let declared = ChainSet::read_cfg(buf, &config.chains())?;
        let tips = Vec::<BlockRef<D>>::read_cfg(buf, &(RangeCfg::exact(config.chains()), ()))?;
        Self::new(declared, tips, *config)
            .map_err(|error| CodecError::Wrapped("Endorsement", error.into()))
    }
}

/// The statement one validator signs in a view.
///
/// A vote for a leader block carries its digest; a vote without one is a pre-vote, or, when final,
/// a leaderless final message. A final vote is the voter's last statement for the view, the kind a
/// V-QC is formed from.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct VoteContent<D: Digest> {
    round: Round,
    leader: Option<D>,
    final_: bool,
    endorsement: Endorsement<D>,
}

impl<D: Digest> VoteContent<D> {
    /// Creates the content of a vote tagged with `round`'s view.
    pub fn new(
        round: Round,
        leader: Option<D>,
        final_: bool,
        endorsement: Endorsement<D>,
    ) -> Result<Self, Error> {
        if round.view().is_zero() {
            return Err(Error::GenesisView);
        }
        Ok(Self {
            round,
            leader,
            final_,
            endorsement,
        })
    }

    /// Returns the round whose view tags the vote.
    pub const fn round(&self) -> Round {
        self.round
    }

    /// Returns the voted-for leader-block digest, if any.
    pub const fn leader(&self) -> Option<D> {
        self.leader
    }

    /// Returns whether this is the voter's final statement for the view.
    pub const fn is_final(&self) -> bool {
        self.final_
    }

    /// Returns the endorsed tips and declared chains.
    pub const fn endorsement(&self) -> &Endorsement<D> {
        &self.endorsement
    }

    /// Returns the chains declared final.
    pub const fn declared(&self) -> &ChainSet {
        self.endorsement.declared()
    }

    /// Returns the endorsed tip of every chain, in chain order.
    pub fn tips(&self) -> &[BlockRef<D>] {
        self.endorsement.tips()
    }
}

impl<D: Digest> Epochable for VoteContent<D> {
    fn epoch(&self) -> Epoch {
        self.round.epoch()
    }
}

impl<D: Digest> Viewable for VoteContent<D> {
    fn view(&self) -> View {
        self.round.view()
    }
}

impl<D: Digest> Write for VoteContent<D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.round.write(buf);
        self.leader.write(buf);
        self.final_.write(buf);
        self.endorsement.write(buf);
    }
}

impl<D: Digest> EncodeSize for VoteContent<D> {
    fn encode_size(&self) -> usize {
        self.round.encode_size()
            + self.leader.encode_size()
            + self.final_.encode_size()
            + self.endorsement.encode_size()
    }
}

impl<D: Digest> Read for VoteContent<D> {
    type Cfg = CodecConfig;

    fn read_cfg(buf: &mut impl Buf, config: &Self::Cfg) -> Result<Self, CodecError> {
        let round = Round::read(buf)?;
        let leader = Option::<D>::read(buf)?;
        let final_ = bool::read(buf)?;
        let endorsement = Endorsement::read_cfg(buf, config)?;
        Self::new(round, leader, final_, endorsement)
            .map_err(|error| CodecError::Wrapped("VoteContent", error.into()))
    }
}

/// One chain's changed tip in a vote update, with payload hashes of the path ending at it.
///
/// `payloads` lists the body digests of the last `m` blocks ending at `tip`, lowest first, so a
/// reader holding the header `m` below the tip rebuilds every header in between.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ChainChange<D: Digest> {
    tip: BlockRef<D>,
    payloads: Vec<D>,
}

impl<D: Digest> ChainChange<D> {
    /// Creates a change carrying at most `delta_max` payload hashes, none below height one.
    pub fn new(tip: BlockRef<D>, payloads: Vec<D>, config: CodecConfig) -> Result<Self, Error> {
        let change = Self { tip, payloads };
        change.validate(config)?;
        Ok(change)
    }

    const fn validate(&self, config: CodecConfig) -> Result<(), Error> {
        if self.tip.chain().index() >= config.chains() {
            return Err(Error::Chain);
        }
        if self.payloads.len() > config.window().delta_max() as usize
            || self.payloads.len() as u64 > self.tip.height().get()
        {
            return Err(Error::Window);
        }
        Ok(())
    }

    /// Returns the changed chain.
    pub const fn chain(&self) -> ChainId {
        self.tip.chain()
    }

    /// Returns the new endorsed tip.
    pub const fn tip(&self) -> BlockRef<D> {
        self.tip
    }

    /// Returns the body digests of the blocks ending at the tip, lowest first.
    pub fn payloads(&self) -> &[D] {
        &self.payloads
    }

    fn max_encode_size(codec: CodecConfig) -> Option<usize> {
        checked_sum(&[
            block_ref_size::<D>(codec)?,
            encoded_vec(codec.window().delta_max() as usize, D::SIZE)?,
        ])
    }
}

impl<D: Digest> Write for ChainChange<D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.tip.write(buf);
        self.payloads.write(buf);
    }
}

impl<D: Digest> EncodeSize for ChainChange<D> {
    fn encode_size(&self) -> usize {
        self.tip.encode_size() + self.payloads.encode_size()
    }
}

impl<D: Digest> Read for ChainChange<D> {
    type Cfg = CodecConfig;

    fn read_cfg(buf: &mut impl Buf, config: &Self::Cfg) -> Result<Self, CodecError> {
        let tip = BlockRef::read(buf)?;
        let bound = RangeCfg::from(0..=config.window().delta_max() as usize);
        let payloads = Vec::<D>::read_cfg(buf, &(bound, ()))?;
        Self::new(tip, payloads, *config)
            .map_err(|error| CodecError::Wrapped("ChainChange", error.into()))
    }
}

/// The message a validator sends for its current vote: the vote's leader, finality flag, and
/// declared chains, the tips of the chains that changed, and the signature over the full
/// [`VoteContent`].
///
/// `seq` numbers a validator's updates for one view from one. It is not signed: a reader uses it
/// only to rebuild the omitted tips from the updates `seq - 1` or `seq - 2`, and the rebuilt
/// content's signature check rejects a wrong reconstruction.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct VoteUpdate<V: Variant, D: Digest> {
    round: Round,
    leader: Option<D>,
    final_: bool,
    declared: ChainSet,
    seq: u32,
    changes: Vec<ChainChange<D>>,
    attestation: Attestation<V>,
}

impl<V: Variant, D: Digest> VoteUpdate<V, D> {
    /// Creates an unverified update. `changes` must name distinct chains in ascending order.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        round: Round,
        leader: Option<D>,
        final_: bool,
        declared: ChainSet,
        seq: u32,
        changes: Vec<ChainChange<D>>,
        attestation: Attestation<V>,
        config: CodecConfig,
    ) -> Result<Self, Error> {
        let update = Self {
            round,
            leader,
            final_,
            declared,
            seq,
            changes,
            attestation,
        };
        update.validate(config)?;
        Ok(update)
    }

    fn validate(&self, config: CodecConfig) -> Result<(), Error> {
        if self.round.view().is_zero() {
            return Err(Error::GenesisView);
        }
        if self.seq == 0 {
            return Err(Error::Sequence);
        }
        if self.declared.chains() != config.chains() {
            return Err(Error::Declared);
        }
        if self
            .changes
            .windows(2)
            .any(|pair| pair[0].chain() >= pair[1].chain())
        {
            return Err(Error::Chain);
        }
        self.changes
            .iter()
            .try_for_each(|change| change.validate(config))
    }

    /// Returns the round whose view tags the vote.
    pub const fn round(&self) -> Round {
        self.round
    }

    /// Returns the voted-for leader-block digest, if any.
    pub const fn leader(&self) -> Option<D> {
        self.leader
    }

    /// Returns whether the vote is final.
    pub const fn is_final(&self) -> bool {
        self.final_
    }

    /// Returns the chains declared final.
    pub const fn declared(&self) -> &ChainSet {
        &self.declared
    }

    /// Returns the update's sequence number within the sender's updates for the view.
    pub const fn seq(&self) -> u32 {
        self.seq
    }

    /// Returns the changed chains in ascending order.
    pub fn changes(&self) -> &[ChainChange<D>] {
        &self.changes
    }

    /// Returns the sender's attestation over the full content.
    pub const fn attestation(&self) -> &Attestation<V> {
        &self.attestation
    }

    /// Rebuilds the signed content from `previous`, the tips the omitted chains keep.
    pub fn content(
        &self,
        previous: &[BlockRef<D>],
        config: CodecConfig,
    ) -> Result<VoteContent<D>, Error> {
        let mut tips = previous.to_vec();
        if tips.len() != config.chains() {
            return Err(Error::ChainCount);
        }
        for change in &self.changes {
            tips[change.chain().index()] = change.tip;
        }
        let endorsement = Endorsement::new(self.declared.clone(), tips, config)?;
        VoteContent::new(self.round, self.leader, self.final_, endorsement)
    }

    pub(super) fn max_encode_size(codec: CodecConfig) -> Option<usize> {
        checked_sum(&[
            2 * MAX_U64_VARINT_SIZE,
            1 + D::SIZE,
            1,
            ChainSet::encoded_size(codec.chains()),
            UInt(u32::MAX).encode_size(),
            encoded_vec(codec.chains(), ChainChange::<D>::max_encode_size(codec)?)?,
            max_index_width(codec.participants())?,
            V::Signature::SIZE,
        ])
    }
}

impl<V: Variant, D: Digest> Epochable for VoteUpdate<V, D> {
    fn epoch(&self) -> Epoch {
        self.round.epoch()
    }
}

impl<V: Variant, D: Digest> Viewable for VoteUpdate<V, D> {
    fn view(&self) -> View {
        self.round.view()
    }
}

impl<V: Variant, D: Digest> Attributable for VoteUpdate<V, D> {
    fn signer(&self) -> Participant {
        self.attestation.signer()
    }
}

impl<V: Variant, D: Digest> Write for VoteUpdate<V, D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.round.write(buf);
        self.leader.write(buf);
        self.final_.write(buf);
        self.declared.write(buf);
        UInt(self.seq).write(buf);
        self.changes.write(buf);
        self.attestation.write(buf);
    }
}

impl<V: Variant, D: Digest> EncodeSize for VoteUpdate<V, D> {
    fn encode_size(&self) -> usize {
        self.round.encode_size()
            + self.leader.encode_size()
            + self.final_.encode_size()
            + self.declared.encode_size()
            + UInt(self.seq).encode_size()
            + self.changes.encode_size()
            + self.attestation.encode_size()
    }
}

impl<V: Variant, D: Digest> Read for VoteUpdate<V, D> {
    type Cfg = CodecConfig;

    fn read_cfg(buf: &mut impl Buf, config: &Self::Cfg) -> Result<Self, CodecError> {
        let round = Round::read(buf)?;
        let leader = Option::<D>::read(buf)?;
        let final_ = bool::read(buf)?;
        let declared = ChainSet::read_cfg(buf, &config.chains())?;
        let seq: u32 = UInt::read(buf)?.into();
        let changes =
            Vec::<ChainChange<D>>::read_cfg(buf, &(RangeCfg::from(0..=config.chains()), *config))?;
        let attestation = Attestation::read(buf)?;
        Self::new(
            round,
            leader,
            final_,
            declared,
            seq,
            changes,
            attestation,
            *config,
        )
        .map_err(|error| CodecError::Wrapped("VoteUpdate", error.into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{multimmit::types::Window, types::Height};
    use commonware_codec::{Decode as _, Encode as _, types::lazy::Lazy};
    use commonware_cryptography::{
        Hasher as _, Sha256, bls12381::primitives::variant::MinSig, sha256::Digest as Sha256Digest,
    };
    use commonware_math::algebra::Additive as _;

    type D = Sha256Digest;

    fn config() -> CodecConfig {
        CodecConfig::new(6, 3, Window::with_bounds(2, 4, 2).unwrap()).unwrap()
    }

    fn tip(chain: u32, height: u64) -> BlockRef<D> {
        BlockRef::new(
            ChainId::new(chain),
            Height::new(height),
            Sha256::hash(&[&chain.to_be_bytes(), &height.to_be_bytes()]),
        )
    }

    fn endorsement(heights: [u64; 3]) -> Endorsement<D> {
        Endorsement::new(
            ChainSet::from_chains(3, [ChainId::new(1)]).unwrap(),
            (0..3)
                .map(|chain| tip(chain, heights[chain as usize]))
                .collect::<Vec<_>>(),
            config(),
        )
        .unwrap()
    }

    fn attestation() -> Attestation<MinSig> {
        let signature = <MinSig as Variant>::Signature::zero();
        Attestation::new(Participant::new(2), Lazy::from(signature))
    }

    #[test]
    fn content_round_trips_and_rejects_bad_shape() {
        let config = config();
        let round = Round::new(Epoch::new(3), View::new(5));
        for leader in [None, Some(Sha256::hash(&[b"leader"]))] {
            let content = VoteContent::new(round, leader, true, endorsement([0, 4, 9])).unwrap();
            let encoded = content.encode();
            assert_eq!(VoteContent::decode_cfg(encoded, &config).unwrap(), content);
        }

        assert_eq!(
            VoteContent::new(
                Round::new(Epoch::new(3), View::zero()),
                None,
                false,
                endorsement([0, 0, 0])
            )
            .unwrap_err(),
            Error::GenesisView
        );
        assert_eq!(
            Endorsement::new(ChainSet::empty(3), vec![tip(0, 1), tip(1, 1)], config).unwrap_err(),
            Error::ChainCount
        );
        assert_eq!(
            Endorsement::new(
                ChainSet::empty(3),
                vec![tip(1, 1), tip(0, 1), tip(2, 1)],
                config
            )
            .unwrap_err(),
            Error::Chain
        );
        assert_eq!(
            Endorsement::new(
                ChainSet::empty(4),
                vec![tip(0, 1), tip(1, 1), tip(2, 1)],
                config
            )
            .unwrap_err(),
            Error::Declared
        );
    }

    #[test]
    fn update_rebuilds_content_from_previous_tips() {
        let config = config();
        let round = Round::new(Epoch::new(3), View::new(5));
        let previous = endorsement([1, 1, 1]);
        let change = ChainChange::new(
            tip(2, 3),
            vec![Sha256::hash(&[b"p2"]), Sha256::hash(&[b"p3"])],
            config,
        )
        .unwrap();
        let update = VoteUpdate::new(
            round,
            None,
            false,
            previous.declared().clone(),
            4,
            vec![change],
            attestation(),
            config,
        )
        .unwrap();
        let content = update.content(previous.tips(), config).unwrap();
        assert_eq!(content.tips()[0], tip(0, 1));
        assert_eq!(content.tips()[2], tip(2, 3));
        assert_eq!(content.declared(), previous.declared());

        // The placeholder signature is not a valid point, so compare encodings.
        let encoded = update.encode();
        assert!(encoded.len() <= VoteUpdate::<MinSig, D>::max_encode_size(config).unwrap());
        assert_eq!(
            VoteUpdate::<MinSig, D>::decode_cfg(encoded.clone(), &config)
                .unwrap()
                .encode(),
            encoded
        );
    }

    #[test]
    fn update_rejects_adversarial_shapes() {
        let config = config();
        let round = Round::new(Epoch::new(3), View::new(5));
        let build = |seq, changes| {
            VoteUpdate::new(
                round,
                None,
                false,
                ChainSet::empty(3),
                seq,
                changes,
                attestation(),
                config,
            )
        };
        let change =
            |chain, height| ChainChange::new(tip(chain, height), Vec::new(), config).unwrap();

        assert_eq!(build(0, Vec::new()).unwrap_err(), Error::Sequence);
        assert_eq!(
            build(1, vec![change(1, 1), change(1, 2)]).unwrap_err(),
            Error::Chain
        );
        assert_eq!(
            build(1, vec![change(2, 1), change(1, 2)]).unwrap_err(),
            Error::Chain
        );
        assert_eq!(
            ChainChange::new(tip(3, 1), Vec::new(), config).unwrap_err(),
            Error::Chain
        );
        let three = vec![Sha256::hash(&[b"a"]); 3];
        assert_eq!(
            ChainChange::new(tip(0, 5), three, config).unwrap_err(),
            Error::Window
        );
        assert_eq!(
            ChainChange::new(tip(0, 1), vec![Sha256::hash(&[b"a"]); 2], config).unwrap_err(),
            Error::Window
        );

        // A decoder bounds the change count before allocating.
        let mut encoded = Vec::new();
        round.write(&mut encoded);
        Option::<D>::None.write(&mut encoded);
        false.write(&mut encoded);
        ChainSet::empty(3).write(&mut encoded);
        UInt(1u32).write(&mut encoded);
        UInt(4u32).write(&mut encoded);
        assert!(VoteUpdate::<MinSig, D>::decode_cfg(encoded, &config).is_err());
    }
}
