//! Authenticated safe-tip history.

use super::{BlockRef, ChainId, EpochGenesis, Error};
use crate::types::Height;
use bytes::{Buf, BufMut};
use commonware_codec::{Encode, EncodeSize, Error as CodecError, RangeCfg, Read, ReadExt, Write};
use commonware_cryptography::{Digest, Hasher};

const TIP_HISTORY_NAMESPACE: &[u8] = b"_COMMONWARE_CONSENSUS_MULTIMMIT_TIP_HISTORY_V2";

/// One compact commitment link for safe-to-extend producer tips.
///
/// A leader block commits to the record derived from its parent V-QC. Validators reconstruct that
/// record while validating and extending the parent; certificates carry only the commitment.
///
/// Besides the safe tips, a record carries the tip height each chain's proposal reached in the
/// view that produced it. The ordering sweep places the blocks at or below that height, which the
/// proposal pins, before any block above it, which only vote extensions endorse. Both vectors are
/// committed because peers serve history records during catch-up.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TipRecord<D: Digest> {
    parent: D,
    tips: Vec<BlockRef<D>>,
    proposed: Vec<Height>,
}

impl<D: Digest> TipRecord<D> {
    /// Creates a history record extending `parent` with one safe tip and one proposed tip height
    /// per producer chain.
    pub fn new(parent: D, tips: Vec<BlockRef<D>>, proposed: Vec<Height>) -> Result<Self, Error> {
        if tips.is_empty()
            || tips.len() != proposed.len()
            || tips
                .iter()
                .enumerate()
                .any(|(index, tip)| u32::try_from(index).map(ChainId::new) != Ok(tip.chain()))
        {
            return Err(Error::Chain);
        }
        Ok(Self {
            parent,
            tips,
            proposed,
        })
    }

    /// Creates a record whose proposed tips are the safe tips themselves.
    ///
    /// This is the genesis record, and the record of any view whose proposal added nothing above
    /// the tips its V-QC carried.
    pub fn at_tips(parent: D, tips: Vec<BlockRef<D>>) -> Result<Self, Error> {
        let proposed = tips.iter().map(|tip| tip.height()).collect();
        Self::new(parent, tips, proposed)
    }

    /// Returns the preceding history commitment.
    pub const fn parent(&self) -> D {
        self.parent
    }

    /// Returns the safe tips contributed by this history link.
    pub fn tips(&self) -> &[BlockRef<D>] {
        &self.tips
    }

    /// Returns the proposed tip height per chain in the view that produced this link.
    pub fn proposed(&self) -> &[Height] {
        &self.proposed
    }

    /// Returns `H(namespace, parent, canonical_tips, proposed_heights)`, the child leader's
    /// history commitment.
    pub fn commitment<H: Hasher<Digest = D>>(&self) -> D {
        let tips = self.tips.encode();
        let proposed = self.proposed.encode();
        H::hash(&[
            TIP_HISTORY_NAMESPACE,
            self.parent.as_ref(),
            tips.as_ref(),
            proposed.as_ref(),
        ])
    }
}

impl<D: Digest> Write for TipRecord<D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.parent.write(buf);
        self.tips.write(buf);
        self.proposed.write(buf);
    }
}

impl<D: Digest> EncodeSize for TipRecord<D> {
    fn encode_size(&self) -> usize {
        self.parent.encode_size() + self.tips.encode_size() + self.proposed.encode_size()
    }
}

impl<D: Digest> Read for TipRecord<D> {
    type Cfg = usize;

    fn read_cfg(buf: &mut impl Buf, chains: &Self::Cfg) -> Result<Self, CodecError> {
        let parent = D::read(buf)?;
        let tips = Vec::<BlockRef<D>>::read_cfg(buf, &(RangeCfg::exact(*chains), ()))?;
        let proposed = Vec::<Height>::read_cfg(buf, &(RangeCfg::exact(*chains), ()))?;
        Self::new(parent, tips, proposed)
            .map_err(|_| CodecError::Invalid("TipRecord", "invalid canonical tips"))
    }
}

/// Returns the deterministic commitment preceding the epoch's first tip record.
pub fn genesis_history<H: Hasher>(genesis: &EpochGenesis<H::Digest>) -> H::Digest {
    H::hash(&[genesis.encode().as_ref()])
}

/// Returns the commitment after incorporating the synthetic genesis tips.
#[cfg(any(test, feature = "mocks"))]
pub(crate) fn genesis_tip_commitment<H: Hasher>(genesis: &EpochGenesis<H::Digest>) -> H::Digest {
    TipRecord::at_tips(genesis_history::<H>(genesis), genesis.tips().to_vec())
        .expect("genesis tips are canonical")
        .commitment::<H>()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::multimmit::types::Height;
    use commonware_cryptography::Sha256;

    #[test]
    fn commitment_is_domain_separated() {
        let parent = Sha256::hash(&[b"parent"]);
        let tips = vec![
            BlockRef::new(
                ChainId::new(0),
                Height::new(11),
                Sha256::hash(&[b"chain 0 tip"]),
            ),
            BlockRef::new(
                ChainId::new(1),
                Height::new(17),
                Sha256::hash(&[b"chain 1 tip"]),
            ),
        ];
        let proposed = vec![Height::new(12), Height::new(17)];
        let encoded_tips = tips.encode();
        let encoded_proposed = proposed.encode();
        let expected = Sha256::hash(&[
            TIP_HISTORY_NAMESPACE,
            parent.as_ref(),
            encoded_tips.as_ref(),
            encoded_proposed.as_ref(),
        ]);
        let legacy = Sha256::hash(&[parent.as_ref(), encoded_tips.as_ref()]);
        let record = TipRecord::new(parent, tips.clone(), proposed).unwrap();
        assert_ne!(
            record.commitment::<Sha256>(),
            TipRecord::at_tips(parent, tips).unwrap().commitment::<Sha256>()
        );

        assert_eq!(record.commitment::<Sha256>(), expected);
        assert_ne!(record.commitment::<Sha256>(), legacy);
    }
}
