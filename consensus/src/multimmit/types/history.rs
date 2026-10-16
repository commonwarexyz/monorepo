//! The tips-history commitment chain that leader blocks and finalization certificates pin.

use super::{BlockRef, CodecConfig, Error, ensure_canonical_chains};
use crate::types::Epoch;
use bytes::BufMut;
use commonware_codec::{
    Buf, Encode, EncodeSize, Error as CodecError, RangeCfg, Read, ReadExt, Write,
};
use commonware_cryptography::{Digest, Hasher};

const TIP_HISTORY_NAMESPACE: &[u8] = b"_COMMONWARE_CONSENSUS_MULTIMMIT_TIP_HISTORY";
const GENESIS_HISTORY_NAMESPACE: &[u8] = b"_COMMONWARE_CONSENSUS_MULTIMMIT_GENESIS_HISTORY";

/// One link of the tips-history chain: the commitment of a V-QC's parent and the V-QC's tips.
///
/// For a V-QC `Q`, `C(Q) = H(TIP_HISTORY, C(parent(Q)), Tips(Q))`, and the genesis V-QC's
/// commitment is [`EpochGenesis::history`](super::EpochGenesis::history). A leader block carries
/// `C(Q')` for its parent `Q'`, so the record of `Q'` opens that commitment to the tips every
/// correct log contains once the leader block is finalized, and its `parent` links to the record of
/// the view before.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct HistoryRecord<D: Digest> {
    parent: D,
    tips: Vec<BlockRef<D>>,
}

impl<D: Digest> HistoryRecord<D> {
    /// Creates a record extending `parent` with one tip per producer chain, in chain order.
    pub fn new(parent: D, tips: Vec<BlockRef<D>>) -> Result<Self, Error> {
        if tips.is_empty() || ensure_canonical_chains(tips.iter().map(BlockRef::chain)).is_err() {
            return Err(Error::Chain);
        }
        Ok(Self { parent, tips })
    }

    /// Returns the commitment of the parent V-QC's chain.
    pub const fn parent(&self) -> D {
        self.parent
    }

    /// Returns the V-QC's tips in chain order.
    pub fn tips(&self) -> &[BlockRef<D>] {
        &self.tips
    }

    /// Returns `H(TIP_HISTORY, parent, tips)`, the commitment this record opens.
    pub fn commitment<H: Hasher<Digest = D>>(&self) -> D {
        H::hash(&[
            TIP_HISTORY_NAMESPACE,
            self.parent.as_ref(),
            self.tips.encode().as_ref(),
        ])
    }

    /// Returns the sum of the tips' heights: the number of producer blocks every correct log holds
    /// once it contains these tips.
    pub fn output_index(&self) -> Option<u64> {
        self.tips
            .iter()
            .try_fold(0u64, |sum, tip| sum.checked_add(tip.height().get()))
    }
}

/// Returns `H(GENESIS_HISTORY, epoch, tips)`, the commitment of the genesis V-QC.
pub(super) fn genesis_commitment<H: Hasher>(
    epoch: Epoch,
    tips: &[BlockRef<H::Digest>],
) -> H::Digest {
    H::hash(&[
        GENESIS_HISTORY_NAMESPACE,
        epoch.encode().as_ref(),
        tips.encode().as_ref(),
    ])
}

impl<D: Digest> Write for HistoryRecord<D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.parent.write(buf);
        self.tips.write(buf);
    }
}

impl<D: Digest> EncodeSize for HistoryRecord<D> {
    fn encode_size(&self) -> usize {
        self.parent.encode_size() + self.tips.encode_size()
    }
}

impl<D: Digest> Read for HistoryRecord<D> {
    type Cfg = CodecConfig;

    fn read_cfg(buf: &mut impl Buf, config: &Self::Cfg) -> Result<Self, CodecError> {
        let parent = D::read(buf)?;
        let tips = Vec::<BlockRef<D>>::read_cfg(buf, &(RangeCfg::exact(config.chains()), ()))?;
        Self::new(parent, tips).map_err(|error| CodecError::Wrapped("HistoryRecord", error.into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        multimmit::types::{ChainId, EpochGenesis, Window},
        types::Height,
    };
    use commonware_codec::Decode as _;
    use commonware_cryptography::{Sha256, sha256::Digest as Sha256Digest};

    fn tips() -> Vec<BlockRef<Sha256Digest>> {
        vec![
            BlockRef::new(ChainId::new(0), Height::new(11), Sha256::hash(&[b"tip 0"])),
            BlockRef::new(ChainId::new(1), Height::new(17), Sha256::hash(&[b"tip 1"])),
        ]
    }

    #[test]
    fn commitment_is_domain_separated() {
        let parent = Sha256::hash(&[b"parent"]);
        let record = HistoryRecord::new(parent, tips()).unwrap();
        let encoded_tips = tips().encode();
        assert_eq!(
            record.commitment::<Sha256>(),
            Sha256::hash(&[
                TIP_HISTORY_NAMESPACE,
                parent.as_ref(),
                encoded_tips.as_ref()
            ])
        );
        assert_ne!(
            record.commitment::<Sha256>(),
            Sha256::hash(&[parent.as_ref(), encoded_tips.as_ref()])
        );
        assert_ne!(
            record.commitment::<Sha256>(),
            HistoryRecord::new(Sha256::hash(&[b"other"]), tips())
                .unwrap()
                .commitment::<Sha256>()
        );
        assert_eq!(record.output_index(), Some(28));
    }

    #[test]
    fn genesis_commitment_is_domain_separated() {
        let genesis = EpochGenesis::new::<Sha256>(Epoch::new(4), 2).unwrap();
        let tips = genesis.tips().encode();
        let epoch = Epoch::new(4).encode();
        assert_eq!(
            genesis.history(),
            Sha256::hash(&[GENESIS_HISTORY_NAMESPACE, epoch.as_ref(), tips.as_ref()])
        );
        assert_ne!(
            genesis.history(),
            Sha256::hash(&[TIP_HISTORY_NAMESPACE, epoch.as_ref(), tips.as_ref()])
        );
    }

    #[test]
    fn records_require_canonical_chains() {
        let parent = Sha256::hash(&[b"parent"]);
        assert_eq!(HistoryRecord::new(parent, Vec::new()), Err(Error::Chain));
        let mut swapped = tips();
        swapped.swap(0, 1);
        assert_eq!(HistoryRecord::new(parent, swapped), Err(Error::Chain));
    }

    #[test]
    fn codec_round_trips_with_exact_chain_bound() {
        let record = HistoryRecord::new(Sha256::hash(&[b"parent"]), tips()).unwrap();
        let codec = CodecConfig::new(6, 2, Window::new(4).unwrap()).unwrap();
        assert_eq!(
            HistoryRecord::decode_cfg(record.encode(), &codec).unwrap(),
            record
        );
        let wider = CodecConfig::new(6, 3, Window::new(4).unwrap()).unwrap();
        assert!(HistoryRecord::<Sha256Digest>::decode_cfg(record.encode(), &wider).is_err());
    }
}
