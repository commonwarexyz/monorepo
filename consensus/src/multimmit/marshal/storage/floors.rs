//! Floors established by finalized L-QCs.

use super::catalog_state::frontier_index;
#[cfg(feature = "arbitrary")]
use crate::{multimmit::types::ChainId, types::Height};
use crate::{
    multimmit::types::{BlockRef, Frontier},
    types::OutputIndex,
};
use commonware_codec::{Buf, EncodeSize, Error, RangeCfg, Read, ReadExt as _, Write};
use commonware_cryptography::Digest;

/// The floor a finalized L-QC establishes: where its final sweep ends, and the finalized ordinal
/// of the tip-history opening its leader committed.
///
/// The record is stored at the L-QC's finalized ordinal and keyed by its certificate identity, so
/// it is retained exactly as long as the L-QC. The L-QC, that opening, and the emitted frontier
/// together form a [`Floor`](crate::multimmit::marshal::Floor).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct FloorRecord<D: Digest> {
    history_index: u64,
    emitted: Frontier<D>,
    /// Derived from `emitted`; not encoded.
    index: OutputIndex,
}

impl<D: Digest> FloorRecord<D> {
    /// Records a floor whose leader committed the opening at `history_index` and whose final
    /// sweep ends at `emitted`, or returns `None` if `emitted`'s heights sum past the output index
    /// space.
    pub(crate) fn new(history_index: u64, emitted: Frontier<D>) -> Option<Self> {
        let index = frontier_index(emitted.references())?;
        Some(Self {
            history_index,
            emitted,
            index,
        })
    }

    /// Returns the finalized ordinal of the tip-history opening the floor's leader committed.
    pub(crate) const fn history_index(&self) -> u64 {
        self.history_index
    }

    /// Returns the emitted frontier at the end of the final sweep, in chain order.
    pub(crate) fn emitted(&self) -> &[BlockRef<D>] {
        self.emitted.references()
    }

    /// Returns the index of the last output of the final sweep.
    pub(crate) const fn index(&self) -> OutputIndex {
        self.index
    }
}

impl<D: Digest> Write for FloorRecord<D> {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.history_index.write(buf);
        self.emitted.references().write(buf);
    }
}

impl<D: Digest> EncodeSize for FloorRecord<D> {
    fn encode_size(&self) -> usize {
        self.history_index.encode_size() + self.emitted.references().encode_size()
    }
}

impl<D: Digest> Read for FloorRecord<D> {
    /// The number of producer chains.
    type Cfg = usize;

    fn read_cfg(buf: &mut impl Buf, chains: &usize) -> Result<Self, Error> {
        let history_index = u64::read(buf)?;
        let emitted = Vec::<BlockRef<D>>::read_cfg(buf, &(RangeCfg::exact(*chains), ()))?;
        let emitted = Frontier::new(emitted).map_err(|_| {
            Error::Invalid(
                "consensus::multimmit::marshal::FloorRecord",
                "emitted frontier is not canonical",
            )
        })?;
        Self::new(history_index, emitted).ok_or(Error::Invalid(
            "consensus::multimmit::marshal::FloorRecord",
            "emitted frontier overflows the output index",
        ))
    }
}

#[cfg(feature = "arbitrary")]
impl<'a, D> arbitrary::Arbitrary<'a> for FloorRecord<D>
where
    D: Digest + arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let history_index = u.arbitrary()?;
        let chains = u.int_in_range(1..=8u32)?;
        // Bound every height so the frontier's sum fits the output index space.
        let max_height = u64::MAX / u64::from(chains);
        let emitted = (0..chains)
            .map(|chain| {
                Ok(BlockRef::new(
                    ChainId::new(chain),
                    Height::new(u.int_in_range(0..=max_height)?),
                    u.arbitrary()?,
                ))
            })
            .collect::<arbitrary::Result<Vec<_>>>()?;
        let emitted = Frontier::new(emitted).expect("generated frontier is canonical");
        Ok(Self::new(history_index, emitted).expect("generated frontier fits the output index"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{multimmit::types::ChainId, types::Height};
    use commonware_codec::{Decode as _, Encode as _};
    use commonware_cryptography::{Hasher as _, Sha256, sha256::Digest as Sha256Digest};

    fn reference(chain: u32, height: u64) -> BlockRef<Sha256Digest> {
        BlockRef::new(
            ChainId::new(chain),
            Height::new(height),
            Sha256::hash(&[&chain.to_be_bytes(), &height.to_be_bytes()]),
        )
    }

    #[test]
    fn index_is_the_emitted_frontier_sum() {
        let emitted = Frontier::new(vec![reference(0, 4), reference(1, 7)]).unwrap();
        let record = FloorRecord::new(3, emitted).unwrap();
        assert_eq!(record.history_index(), 3);
        assert_eq!(record.index(), OutputIndex::new(11));
        assert_eq!(record.emitted(), &[reference(0, 4), reference(1, 7)]);

        let encoded = record.encode();
        assert_eq!(encoded.len(), record.encode_size());
        assert_eq!(
            FloorRecord::decode_cfg(encoded.clone(), &2).unwrap(),
            record
        );
        assert!(FloorRecord::<Sha256Digest>::decode_cfg(encoded, &3).is_err());
    }

    #[test]
    fn overflowing_frontiers_are_rejected() {
        let emitted = vec![reference(0, u64::MAX), reference(1, 1)];
        assert!(FloorRecord::new(0, Frontier::new(emitted.clone()).unwrap()).is_none());
        let encoded = (0u64, emitted).encode();
        assert!(FloorRecord::<Sha256Digest>::decode_cfg(encoded, &2).is_err());
    }

    #[test]
    fn non_canonical_frontiers_are_rejected() {
        let swapped = vec![reference(1, 3), reference(0, 3)];
        let encoded = (0u64, swapped).encode();
        assert!(FloorRecord::<Sha256Digest>::decode_cfg(encoded, &2).is_err());
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::*;
        use commonware_codec::conformance::generate_value;
        use commonware_conformance::Conformance;

        struct FloorRecordConformance;

        impl Conformance for FloorRecordConformance {
            async fn commit(seed: u64) -> Vec<u8> {
                let record = generate_value::<FloorRecord<Sha256Digest>>(seed);
                let encoded = record.encode();
                assert_eq!(
                    FloorRecord::decode_cfg(encoded.clone(), &record.emitted().len()).unwrap(),
                    record
                );
                encoded.to_vec()
            }
        }

        commonware_conformance::conformance_tests! {
            FloorRecordConformance => 128,
        }
    }
}
