//! The finalization certificate a lagging node anchors on and marshal resumes ordering from.

use super::{BlockRef, CodecConfig, HistoryRecord, Lqc};
use crate::{
    Epochable, Viewable,
    types::{Epoch, View},
};
use bytes::BufMut;
use commonware_codec::{Buf, EncodeSize, Error as CodecError, Read, Write};
use commonware_cryptography::{Digest, bls12381::primitives::variant::Variant};
use std::sync::Arc;

/// A finalization certificate: an L-QC and the [`HistoryRecord`] opening its leader block's
/// history commitment.
///
/// For an L-QC of view `v` whose leader block names `Q'`, the opening is `(C(parent(Q')),
/// Tips(Q'))`. Every correct log contains the opened tips, and every V-QC of view `v` or later
/// descends from `Q'`, so a floor fixes the facts of `Q'` without its chain. Producer chains
/// start at height zero and every output advances one chain by one height, so the floor's index
/// is the sum of the opened tips' heights.
///
/// Decoding checks only the floor's shape; a reader authenticates the L-QC and checks that the
/// opening hashes to its leader block's history commitment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Floor<V: Variant, D: Digest> {
    pub(crate) lqc: Arc<Lqc<V, D>>,
    pub(crate) opening: Arc<HistoryRecord<D>>,
}

impl<V: Variant, D: Digest> Floor<V, D> {
    /// Creates a floor from an L-QC and the record opening its leader block's history commitment.
    pub const fn new(lqc: Arc<Lqc<V, D>>, opening: Arc<HistoryRecord<D>>) -> Self {
        Self { lqc, opening }
    }

    /// Returns the L-QC finalizing the floor.
    pub fn lqc(&self) -> &Lqc<V, D> {
        &self.lqc
    }

    /// Returns the record opening the L-QC's leader block history commitment.
    pub fn opening(&self) -> &HistoryRecord<D> {
        &self.opening
    }

    /// Returns the opened tips in chain order: the application snapshot frontier.
    pub fn tips(&self) -> &[BlockRef<D>] {
        self.opening.tips()
    }
}

/// A floor's epoch is its L-QC's, which the L-QC signs.
impl<V: Variant, D: Digest> Epochable for Floor<V, D> {
    fn epoch(&self) -> Epoch {
        self.lqc.epoch()
    }
}

/// A floor's view is its L-QC's, which the L-QC signs.
impl<V: Variant, D: Digest> Viewable for Floor<V, D> {
    fn view(&self) -> View {
        self.lqc.view()
    }
}

impl<V: Variant, D: Digest> Write for Floor<V, D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.lqc.write(writer);
        self.opening.write(writer);
    }
}

impl<V: Variant, D: Digest> EncodeSize for Floor<V, D> {
    fn encode_size(&self) -> usize {
        self.lqc.encode_size() + self.opening.encode_size()
    }
}

impl<V: Variant, D: Digest> Read for Floor<V, D> {
    type Cfg = CodecConfig;

    fn read_cfg(reader: &mut impl Buf, config: &Self::Cfg) -> Result<Self, CodecError> {
        let lqc = Lqc::<V, D>::read_cfg(reader, config)?;
        let opening = HistoryRecord::<D>::read_cfg(reader, config)?;
        // An index of `u64::MAX` leaves no index for the output after the floor.
        if opening.output_index().is_none_or(|index| index == u64::MAX) {
            return Err(CodecError::Invalid(
                "consensus::multimmit::Floor",
                "opened tips overflow the output index",
            ));
        }
        Ok(Self::new(Arc::new(lqc), Arc::new(opening)))
    }
}

#[cfg(feature = "arbitrary")]
impl<'a, V> arbitrary::Arbitrary<'a> for Floor<V, commonware_cryptography::sha256::Digest>
where
    V: Variant,
    Lqc<V, commonware_cryptography::sha256::Digest>: arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        use super::ChainId;
        use crate::types::Height;

        let tips = (0..super::arbitrary_codec_config().chains())
            .map(|chain| {
                // Heights stay small enough that the floor's index fits the output index.
                Ok(BlockRef::new(
                    ChainId::new(chain as u32),
                    Height::new(u64::from(u.arbitrary::<u32>()?)),
                    u.arbitrary()?,
                ))
            })
            .collect::<arbitrary::Result<_>>()?;
        let opening = HistoryRecord::new(u.arbitrary()?, tips).expect("tips are in chain order");
        Ok(Self::new(Arc::new(u.arbitrary()?), Arc::new(opening)))
    }
}
