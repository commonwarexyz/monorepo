//! The immutable body archive and the durable promotion cursor.
//!
//! The durable cursor binds each producer frontier to the floor generation that established it.
//! Generation-tagged output rows make state-sync jumps explicit, so recovery can replay later
//! outputs without depending on an in-memory install notification.

use crate::multimmit::{
    marshal::{
        storage::{
            Error,
            archive::FinalBody,
            record::{DurableRecord, OnMissing},
        },
        types::OutputIndex,
    },
    types::{BlockRef, Body, ChainId, Frontier, TransactionBlock},
};
use commonware_codec::{Buf, EncodeSize, Error as CodecError, RangeCfg, Read, ReadExt, Write};
use commonware_cryptography::{Digest, Hasher};
use commonware_storage::{Context, translator::Translator};
use std::sync::Arc;

/// Version byte leading every encoded [`PromotionState`].
const STATE_VERSION: u8 = 1;

/// Promotion progress on one producer chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ChainCursor<D: Digest> {
    /// Highest block whose body is immutable, or the floor installed on this chain.
    frontier: BlockRef<D>,
    /// Newest floor generation applied to this chain.
    generation: u64,
}

/// Durable immutable-promotion progress.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PromotionState<D: Digest> {
    /// Highest output whose body is immutable.
    through: Option<OutputIndex>,
    /// One cursor per producer chain, in chain order.
    cursors: Vec<ChainCursor<D>>,
}

/// The promotion state stored when a namespace has none.
pub(crate) struct PromotionSeed<D: Digest> {
    /// Committed output of the catalog checkpoint.
    pub(crate) through: Option<OutputIndex>,
    /// Emitted frontier of the catalog checkpoint.
    pub(crate) frontier: Frontier<D>,
    /// Floor generation of the catalog checkpoint.
    pub(crate) generation: u64,
}

/// One finalized body ready for immutable promotion.
pub(crate) struct PromotedBody<H, B>
where
    H: Hasher,
    B: Body<H>,
{
    /// Dense output the body is committed at.
    pub index: OutputIndex,
    /// Block reference recorded by the output row.
    pub reference: BlockRef<H::Digest>,
    /// Complete block.
    pub block: Arc<TransactionBlock<H, B>>,
    /// Floor generation that committed the output.
    pub floor_generation: u64,
}

/// Exclusive immutable archive state owned by the promoter actor.
pub(crate) struct PromotionStore<T, E, H, B>
where
    T: Translator,
    E: Context,
    H: Hasher,
    B: Body<H>,
{
    bodies: Option<FinalBody<T, E, H, B>>,
    record: DurableRecord<E, PromotionState<H::Digest>>,
    state: PromotionState<H::Digest>,
}

impl<D: Digest> PromotionState<D> {
    fn seed(seed: &PromotionSeed<D>) -> Self {
        Self {
            through: seed.through,
            cursors: seed
                .frontier
                .references()
                .iter()
                .map(|&frontier| ChainCursor {
                    frontier,
                    generation: seed.generation,
                })
                .collect(),
        }
    }

    /// Returns the promoted frontier on every chain, in chain order.
    fn frontiers(&self) -> Vec<BlockRef<D>> {
        self.cursors.iter().map(|cursor| cursor.frontier).collect()
    }

    /// Merges an installed floor without regressing bodies promoted beyond it.
    ///
    /// Returns whether any chain's frontier or generation changed.
    fn install(&mut self, generation: u64, floor: &Frontier<D>) -> Result<bool, Error> {
        let mut frontier =
            Frontier::new(self.frontiers()).expect("promotion cursors are chain-indexed");
        let mut changed = frontier.merge_max(floor).map_err(|_| {
            Error::Inconsistent("immutable promotion floor conflicts or mismatches")
        })?;
        for (cursor, merged) in self.cursors.iter_mut().zip(frontier.into_references()) {
            cursor.frontier = merged;
            if generation > cursor.generation {
                cursor.generation = generation;
                changed = true;
            }
        }
        Ok(changed)
    }

    /// Applies one dense output. A newer generation authenticates a state-sync jump.
    fn extend(&mut self, reference: BlockRef<D>, parent: D, generation: u64) -> Result<(), Error> {
        let Some(cursor) = self.cursors.get_mut(reference.chain().get() as usize) else {
            return Err(Error::Inconsistent(
                "immutable promotion block has an unknown producer chain",
            ));
        };
        let current = cursor.frontier;
        let direct = current.height().next() == reference.height() && parent == current.digest();
        let installed_jump =
            generation > cursor.generation && reference.height() > current.height();
        if !direct && !installed_jump {
            return Err(Error::Inconsistent(
                "immutable promotion block does not extend its producer frontier",
            ));
        }
        cursor.frontier = reference;
        cursor.generation = cursor.generation.max(generation);
        Ok(())
    }
}

impl<T, E, H, B> PromotionStore<T, E, H, B>
where
    T: Translator,
    E: Context,
    H: Hasher,
    B: Body<H>,
{
    /// Opens the promotion cursor stored in `partition` over an opened body archive.
    ///
    /// A missing cursor is stored from `seed` when `on_missing` allows it.
    pub(crate) async fn init(
        context: E,
        bodies: FinalBody<T, E, H, B>,
        partition: String,
        seed: PromotionSeed<H::Digest>,
        on_missing: OnMissing,
    ) -> Result<Self, Error> {
        let mut record =
            DurableRecord::init(context, partition, seed.frontier.chains(), None).await?;
        let state = match record.get()?.cloned() {
            Some(state) => state,
            None if on_missing == OnMissing::Initialize => {
                let state = PromotionState::seed(&seed);
                record.put_sync(state.clone()).await?;
                state
            }
            None => return Err(Error::Inconsistent("immutable promotion state is missing")),
        };
        Ok(Self {
            bodies: Some(bodies),
            record,
            state,
        })
    }

    /// Returns the highest output whose body is immutable.
    pub(crate) const fn through(&self) -> Option<OutputIndex> {
        self.state.through
    }

    /// Advances a state-sync floor without inventing archived output rows.
    ///
    /// The output cursor is unchanged. The caller may reclaim pending bodies below the returned
    /// frontiers only after this update is durable.
    pub(crate) async fn advance_frontiers(
        &mut self,
        floor_generation: u64,
        frontiers: Vec<BlockRef<H::Digest>>,
    ) -> Result<Vec<BlockRef<H::Digest>>, Error> {
        let floor = Frontier::new(frontiers)
            .map_err(|_| Error::Inconsistent("immutable promotion floor is not chain-indexed"))?;
        let mut next = self.state.clone();
        if next.install(floor_generation, &floor)? {
            self.record.put_sync(next.clone()).await?;
            self.state = next;
        }
        Ok(self.state.frontiers())
    }

    /// Returns the immutable block with `digest`, if promoted.
    pub(crate) async fn block_by_digest(
        &self,
        digest: H::Digest,
    ) -> Result<Option<Arc<TransactionBlock<H, B>>>, Error> {
        self.bodies
            .as_ref()
            .ok_or(Error::Poisoned)?
            .get_by_key(&digest)
            .await
    }

    /// Returns the immutable block named by `reference`, if promoted.
    pub(crate) async fn block(
        &self,
        reference: BlockRef<H::Digest>,
    ) -> Result<Option<Arc<TransactionBlock<H, B>>>, Error> {
        Ok(self
            .block_by_digest(reference.digest())
            .await?
            .filter(|block| block.reference() == reference))
    }

    /// Promotes one dense output batch and advances the cursor only after body durability.
    pub(crate) async fn promote(
        &mut self,
        outputs: Vec<PromotedBody<H, B>>,
    ) -> Result<Vec<BlockRef<H::Digest>>, Error> {
        let Some(last) = outputs.last().map(|output| output.index) else {
            return Ok(self.state.frontiers());
        };
        check_batch(self.state.through, &outputs)?;
        let mut bodies = self.bodies.take().ok_or(Error::Poisoned)?;
        let mut state = self.state.clone();
        for output in outputs {
            state.extend(
                output.reference,
                output.block.header().parent(),
                output.floor_generation,
            )?;
            bodies = bodies
                .put(output.index.get(), output.reference.digest(), output.block)
                .await?;
        }
        self.bodies = Some(bodies.sync().await?);
        state.through = Some(last);
        self.record.put_sync(state.clone()).await?;
        self.state = state;
        Ok(self.state.frontiers())
    }
}

/// Checks that `outputs` continue densely after `through`, each carrying the block its row
/// names.
fn check_batch<H, B>(
    through: Option<OutputIndex>,
    outputs: &[PromotedBody<H, B>],
) -> Result<(), Error>
where
    H: Hasher,
    B: Body<H>,
{
    let mut expected = OutputIndex::after(through);
    for output in outputs {
        if Some(output.index) != expected || output.block.reference() != output.reference {
            return Err(Error::Inconsistent(
                "immutable promotion batch is not dense and exact",
            ));
        }
        expected = output.index.next();
    }
    Ok(())
}

impl<D: Digest> Read for ChainCursor<D> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        Ok(Self {
            frontier: BlockRef::read(buf)?,
            generation: u64::read(buf)?,
        })
    }
}

impl<D: Digest> Write for ChainCursor<D> {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.frontier.write(buf);
        self.generation.write(buf);
    }
}

impl<D: Digest> EncodeSize for ChainCursor<D> {
    fn encode_size(&self) -> usize {
        self.frontier.encode_size() + self.generation.encode_size()
    }
}

impl<D: Digest> Read for PromotionState<D> {
    type Cfg = usize;

    fn read_cfg(buf: &mut impl Buf, chains: &usize) -> Result<Self, CodecError> {
        let version = u8::read(buf)?;
        if version != STATE_VERSION {
            return Err(CodecError::InvalidEnum(version));
        }
        let through = Option::<OutputIndex>::read(buf)?;
        let cursors = Vec::<ChainCursor<D>>::read_cfg(buf, &(RangeCfg::exact(*chains), ()))?;
        if cursors.iter().enumerate().any(|(chain, cursor)| {
            u32::try_from(chain).map(ChainId::new) != Ok(cursor.frontier.chain())
        }) {
            return Err(CodecError::Invalid(
                "consensus::multimmit::marshal::PromotionState",
                "promotion cursors are not chain-indexed",
            ));
        }
        Ok(Self { through, cursors })
    }
}

impl<D: Digest> Write for PromotionState<D> {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        STATE_VERSION.write(buf);
        self.through.write(buf);
        self.cursors.write(buf);
    }
}

impl<D: Digest> EncodeSize for PromotionState<D> {
    fn encode_size(&self) -> usize {
        STATE_VERSION.encode_size() + self.through.encode_size() + self.cursors.encode_size()
    }
}

#[cfg(feature = "arbitrary")]
impl<'a, D> arbitrary::Arbitrary<'a> for PromotionState<D>
where
    D: Digest + arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let chains = u.int_in_range(1..=8u32)?;
        let cursors = (0..chains)
            .map(|chain| {
                Ok(ChainCursor {
                    frontier: BlockRef::new(ChainId::new(chain), u.arbitrary()?, u.arbitrary()?),
                    generation: u.arbitrary()?,
                })
            })
            .collect::<arbitrary::Result<_>>()?;
        Ok(Self {
            through: u.arbitrary()?,
            cursors,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        multimmit::types::TransactionBlockHeader,
        simplex::marshal::mocks::block::EmptyBlock,
        types::{Epoch, Height},
    };
    use commonware_codec::{Decode as _, Encode as _};
    use commonware_cryptography::{Digestible as _, Sha256, sha256::Digest as Sha256Digest};

    fn reference(chain: u32, height: u64, label: &[u8]) -> BlockRef<Sha256Digest> {
        BlockRef::new(
            ChainId::new(chain),
            Height::new(height),
            Sha256::hash(&[label]),
        )
    }

    fn state(frontier: BlockRef<Sha256Digest>, generation: u64) -> PromotionState<Sha256Digest> {
        PromotionState::seed(&PromotionSeed {
            through: None,
            frontier: Frontier::new(vec![frontier]).unwrap(),
            generation,
        })
    }

    fn generations(state: &PromotionState<Sha256Digest>) -> Vec<u64> {
        state
            .cursors
            .iter()
            .map(|cursor| cursor.generation)
            .collect()
    }

    #[test]
    fn generations_authorize_state_sync_jumps_without_regressing_frontiers() {
        let genesis = reference(0, 0, b"genesis");
        let mut state = state(genesis, 0);

        let first = reference(0, 1, b"first");
        state.extend(first, genesis.digest(), 0).unwrap();

        let jumped = reference(0, 5, b"jumped");
        state
            .extend(jumped, Sha256::hash(&[b"installed parent"]), 1)
            .unwrap();
        let continued = reference(0, 6, b"continued");
        state.extend(continued, jumped.digest(), 1).unwrap();

        let stale = reference(0, 7, b"stale direct");
        state.extend(stale, continued.digest(), 0).unwrap();
        assert_eq!(generations(&state), vec![1]);

        let invalid = reference(0, 8, b"invalid jump");
        assert!(
            state
                .extend(invalid, Sha256::hash(&[b"wrong parent"]), 0)
                .is_err()
        );
        assert!(
            state
                .extend(invalid, Sha256::hash(&[b"wrong parent"]), 1)
                .is_err()
        );

        let floor = Frontier::new(vec![jumped]).unwrap();
        assert!(!state.install(1, &floor).unwrap());
        assert_eq!(state.frontiers(), vec![stale]);
        assert_eq!(generations(&state), vec![1]);
    }

    #[test]
    fn direct_output_survives_a_newer_floor_generation() {
        let genesis = reference(0, 0, b"genesis");
        let mut state = state(genesis, 0);
        assert!(
            state
                .install(1, &Frontier::new(vec![genesis]).unwrap())
                .unwrap()
        );

        let child = reference(0, 1, b"child");
        state.extend(child, genesis.digest(), 0).unwrap();

        assert_eq!(state.frontiers(), vec![child]);
        assert_eq!(generations(&state), vec![1]);
    }

    #[test]
    fn conflicting_or_mismatched_floors_are_rejected_without_change() {
        let genesis = reference(0, 0, b"genesis");
        let mut state = state(genesis, 0);
        let conflict = Frontier::new(vec![reference(0, 0, b"conflict")]).unwrap();
        assert!(state.install(1, &conflict).is_err());
        let wider = Frontier::new(vec![genesis, reference(1, 0, b"other")]).unwrap();
        assert!(state.install(1, &wider).is_err());
        assert_eq!(state.frontiers(), vec![genesis]);
        assert_eq!(generations(&state), vec![0]);
    }

    fn promoted(index: u64) -> PromotedBody<Sha256, EmptyBlock<Sha256>> {
        let body = EmptyBlock::new(
            Sha256::hash(&[b"body parent"]),
            Height::new(index + 1),
            index,
        );
        let header = TransactionBlockHeader::new(
            Epoch::new(0),
            ChainId::new(0),
            Height::new(index + 1),
            Sha256::hash(&[&index.to_be_bytes()]),
            body.digest(),
        )
        .unwrap();
        let block = Arc::new(TransactionBlock::new(header, body).unwrap());
        PromotedBody {
            index: OutputIndex::new(index),
            reference: block.reference(),
            block,
            floor_generation: 0,
        }
    }

    #[test]
    fn promotion_batches_must_be_dense_after_the_cursor() {
        let batch = |indexes: &[u64]| {
            indexes
                .iter()
                .map(|&index| promoted(index))
                .collect::<Vec<_>>()
        };
        assert!(check_batch(None, &batch(&[0, 1, 2])).is_ok());
        assert!(check_batch(Some(OutputIndex::new(1)), &batch(&[2])).is_ok());
        assert!(check_batch(None, &batch(&[1])).is_err());
        assert!(check_batch(None, &batch(&[0, 2])).is_err());
        assert!(check_batch(None, &batch(&[0, 1, 1])).is_err());
        assert!(check_batch(Some(OutputIndex::new(u64::MAX)), &batch(&[0])).is_err());

        let mut wrong = batch(&[0]);
        wrong[0].reference = promoted(1).reference;
        assert!(check_batch(None, &wrong).is_err());
    }

    #[test]
    fn state_codec_is_versioned_and_chain_indexed() {
        let mut state = state(reference(0, 3, b"tip"), 2);
        state.through = Some(OutputIndex::new(9));
        let encoded = state.encode();
        assert_eq!(encoded.len(), state.encode_size());
        assert_eq!(
            PromotionState::decode_cfg(encoded.clone(), &1).unwrap(),
            state
        );
        assert!(PromotionState::<Sha256Digest>::decode_cfg(encoded.clone(), &2).is_err());

        let mut wrong_version = encoded.to_vec();
        wrong_version[0] = STATE_VERSION.wrapping_add(1);
        assert!(matches!(
            PromotionState::<Sha256Digest>::decode_cfg(wrong_version, &1),
            Err(CodecError::InvalidEnum(_))
        ));

        let misplaced = PromotionState {
            through: None,
            cursors: vec![ChainCursor {
                frontier: reference(1, 3, b"misplaced"),
                generation: 0,
            }],
        };
        assert!(matches!(
            PromotionState::<Sha256Digest>::decode_cfg(misplaced.encode(), &1),
            Err(CodecError::Invalid(_, _))
        ));
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::*;
        use commonware_codec::conformance::generate_value;
        use commonware_conformance::Conformance;

        struct PromotionStateConformance;

        impl Conformance for PromotionStateConformance {
            async fn commit(seed: u64) -> Vec<u8> {
                let state = generate_value::<PromotionState<Sha256Digest>>(seed);
                let encoded = state.encode();
                assert_eq!(
                    PromotionState::decode_cfg(encoded.clone(), &state.cursors.len()).unwrap(),
                    state
                );
                encoded.to_vec()
            }
        }

        commonware_conformance::conformance_tests! {
            PromotionStateConformance => 128,
        }
    }
}
