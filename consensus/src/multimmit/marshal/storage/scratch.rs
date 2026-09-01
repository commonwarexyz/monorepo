//! Disposable spill stacks for history and producer-chain walks.
//!
//! A walk discovers values newest-first and consumes them oldest-first. [`SpillStack`] keeps a
//! bounded walk in memory and spills to a journal once it exceeds its memory limit, so an
//! arbitrarily long backfill uses bounded memory. Contents are non-authoritative plans derived
//! from authenticated ancestry and are discarded when the stack opens.

use super::Error;
use crate::multimmit::types::{BlockRef, CodecConfig, TipRecord};
use commonware_codec::{Buf, CodecShared, EncodeSize, FixedSize as _, Read, Write};
use commonware_cryptography::{Digest, Hasher};
use commonware_storage::{Context, journal::segmented::variable};
use std::{fmt::Display, future::Future, mem, sync::Arc};

/// History walks keep no openings in memory: every opening spills to the journal.
const HISTORY_MEMORY_LIMIT: usize = 0;

/// A journal node linking a value to the next newer value in its section.
struct ReverseNode<V: CodecShared> {
    newer: Option<u64>,
    value: V,
}

impl<V: CodecShared> ReverseNode<V> {
    /// Largest encoded size of the link stored with each value.
    const LINK_SIZE: usize = bool::SIZE + u64::SIZE;
}

/// Whether a stack still accepts pushes.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Writing,
    Reading,
}

/// Where a stack's values currently live.
enum Tier<V> {
    /// Values per section, newest last, with their encoded bytes plus link overhead.
    Memory { sections: Vec<Vec<V>>, bytes: usize },
    /// Values spilled to the journal, with the newest node of each section.
    Disk { heads: Vec<Option<u64>> },
}

/// A stack per section whose values are pushed newest-first and read oldest-first.
pub(crate) struct SpillStack<E, V>
where
    E: Context,
    V: CodecShared,
{
    journal: Option<variable::Journal<E, ReverseNode<V>>>,
    tier: Tier<V>,
    mode: Mode,
    /// Encoded bytes, including link overhead, held in memory before the stack spills.
    memory_limit: usize,
}

impl<E, V> SpillStack<E, V>
where
    E: Context,
    V: CodecShared,
{
    /// Opens an empty stack after discarding any recovered residue.
    pub(crate) async fn init(
        context: E,
        config: variable::Config<V::Cfg>,
        memory_limit: usize,
    ) -> Result<Self, Error> {
        let journal = variable::Journal::init(context, config)
            .await?
            .clear()
            .await?;
        Ok(Self {
            journal: Some(journal),
            tier: Tier::Memory {
                sections: Vec::new(),
                bytes: 0,
            },
            mode: Mode::Writing,
            memory_limit,
        })
    }

    /// Discards every value and returns to writing.
    pub(crate) async fn reset(&mut self) -> Result<(), Error> {
        if self.journal.is_none() {
            return Err(Error::Poisoned);
        }
        if matches!(self.tier, Tier::Disk { .. }) {
            let journal = self.journal.take().ok_or(Error::Poisoned)?;
            self.journal = Some(journal.clear().await?);
        }
        self.tier = Tier::Memory {
            sections: Vec::new(),
            bytes: 0,
        };
        self.mode = Mode::Writing;
        Ok(())
    }

    /// Pushes the next newer value of `section`.
    pub(crate) async fn push(&mut self, section: usize, value: V) -> Result<(), Error> {
        if self.mode == Mode::Reading {
            return Err(Error::Invalid(
                "scratch values cannot be pushed after reading begins",
            ));
        }
        if let Tier::Memory { sections, bytes } = &mut self.tier {
            let encoded = value
                .encode_size()
                .saturating_add(ReverseNode::<V>::LINK_SIZE);
            if let Some(total) = bytes.checked_add(encoded)
                && total <= self.memory_limit
            {
                if sections.len() <= section {
                    sections.resize_with(section + 1, Vec::new);
                }
                sections[section].push(value);
                *bytes = total;
                return Ok(());
            }
            self.spill().await?;
        }
        self.push_disk(section, value).await
    }

    /// Reads the oldest unread value of `section`, ending the writing phase.
    pub(crate) async fn read_oldest(&mut self, section: usize) -> Result<Option<V>, Error> {
        self.mode = Mode::Reading;
        let heads = match &mut self.tier {
            Tier::Memory { sections, .. } => {
                return Ok(sections.get_mut(section).and_then(Vec::pop));
            }
            Tier::Disk { heads } => heads,
        };
        let Some(offset) = heads.get(section).copied().flatten() else {
            return Ok(None);
        };
        let node = self
            .journal
            .as_ref()
            .ok_or(Error::Poisoned)?
            .get(section as u64, offset)
            .await?;
        heads[section] = node.newer;
        Ok(Some(node.value))
    }

    /// Moves every in-memory value to the journal, preserving each section's order.
    async fn spill(&mut self) -> Result<(), Error> {
        let tier = mem::replace(&mut self.tier, Tier::Disk { heads: Vec::new() });
        let Tier::Memory { sections, .. } = tier else {
            self.tier = tier;
            return Ok(());
        };
        for (section, values) in sections.into_iter().enumerate() {
            for value in values {
                self.push_disk(section, value).await?;
            }
        }
        Ok(())
    }

    async fn push_disk(&mut self, section: usize, value: V) -> Result<(), Error> {
        let Tier::Disk { heads } = &mut self.tier else {
            unreachable!("only a spilled stack appends to its journal");
        };
        if heads.len() <= section {
            heads.resize(section + 1, None);
        }
        let node = ReverseNode {
            newer: heads[section],
            value,
        };
        let journal = self.journal.take().ok_or(Error::Poisoned)?;
        let (journal, offset, _) = journal.append(section as u64, &node).await?;
        self.journal = Some(journal);
        heads[section] = Some(offset);
        Ok(())
    }
}

/// Scratch storage for a history walk, read oldest-first.
pub(crate) struct HistoryScratch<E, H>
where
    E: Context,
    H: Hasher,
{
    stack: SpillStack<E, Arc<TipRecord<H::Digest>>>,
}

impl<E, H> HistoryScratch<E, H>
where
    E: Context,
    H: Hasher,
{
    /// Opens empty scratch storage after discarding any recovered residue.
    pub(crate) async fn init(
        context: E,
        config: variable::Config<CodecConfig>,
    ) -> Result<Self, Error> {
        Ok(Self {
            stack: SpillStack::init(context, config, HISTORY_MEMORY_LIMIT).await?,
        })
    }
}

/// Scratch storage for producer references, one section per chain, read oldest-first.
pub(crate) type BlockScratch<E, D> = SpillStack<E, BlockRef<D>>;

/// One authenticated history link retained in scratch storage.
pub(crate) struct HistoryLink<H: Hasher> {
    /// Commitment of `record`.
    pub commitment: H::Digest,
    /// Tip-history opening.
    pub record: Arc<TipRecord<H::Digest>>,
}

impl<H: Hasher> Clone for HistoryLink<H> {
    fn clone(&self) -> Self {
        Self {
            commitment: self.commitment,
            record: Arc::clone(&self.record),
        }
    }
}

/// Scratch storage for an unbounded history walk.
///
/// After `reset`, pushes arrive newest-first. `read_oldest` returns them oldest-first and then
/// returns `None`. Implementations may discard read entries.
pub(crate) trait HistoryStack<H: Hasher>: Send + 'static {
    /// Failure reported by the stack.
    type Error: Display + Send + Sync + 'static;

    /// Discards every link and returns to writing.
    fn reset(&mut self) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Pushes the next older link.
    fn push(
        &mut self,
        link: HistoryLink<H>,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Reads the oldest unread link.
    fn read_oldest(
        &mut self,
    ) -> impl Future<Output = Result<Option<HistoryLink<H>>, Self::Error>> + Send;
}

/// Bounded scratch storage for unbounded producer-chain traversals.
///
/// Blocks are pushed in reverse canonical order and read oldest-first per chain.
pub(crate) trait BlockStack<D: Digest>: Send + 'static {
    /// Failure reported by the stack.
    type Error: Display + Send + Sync + 'static;

    /// Discards every block and returns to writing.
    fn reset(&mut self) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Pushes the next older block of its chain.
    fn push(&mut self, block: BlockRef<D>) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Reads the oldest unread block of `chain`.
    fn read_oldest(
        &mut self,
        chain: usize,
    ) -> impl Future<Output = Result<Option<BlockRef<D>>, Self::Error>> + Send;
}

impl<E, H> HistoryStack<H> for HistoryScratch<E, H>
where
    E: Context,
    H: Hasher,
{
    type Error = Error;

    async fn reset(&mut self) -> Result<(), Error> {
        self.stack.reset().await
    }

    async fn push(&mut self, link: HistoryLink<H>) -> Result<(), Error> {
        if link.record.commitment::<H>() != link.commitment {
            return Err(Error::Invalid("history link does not match its commitment"));
        }
        self.stack.push(0, link.record).await
    }

    async fn read_oldest(&mut self) -> Result<Option<HistoryLink<H>>, Error> {
        Ok(self.stack.read_oldest(0).await?.map(|record| HistoryLink {
            commitment: record.commitment::<H>(),
            record,
        }))
    }
}

impl<E, D> BlockStack<D> for BlockScratch<E, D>
where
    E: Context,
    D: Digest,
{
    type Error = Error;

    async fn reset(&mut self) -> Result<(), Error> {
        Self::reset(self).await
    }

    async fn push(&mut self, block: BlockRef<D>) -> Result<(), Error> {
        Self::push(self, block.chain().get() as usize, block).await
    }

    async fn read_oldest(&mut self, chain: usize) -> Result<Option<BlockRef<D>>, Error> {
        Self::read_oldest(self, chain).await
    }
}

impl<V: CodecShared> Write for ReverseNode<V> {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.newer.write(buf);
        self.value.write(buf);
    }
}

impl<V: CodecShared> Read for ReverseNode<V> {
    type Cfg = V::Cfg;

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
        Ok(Self {
            newer: Option::<u64>::read_cfg(buf, &())?,
            value: V::read_cfg(buf, cfg)?,
        })
    }
}

impl<V: CodecShared> EncodeSize for ReverseNode<V> {
    fn encode_size(&self) -> usize {
        self.newer.encode_size() + self.value.encode_size()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        multimmit::types::{ChainId, PathLimits},
        types::Height,
    };
    use commonware_cryptography::{Sha256, sha256::Digest as Sha256Digest};
    use commonware_runtime::{
        Runner as _, Supervisor as _,
        buffer::paged::CacheRef,
        deterministic::{self, Context as DeterministicContext},
    };
    use commonware_utils::{NZU16, NZUsize};

    type TestScratch = HistoryScratch<DeterministicContext, Sha256>;
    type TestJournal =
        variable::Journal<DeterministicContext, ReverseNode<Arc<TipRecord<Sha256Digest>>>>;
    type TestBlockScratch = BlockScratch<DeterministicContext, Sha256Digest>;

    const MEMORY_LIMIT: usize = 1024 * 1024;

    fn config<C>(
        context: &DeterministicContext,
        prefix: &str,
        codec_config: C,
    ) -> variable::Config<C> {
        variable::Config {
            partition: prefix.into(),
            compression: None,
            codec_config,
            page_cache: CacheRef::from_pooler(context, NZU16!(1024), NZUsize!(10)),
            write_buffer: NZUsize!(1024 * 1024),
        }
    }

    fn codec() -> CodecConfig {
        CodecConfig::new(1, 1, PathLimits::new(1, 0).unwrap()).unwrap()
    }

    fn digest(label: &[u8], marker: u64) -> Sha256Digest {
        Sha256::hash(&[label, &marker.to_be_bytes()])
    }

    fn link(marker: u64) -> HistoryLink<Sha256> {
        let record = Arc::new(
            TipRecord::at_tips(
                digest(b"parent", marker),
                vec![BlockRef::new(
                    ChainId::new(0),
                    Height::new(marker),
                    digest(b"tip", marker),
                )],
            )
            .unwrap(),
        );
        HistoryLink {
            commitment: record.commitment::<Sha256>(),
            record,
        }
    }

    fn reference(chain: u32, height: u64, marker: u64) -> BlockRef<Sha256Digest> {
        BlockRef::new(
            ChainId::new(chain),
            Height::new(height),
            digest(b"block", marker),
        )
    }

    const fn spilled<E: Context, V: CodecShared>(stack: &SpillStack<E, V>) -> bool {
        matches!(stack.tier, Tier::Disk { .. })
    }

    #[test]
    fn very_long_stack_is_oldest_first_without_sync() {
        const LINKS: u64 = 10_000;
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let mut scratch = TestScratch::init(
                context.child("long_stack"),
                config(&context, "history_scratch_long", codec()),
            )
            .await
            .unwrap();
            for marker in 0..LINKS {
                scratch.push(link(marker)).await.unwrap();
            }
            for expected in (0..LINKS).rev() {
                let actual = scratch.read_oldest().await.unwrap().unwrap();
                assert_eq!(actual.record.tips()[0].height(), Height::new(expected));
                assert_eq!(actual.commitment, actual.record.commitment::<Sha256>());
            }
            assert!(scratch.read_oldest().await.unwrap().is_none());
            assert!(matches!(
                scratch.push(link(0)).await,
                Err(Error::Invalid(_))
            ));
        });
    }

    #[test]
    fn reset_and_reopen_discard_every_prior_segment() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let cfg = config(&context, "history_scratch_reset", codec());
            let mut scratch = TestScratch::init(context.child("first"), cfg.clone())
                .await
                .unwrap();
            for marker in 0..130 {
                scratch.push(link(marker)).await.unwrap();
            }
            assert!(scratch.read_oldest().await.unwrap().is_some());
            scratch.reset().await.unwrap();
            assert!(scratch.read_oldest().await.unwrap().is_none());
            scratch.reset().await.unwrap();
            scratch.push(link(900)).await.unwrap();
            drop(scratch);

            let mut reopened = TestScratch::init(context.child("second"), cfg)
                .await
                .unwrap();
            assert!(reopened.read_oldest().await.unwrap().is_none());
            reopened.reset().await.unwrap();
            reopened.push(link(901)).await.unwrap();
            assert_eq!(
                reopened.read_oldest().await.unwrap().unwrap().record.tips()[0].height(),
                Height::new(901)
            );
        });
    }

    #[test]
    fn durable_reset_survives_a_logically_empty_reopen() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let cfg = config(&context, "history_scratch_durable_reset", codec());
            let mut scratch = TestScratch::init(context.child("before_reset"), cfg.clone())
                .await
                .unwrap();
            for marker in 0..8 {
                scratch.push(link(marker)).await.unwrap();
            }
            let journal = scratch.stack.journal.take().unwrap();
            scratch.stack.journal = Some(journal.sync_all().await.unwrap());
            scratch.reset().await.unwrap();
            assert!(scratch.read_oldest().await.unwrap().is_none());
            drop(scratch);

            let mut reopened = TestScratch::init(context.child("after_reset"), cfg)
                .await
                .unwrap();
            assert!(reopened.read_oldest().await.unwrap().is_none());
            reopened.reset().await.unwrap();
            reopened.push(link(8)).await.unwrap();
            assert_eq!(
                reopened.read_oldest().await.unwrap().unwrap().record.tips()[0].height(),
                Height::new(8)
            );
        });
    }

    #[test]
    fn initialization_hides_durable_crash_residue() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let cfg = config(&context, "history_scratch_recovery", codec());
            let mut journal = TestJournal::init(context.child("seed"), cfg.clone())
                .await
                .unwrap();
            let mut head = None;
            for marker in 70..=77 {
                let node = ReverseNode {
                    newer: head,
                    value: link(marker).record,
                };
                let (next, offset, _) = journal.append(0, &node).await.unwrap();
                journal = next;
                head = Some(offset);
            }
            drop(journal.sync_all().await.unwrap());

            let mut scratch = TestScratch::init(context.child("recover"), cfg.clone())
                .await
                .unwrap();
            assert!(scratch.read_oldest().await.unwrap().is_none());
            scratch.reset().await.unwrap();
            drop(scratch);

            let mut scratch = TestScratch::init(context.child("recover_empty"), cfg)
                .await
                .unwrap();
            assert!(scratch.read_oldest().await.unwrap().is_none());
            scratch.reset().await.unwrap();
            scratch.push(link(78)).await.unwrap();
            assert_eq!(
                scratch.read_oldest().await.unwrap().unwrap().record.tips()[0].height(),
                Height::new(78)
            );
        });
    }

    #[test]
    fn invalid_and_poisoned_history_scratch_is_rejected() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let mut scratch = TestScratch::init(
                context.child("overflow"),
                config(&context, "history_scratch_overflow", codec()),
            )
            .await
            .unwrap();
            let mut invalid = link(1);
            invalid.commitment = digest(b"wrong commitment", 1);
            assert!(matches!(
                scratch.push(invalid).await,
                Err(Error::Invalid(_))
            ));
            assert!(scratch.stack.journal.is_some());
            scratch.stack.journal = None;
            assert!(matches!(scratch.reset().await, Err(Error::Poisoned)));
        });
    }

    #[test]
    fn block_scratch_reads_oldest_first() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let mut scratch = TestBlockScratch::init(
                context.child("block_order"),
                config(&context, "block_scratch_order", ()),
                MEMORY_LIMIT,
            )
            .await
            .unwrap();
            let newest = reference(0, 3, 3);
            let middle = reference(0, 2, 2);
            let oldest = reference(0, 1, 1);

            for reference in [newest, middle, oldest] {
                BlockStack::push(&mut scratch, reference).await.unwrap();
            }
            assert!(!spilled(&scratch));
            for expected in [oldest, middle, newest] {
                assert_eq!(scratch.read_oldest(0).await.unwrap().unwrap(), expected);
            }
            assert!(scratch.read_oldest(0).await.unwrap().is_none());
            assert!(matches!(
                BlockStack::push(&mut scratch, reference(0, 1, 1)).await,
                Err(Error::Invalid(_))
            ));
        });
    }

    #[test]
    fn block_scratch_reopen_hides_durable_residue() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let stale = reference(0, 1, 1);
            let cfg = config(&context, "block_scratch_reopen", ());
            let mut scratch =
                TestBlockScratch::init(context.child("first"), cfg.clone(), stale.encode_size())
                    .await
                    .unwrap();
            BlockStack::push(&mut scratch, stale).await.unwrap();
            assert!(spilled(&scratch));
            let journal = scratch.journal.take().unwrap();
            scratch.journal = Some(journal.sync_all().await.unwrap());
            drop(scratch);

            let mut reopened = TestBlockScratch::init(context.child("second"), cfg, MEMORY_LIMIT)
                .await
                .unwrap();
            assert!(reopened.read_oldest(0).await.unwrap().is_none());
            reopened.reset().await.unwrap();
            let current = reference(0, 2, 2);
            BlockStack::push(&mut reopened, current).await.unwrap();
            assert_eq!(reopened.read_oldest(0).await.unwrap().unwrap(), current);
        });
    }

    #[test]
    fn block_scratch_spills_without_changing_chain_order() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let newest = reference(0, 2, 2);
            let oldest = reference(0, 1, 1);
            let other = reference(1, 1, 3);
            let mut scratch = TestBlockScratch::init(
                context.child("spill"),
                config(&context, "block_scratch_spill", ()),
                newest.encode_size() + ReverseNode::<BlockRef<Sha256Digest>>::LINK_SIZE,
            )
            .await
            .unwrap();

            BlockStack::push(&mut scratch, newest).await.unwrap();
            assert!(!spilled(&scratch));
            BlockStack::push(&mut scratch, other).await.unwrap();
            BlockStack::push(&mut scratch, oldest).await.unwrap();

            assert!(spilled(&scratch));
            assert_eq!(scratch.read_oldest(0).await.unwrap().unwrap(), oldest);
            assert_eq!(scratch.read_oldest(0).await.unwrap().unwrap(), newest);
            assert!(scratch.read_oldest(0).await.unwrap().is_none());
            assert_eq!(scratch.read_oldest(1).await.unwrap().unwrap(), other);
            assert!(scratch.read_oldest(1).await.unwrap().is_none());
        });
    }

    #[test]
    fn block_scratch_reset_discards_partial_reads() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let mut scratch = TestBlockScratch::init(
                context.child("block_reset"),
                config(&context, "block_scratch_reset", ()),
                MEMORY_LIMIT,
            )
            .await
            .unwrap();
            for height in (1..=3).rev() {
                BlockStack::push(&mut scratch, reference(0, height, height))
                    .await
                    .unwrap();
            }
            assert!(scratch.read_oldest(0).await.unwrap().is_some());
            scratch.reset().await.unwrap();
            assert!(scratch.read_oldest(0).await.unwrap().is_none());

            scratch.reset().await.unwrap();
            let only = reference(0, 4, 4);
            BlockStack::push(&mut scratch, only).await.unwrap();
            assert_eq!(scratch.read_oldest(0).await.unwrap().unwrap(), only);
        });
    }
}
