//! Disposable spillable stacks for history and producer-chain walks.

use crate::multimmit::{
    marshal::actors::{
        catalog::Shared,
        synchronizer::{BlockStack, HistoryLink, HistoryStack},
    },
    types::{BlockRef, TipRecord},
};
use commonware_codec::{CodecShared, EncodeSize, Read, Write};
use commonware_cryptography::{Digest, Hasher};
use commonware_storage::{
    Context,
    journal::{self, segmented::variable},
};
use std::{future::Future, mem};

/// A scratch-stack operation failed.
#[derive(Debug, thiserror::Error)]
pub(in crate::multimmit::marshal) enum Error {
    #[error("scratch journal is unavailable after a failed or canceled mutation")]
    Poisoned,
    #[error("scratch items cannot be pushed after reverse reading begins")]
    Reading,
    #[error("history link does not match its digest key")]
    Commitment,
    #[error(transparent)]
    Journal(#[from] journal::Error),
}

type HistoryValue<H> = Shared<TipRecord<<H as Hasher>::Digest>>;

struct ReverseNode<V: CodecShared> {
    newer: Option<u64>,
    value: V,
}

impl<V: CodecShared> Write for ReverseNode<V> {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.newer.write(buf);
        self.value.write(buf);
    }
}

impl<V: CodecShared> Read for ReverseNode<V> {
    type Cfg = V::Cfg;

    fn read_cfg(
        buf: &mut impl bytes::Buf,
        cfg: &Self::Cfg,
    ) -> Result<Self, commonware_codec::Error> {
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

struct ReverseStack<E, V>
where
    E: Context,
    V: CodecShared,
{
    journal: Option<variable::Journal<E, ReverseNode<V>>>,
    head: Option<u64>,
    reading: bool,
    dirty: bool,
}

impl<E, V> ReverseStack<E, V>
where
    E: Context,
    V: CodecShared,
{
    async fn init(context: E, config: variable::Config<V::Cfg>) -> Result<Self, Error> {
        let journal = variable::Journal::init(context, config)
            .await?
            .clear()
            .await?;
        Ok(Self {
            journal: Some(journal),
            head: None,
            reading: false,
            dirty: false,
        })
    }

    async fn reset(&mut self) -> Result<(), Error> {
        if self.journal.is_none() {
            return Err(Error::Poisoned);
        }
        if self.dirty {
            let journal = self.journal.take().ok_or(Error::Poisoned)?;
            self.journal = Some(journal.clear().await?);
            self.dirty = false;
        }
        self.head = None;
        self.reading = false;
        Ok(())
    }

    async fn push(&mut self, value: V) -> Result<(), Error> {
        if self.reading {
            return Err(Error::Reading);
        }
        let journal = self.journal.take().ok_or(Error::Poisoned)?;
        let node = ReverseNode {
            newer: self.head,
            value,
        };
        let (journal, offset, _) = journal.append(0, &node).await?;
        self.journal = Some(journal);
        self.head = Some(offset);
        self.dirty = true;
        Ok(())
    }

    async fn read_oldest(&mut self) -> Result<Option<V>, Error> {
        self.reading = true;
        let Some(offset) = self.head else {
            return Ok(None);
        };
        let node = self
            .journal
            .as_ref()
            .ok_or(Error::Poisoned)?
            .get(0, offset)
            .await?;
        self.head = node.newer;
        Ok(Some(node.value))
    }
}

/// Disk-backed scratch storage whose newest-first history writes are read oldest-first.
pub(in crate::multimmit::marshal) struct HistoryScratch<E, H>
where
    E: Context,
    H: Hasher,
{
    stack: ReverseStack<E, HistoryValue<H>>,
}

impl<E, H> HistoryScratch<E, H>
where
    E: Context,
    H: Hasher,
{
    /// Opens empty scratch storage after discarding any recovered residue.
    pub(in crate::multimmit::marshal) async fn init(
        context: E,
        config: variable::Config<usize>,
    ) -> Result<Self, Error> {
        Ok(Self {
            stack: ReverseStack::init(context, config).await?,
        })
    }

    async fn push_inner(&mut self, link: HistoryLink<H>) -> Result<(), Error> {
        if link.record.commitment::<H>() != link.commitment {
            return Err(Error::Commitment);
        }
        self.stack.push(Shared::new(link.record)).await
    }

    async fn read_reverse_inner(&mut self) -> Result<Option<HistoryLink<H>>, Error> {
        let Some(record) = self.stack.read_oldest().await?.map(Shared::into_inner) else {
            return Ok(None);
        };
        Ok(Some(HistoryLink {
            commitment: record.commitment::<H>(),
            record,
        }))
    }
}

/// Scratch storage whose producer references are read oldest-first per chain.
///
/// A bounded live walk stays in memory. Crossing the journal's write-buffer budget spills the
/// compact reference plan to disk, so an arbitrarily long backfill retains bounded memory use.
pub(in crate::multimmit::marshal) struct BlockScratch<E, D>
where
    E: Context,
    D: Digest,
{
    journal: Option<variable::Journal<E, ReverseNode<BlockRef<D>>>>,
    heads: Vec<Option<u64>>,
    memory: Vec<Vec<BlockRef<D>>>,
    memory_bytes: usize,
    memory_limit: usize,
    reading: bool,
    dirty: bool,
}

impl<E, D> BlockScratch<E, D>
where
    E: Context,
    D: Digest,
{
    /// Opens empty scratch storage after discarding any recovered residue.
    pub(in crate::multimmit::marshal) async fn init(
        context: E,
        config: variable::Config<()>,
    ) -> Result<Self, Error> {
        let memory_limit = config.write_buffer.get();
        let journal = variable::Journal::init(context, config)
            .await?
            .clear()
            .await?;
        Ok(Self {
            journal: Some(journal),
            heads: Vec::new(),
            memory: Vec::new(),
            memory_bytes: 0,
            memory_limit,
            reading: false,
            dirty: false,
        })
    }

    /// Discards the current logical segment and returns to write mode.
    pub(in crate::multimmit::marshal) async fn reset(&mut self) -> Result<(), Error> {
        if self.journal.is_none() {
            return Err(Error::Poisoned);
        }
        if self.dirty {
            let journal = self.journal.take().ok_or(Error::Poisoned)?;
            self.journal = Some(journal.clear().await?);
            self.dirty = false;
        }
        self.heads.clear();
        self.memory.clear();
        self.memory_bytes = 0;
        self.reading = false;
        Ok(())
    }

    async fn push_disk(&mut self, chain: usize, block: BlockRef<D>) -> Result<(), Error> {
        if self.heads.len() <= chain {
            self.heads.resize(chain + 1, None);
        }
        let node = ReverseNode {
            newer: self.heads[chain],
            value: block,
        };
        let journal = self.journal.take().ok_or(Error::Poisoned)?;
        let (journal, offset, _) = journal.append(chain as u64, &node).await?;
        self.journal = Some(journal);
        self.heads[chain] = Some(offset);
        self.dirty = true;
        Ok(())
    }

    async fn spill(&mut self) -> Result<(), Error> {
        let memory = mem::take(&mut self.memory);
        self.memory_bytes = 0;
        for (chain, blocks) in memory.into_iter().enumerate() {
            for block in blocks {
                self.push_disk(chain, block).await?;
            }
        }
        Ok(())
    }

    /// Pushes one producer block in newest-first traversal order.
    pub(in crate::multimmit::marshal) async fn push(
        &mut self,
        block: BlockRef<D>,
    ) -> Result<(), Error> {
        if self.reading {
            return Err(Error::Reading);
        }
        let chain = block.chain().get() as usize;
        let encoded = block.encode_size().saturating_add(Some(0u64).encode_size());
        if !self.dirty
            && let Some(total) = self.memory_bytes.checked_add(encoded)
            && total <= self.memory_limit
        {
            if self.memory.len() <= chain {
                self.memory.resize_with(chain + 1, Vec::new);
            }
            self.memory[chain].push(block);
            self.memory_bytes = total;
            return Ok(());
        }
        if !self.dirty {
            self.spill().await?;
        }
        self.push_disk(chain, block).await
    }

    /// Reads the next producer block in oldest-first order.
    pub(in crate::multimmit::marshal) async fn read_oldest(
        &mut self,
        chain: usize,
    ) -> Result<Option<BlockRef<D>>, Error> {
        self.reading = true;
        if !self.dirty {
            return Ok(self.memory.get_mut(chain).and_then(Vec::pop));
        }
        let Some(offset) = self.heads.get(chain).copied().flatten() else {
            return Ok(None);
        };
        let node = self
            .journal
            .as_ref()
            .ok_or(Error::Poisoned)?
            .get(chain as u64, offset)
            .await?;
        self.heads[chain] = node.newer;
        Ok(Some(node.value))
    }
}

impl<E, D> BlockStack<D> for BlockScratch<E, D>
where
    E: Context,
    D: Digest,
{
    type Error = Error;

    fn reset(&mut self) -> impl Future<Output = Result<(), Self::Error>> + Send {
        Self::reset(self)
    }

    fn push(&mut self, block: BlockRef<D>) -> impl Future<Output = Result<(), Self::Error>> + Send {
        Self::push(self, block)
    }

    fn read_oldest(
        &mut self,
        chain: usize,
    ) -> impl Future<Output = Result<Option<BlockRef<D>>, Self::Error>> + Send {
        Self::read_oldest(self, chain)
    }
}

impl<E, H> HistoryStack<H> for HistoryScratch<E, H>
where
    E: Context,
    H: Hasher,
{
    type Error = Error;

    fn reset(&mut self) -> impl Future<Output = Result<(), Self::Error>> + Send {
        self.stack.reset()
    }

    fn push(
        &mut self,
        link: HistoryLink<H>,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        self.push_inner(link)
    }

    fn read_reverse(
        &mut self,
    ) -> impl Future<Output = Result<Option<HistoryLink<H>>, Self::Error>> + Send {
        self.read_reverse_inner()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        multimmit::types::{BlockRef, ChainId},
        types::Height,
    };
    use commonware_cryptography::{Sha256, sha256::Digest as Sha256Digest};
    use commonware_runtime::{
        Runner as _, Supervisor as _,
        buffer::paged::CacheRef,
        deterministic::{self, Context as DeterministicContext},
    };
    use commonware_utils::{NZU16, NZUsize};
    use std::sync::Arc;

    type TestScratch = HistoryScratch<DeterministicContext, Sha256>;
    type TestJournal = variable::Journal<DeterministicContext, ReverseNode<HistoryValue<Sha256>>>;
    type TestBlockScratch = BlockScratch<DeterministicContext, Sha256Digest>;

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

    fn digest(label: &[u8], marker: u64) -> Sha256Digest {
        Sha256::hash(&[label, &marker.to_be_bytes()])
    }

    fn link(marker: u64) -> HistoryLink<Sha256> {
        let record = Arc::new(
            TipRecord::new(
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

    #[test]
    fn very_long_stack_is_oldest_first_without_sync() {
        const LINKS: u64 = 10_000;
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let mut scratch = TestScratch::init(
                context.child("long_stack"),
                config(&context, "history_scratch_long", 1),
            )
            .await
            .unwrap();
            for marker in 0..LINKS {
                scratch.push(link(marker)).await.unwrap();
            }
            for expected in (0..LINKS).rev() {
                let actual = scratch.read_reverse().await.unwrap().unwrap();
                assert_eq!(actual.record.tips()[0].height(), Height::new(expected));
                assert_eq!(actual.commitment, actual.record.commitment::<Sha256>());
            }
            assert!(scratch.read_reverse().await.unwrap().is_none());
            assert!(matches!(scratch.push(link(0)).await, Err(Error::Reading)));
        });
    }

    #[test]
    fn reset_and_reopen_discard_every_prior_segment() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let cfg = config(&context, "history_scratch_reset", 1);
            let mut scratch = TestScratch::init(context.child("first"), cfg.clone())
                .await
                .unwrap();
            for marker in 0..130 {
                scratch.push(link(marker)).await.unwrap();
            }
            assert!(scratch.read_reverse().await.unwrap().is_some());
            scratch.reset().await.unwrap();
            assert!(scratch.read_reverse().await.unwrap().is_none());
            scratch.reset().await.unwrap();
            scratch.push(link(900)).await.unwrap();
            drop(scratch);

            let mut reopened = TestScratch::init(context.child("second"), cfg)
                .await
                .unwrap();
            assert!(reopened.read_reverse().await.unwrap().is_none());
            reopened.reset().await.unwrap();
            reopened.push(link(901)).await.unwrap();
            assert_eq!(
                reopened
                    .read_reverse()
                    .await
                    .unwrap()
                    .unwrap()
                    .record
                    .tips()[0]
                    .height(),
                Height::new(901)
            );
        });
    }

    #[test]
    fn durable_reset_survives_a_logically_empty_reopen() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let cfg = config(&context, "history_scratch_durable_reset", 1);
            let mut scratch = TestScratch::init(context.child("before_reset"), cfg.clone())
                .await
                .unwrap();
            for marker in 0..8 {
                scratch.push(link(marker)).await.unwrap();
            }
            let journal = scratch.stack.journal.take().unwrap();
            scratch.stack.journal = Some(journal.sync_all().await.unwrap());
            scratch.reset().await.unwrap();
            assert!(scratch.read_reverse().await.unwrap().is_none());
            drop(scratch);

            let mut reopened = TestScratch::init(context.child("after_reset"), cfg)
                .await
                .unwrap();
            assert!(reopened.read_reverse().await.unwrap().is_none());
            reopened.reset().await.unwrap();
            reopened.push(link(8)).await.unwrap();
            assert_eq!(
                reopened
                    .read_reverse()
                    .await
                    .unwrap()
                    .unwrap()
                    .record
                    .tips()[0]
                    .height(),
                Height::new(8)
            );
        });
    }

    #[test]
    fn initialization_hides_durable_crash_residue() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let cfg = config(&context, "history_scratch_recovery", 1);
            let journal = TestJournal::init(context.child("seed"), cfg.clone())
                .await
                .unwrap();
            let mut journal = journal;
            let mut head = None;
            for marker in 70..=77 {
                let stale = link(marker);
                let node = ReverseNode {
                    newer: head,
                    value: Shared::new(stale.record),
                };
                let (next, offset, _) = journal.append(0, &node).await.unwrap();
                journal = next;
                head = Some(offset);
            }
            drop(journal.sync_all().await.unwrap());

            let mut scratch = TestScratch::init(context.child("recover"), cfg)
                .await
                .unwrap();
            assert!(scratch.read_reverse().await.unwrap().is_none());
            scratch.reset().await.unwrap();
            let cfg = config(&context, "history_scratch_recovery", 1);
            drop(scratch);

            let mut scratch = TestScratch::init(context.child("recover_empty"), cfg)
                .await
                .unwrap();
            assert!(scratch.read_reverse().await.unwrap().is_none());
            scratch.reset().await.unwrap();
            scratch.push(link(78)).await.unwrap();
            assert_eq!(
                scratch.read_reverse().await.unwrap().unwrap().record.tips()[0].height(),
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
                config(&context, "history_scratch_overflow", 1),
            )
            .await
            .unwrap();
            let mut invalid = link(1);
            invalid.commitment = digest(b"wrong commitment", 1);
            assert!(matches!(
                scratch.push(invalid).await,
                Err(Error::Commitment)
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
            )
            .await
            .unwrap();
            let newest = reference(0, 3, 3);
            let middle = reference(0, 2, 2);
            let oldest = reference(0, 1, 1);
            let expected = [oldest, middle, newest];

            for reference in [newest, middle, oldest] {
                scratch.push(reference).await.unwrap();
            }
            assert!(!scratch.dirty);
            for expected in expected {
                assert_eq!(scratch.read_oldest(0).await.unwrap().unwrap(), expected);
            }
            assert!(scratch.read_oldest(0).await.unwrap().is_none());
            assert!(matches!(
                scratch.push(reference(0, 1, 1)).await,
                Err(Error::Reading)
            ));
        });
    }

    #[test]
    fn block_scratch_reopen_hides_durable_residue() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let stale = reference(0, 1, 1);
            let mut cfg = config(&context, "block_scratch_reopen", ());
            cfg.write_buffer = std::num::NonZeroUsize::new(stale.encode_size()).unwrap();
            let mut scratch = TestBlockScratch::init(context.child("first"), cfg.clone())
                .await
                .unwrap();
            scratch.push(stale).await.unwrap();
            assert!(scratch.dirty);
            let journal = scratch.journal.take().unwrap();
            scratch.journal = Some(journal.sync_all().await.unwrap());
            drop(scratch);

            let mut reopened = TestBlockScratch::init(context.child("second"), cfg)
                .await
                .unwrap();
            assert!(reopened.read_oldest(0).await.unwrap().is_none());
            reopened.reset().await.unwrap();
            let current = reference(0, 2, 2);
            let current_reference = current;
            reopened.push(current).await.unwrap();
            assert_eq!(
                reopened.read_oldest(0).await.unwrap().unwrap(),
                current_reference
            );
        });
    }

    #[test]
    fn block_scratch_spills_without_changing_chain_order() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let newest = reference(0, 2, 2);
            let newest_reference = newest;
            let oldest = reference(0, 1, 1);
            let oldest_reference = oldest;
            let mut cfg = config(&context, "block_scratch_spill", ());
            cfg.write_buffer = std::num::NonZeroUsize::new(
                newest
                    .encode_size()
                    .saturating_add(Some(0u64).encode_size()),
            )
            .unwrap();
            let mut scratch = TestBlockScratch::init(context.child("spill"), cfg)
                .await
                .unwrap();

            scratch.push(newest).await.unwrap();
            scratch.push(oldest).await.unwrap();

            assert!(scratch.dirty);
            assert!(scratch.memory.is_empty());
            assert_eq!(
                scratch.read_oldest(0).await.unwrap().unwrap(),
                oldest_reference
            );
            assert_eq!(
                scratch.read_oldest(0).await.unwrap().unwrap(),
                newest_reference
            );
            assert!(scratch.read_oldest(0).await.unwrap().is_none());
        });
    }

    #[test]
    fn block_scratch_reset_discards_partial_reads() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let mut scratch = TestBlockScratch::init(
                context.child("block_reset"),
                config(&context, "block_scratch_reset", ()),
            )
            .await
            .unwrap();
            for height in (1..=3).rev() {
                scratch.push(reference(0, height, height)).await.unwrap();
            }
            assert!(scratch.read_oldest(0).await.unwrap().is_some());
            scratch.reset().await.unwrap();
            assert!(scratch.read_oldest(0).await.unwrap().is_none());

            scratch.reset().await.unwrap();
            let only = reference(0, 4, 4);
            let only_reference = only;
            scratch.push(only).await.unwrap();
            assert_eq!(
                scratch.read_oldest(0).await.unwrap().unwrap(),
                only_reference
            );
        });
    }
}
