//! The sliding custody window that resolves the custody of every planned output in order.

use super::{
    actor::Core,
    inbox::Absorb,
    mailbox::Error,
    ports::{CatalogPort, Fetcher},
    publish::PublicationBatch,
};
use crate::{
    Epochable as _,
    multimmit::{
        marshal::{
            actors::{backfill::CustodiedBlock, metrics::FetchReason},
            protocol::{order::Slot, paths::Branch},
            storage::{
                commit::CustodyRef,
                scratch::{BlockStack, HistoryStack},
            },
            types::{CustodyValues, LqcVerifier},
        },
        types::{BlockRef, Body, TransactionBlock},
    },
    types::Epoch,
};
use commonware_cryptography::{Digest, Hasher, bls12381::primitives::variant::Variant};
use commonware_macros::select;
use commonware_utils::futures::Pool;
use std::{
    collections::{BTreeMap, VecDeque},
    future::Future,
    sync::Arc,
};

/// Maximum number of catalog custody lookups in flight at once within one custody window.
pub(crate) const CUSTODY_LOOKUP_CONCURRENCY: usize = 2;

/// A completed catalog custody lookup for consecutive staged outputs.
pub(super) struct CustodyLookup<D: Digest> {
    /// Sequence number of the first output looked up.
    pub start: usize,
    /// Number of outputs looked up.
    pub count: usize,
    pub result: Result<CustodyValues<D>, Error>,
}

/// A completed peer fetch for one run of outputs missing from local custody.
pub(super) struct CustodyFetch<H: Hasher, B: Body<H>> {
    pub run: MissingRun<H::Digest>,
    pub result: Result<Vec<CustodiedBlock<H, B>>, Error>,
}

/// A completed lookup or fetch of a custody window.
pub(super) enum Completion<H: Hasher, B: Body<H>> {
    Lookup(CustodyLookup<H::Digest>),
    Fetch(CustodyFetch<H, B>),
}

/// One planned output in the custody window, waiting for its custody.
struct StagedOutput<H: Hasher, B: Body<H>> {
    /// Position of the output in the window's ordering stream.
    sequence: usize,
    slot: Slot<H::Digest>,
    reference: BlockRef<H::Digest>,
    /// Custody, once a catalog lookup or peer fetch has resolved it.
    custody: Option<CustodyRef<H::Digest>>,
    /// Body retained from a peer fetch, handed to delivery after publication.
    block: Option<Arc<TransactionBlock<H, B>>>,
}

/// A staged output that local custody does not hold.
pub(super) struct MissingOutput<D: Digest> {
    /// Position of the output in the window's ordering stream.
    pub sequence: usize,
    pub reference: BlockRef<D>,
}

/// One page-local consecutive producer run, retained oldest-first.
pub(super) struct MissingRun<D: Digest> {
    pub outputs: Vec<MissingOutput<D>>,
}

impl<D: Digest> MissingRun<D> {
    fn references_newest_first(&self) -> Vec<BlockRef<D>> {
        self.outputs
            .iter()
            .rev()
            .map(|output| output.reference)
            .collect()
    }
}

/// The next output of the window whose custody is resolved.
pub(super) struct ReadyOutput<H: Hasher, B: Body<H>> {
    pub slot: Slot<H::Digest>,
    pub custody: CustodyRef<H::Digest>,
    /// Body retained from a peer fetch, if any.
    pub block: Option<Arc<TransactionBlock<H, B>>>,
}

/// The sizes of a custody window and its work.
pub(super) struct WindowBounds {
    /// Maximum number of outputs in the window.
    pub capacity: usize,
    /// Maximum number of outputs in one catalog lookup.
    pub batch: usize,
    /// Maximum number of blocks in one peer fetch.
    pub max_fetch: usize,
    /// Maximum number of peer fetches in flight.
    pub max_fetches: usize,
}

/// A window of planned outputs whose custody is resolved out of order but emitted in order.
///
/// Outputs enter in ordering-stream order. Unscheduled outputs are looked up in the catalog in
/// pages of up to `batch` outputs, at most [`CUSTODY_LOOKUP_CONCURRENCY`] lookups at once. Outputs
/// the catalog misses form consecutive per-chain runs of at most `max_fetch` blocks, fetched from
/// peers at most `max_fetches` at once. Only the contiguous resolved prefix leaves the window.
pub(super) struct CustodyWindow<H: Hasher, B: Body<H>> {
    staged: VecDeque<StagedOutput<H, B>>,
    lookups: Pool<'static, CustodyLookup<H::Digest>>,
    fetches: Pool<'static, CustodyFetch<H, B>>,
    missing: VecDeque<MissingRun<H::Digest>>,
    /// Sequence number of the next output to enter.
    next_sequence: usize,
    /// Outputs that entered but are not yet looked up.
    unscheduled: usize,
    /// Whether the ordering stream is exhausted.
    finished: bool,
    /// Resolved outputs still in the window.
    ready: usize,
    /// Whether resolved outputs wait behind an unresolved prefix.
    blocked: bool,
    epoch: Epoch,
    bounds: WindowBounds,
}

impl<H: Hasher, B: Body<H>> CustodyWindow<H, B> {
    pub(super) fn new(epoch: Epoch, bounds: WindowBounds) -> Self {
        Self {
            staged: VecDeque::with_capacity(bounds.capacity),
            lookups: Pool::default(),
            fetches: Pool::default(),
            missing: VecDeque::new(),
            next_sequence: 0,
            unscheduled: 0,
            finished: false,
            ready: 0,
            blocked: false,
            epoch,
            bounds,
        }
    }

    /// Returns whether another output may enter.
    pub(super) fn has_room(&self) -> bool {
        self.staged.len() < self.bounds.capacity && !self.finished
    }

    /// Adds the next planned output of the ordering stream.
    pub(super) fn push(
        &mut self,
        slot: Slot<H::Digest>,
        reference: BlockRef<H::Digest>,
    ) -> Result<(), Error> {
        self.staged.push_back(StagedOutput {
            sequence: self.next_sequence,
            slot,
            reference,
            custody: None,
            block: None,
        });
        self.next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or(Error::OutputExhausted)?;
        self.unscheduled += 1;
        Ok(())
    }

    /// Records that the ordering stream is exhausted.
    pub(super) const fn finish(&mut self) {
        self.finished = true;
    }

    /// Starts catalog lookups for unscheduled outputs: full batches, or the remainder once the
    /// stream is exhausted.
    pub(super) fn schedule_lookups<L, Fut>(&mut self, mut lookup: L) -> Result<(), Error>
    where
        L: FnMut(Vec<BlockRef<H::Digest>>) -> Fut,
        Fut: Future<Output = Result<CustodyValues<H::Digest>, Error>> + Send + 'static,
    {
        while self.lookups.len() < CUSTODY_LOOKUP_CONCURRENCY
            && (self.unscheduled >= self.bounds.batch || (self.finished && self.unscheduled > 0))
        {
            let count = self.unscheduled.min(self.bounds.batch);
            let start = self.next_sequence - self.unscheduled;
            let references = self.references(start, count)?;
            let lookup = lookup(references);
            self.lookups.push(async move {
                CustodyLookup {
                    start,
                    count,
                    result: lookup.await,
                }
            });
            self.unscheduled -= count;
        }
        Ok(())
    }

    /// Starts peer fetches for missing runs while fetch slots are free.
    pub(super) fn schedule_fetches<G, Fut>(&mut self, mut fetch: G)
    where
        G: FnMut(Vec<BlockRef<H::Digest>>) -> Fut,
        Fut: Future<Output = Result<Vec<CustodiedBlock<H, B>>, Error>> + Send + 'static,
    {
        while self.fetches.len() < self.bounds.max_fetches {
            let Some(run) = self.missing.pop_front() else {
                break;
            };
            let fetch = fetch(run.references_newest_first());
            self.fetches.push(async move {
                CustodyFetch {
                    run,
                    result: fetch.await,
                }
            });
        }
    }

    /// Takes the next output if every output before it has left the window.
    pub(super) fn pop_ready(&mut self) -> Option<ReadyOutput<H, B>> {
        let output = self
            .staged
            .pop_front_if(|output| output.custody.is_some())?;
        self.ready -= 1;
        self.blocked = false;
        Some(ReadyOutput {
            slot: output.slot,
            custody: output.custody.expect("a ready output has custody"),
            block: output.block,
        })
    }

    /// Returns whether every output of the exhausted stream has left the window.
    pub(super) fn is_done(&self) -> bool {
        self.finished && self.staged.is_empty()
    }

    /// Returns whether outputs remain but no lookup or fetch can resolve them.
    pub(super) fn is_stalled(&self) -> bool {
        self.lookups.is_empty()
            && self.fetches.is_empty()
            && self.missing.is_empty()
            && self.unscheduled == 0
    }

    /// Records that resolved outputs wait behind an unresolved prefix, returning whether they
    /// just started waiting.
    pub(super) const fn block(&mut self) -> bool {
        let started = self.ready > 0 && !self.blocked;
        if started {
            self.blocked = true;
        }
        started
    }

    /// Waits for the next lookup or fetch to complete, preferring lookups. Pends while none is
    /// in flight.
    pub(super) async fn next_completion(&mut self) -> Completion<H, B> {
        select! {
            lookup = self.lookups.next_completed() => Completion::Lookup(lookup),
            fetch = self.fetches.next_completed() => Completion::Fetch(fetch),
        }
    }

    /// Returns the number of lookups in flight.
    pub(super) fn lookups(&self) -> usize {
        self.lookups.len()
    }

    /// Returns the number of fetches in flight.
    pub(super) fn fetches(&self) -> usize {
        self.fetches.len()
    }

    /// Returns the number of resolved outputs still in the window.
    pub(super) const fn ready(&self) -> usize {
        self.ready
    }

    /// Applies a catalog lookup, returning how many outputs it resolved.
    pub(super) fn on_lookup(&mut self, lookup: CustodyLookup<H::Digest>) -> Result<usize, Error> {
        let CustodyLookup {
            start,
            count,
            result,
        } = lookup;
        let custody = result?;
        if custody.len() != count {
            return Err(Error::Invalid("catalog block batch cardinality mismatch"));
        }
        let epoch = self.epoch;
        let max_fetch = self.bounds.max_fetch;
        let mut runs = BTreeMap::<_, MissingRun<H::Digest>>::new();
        let mut local = 0usize;
        for (offset, custody) in custody.into_iter().enumerate() {
            let sequence = start.checked_add(offset).ok_or(Error::OutputExhausted)?;
            let reference = self.output_mut(sequence)?.reference;
            if let Some(custody) = custody {
                if let Some(run) = runs.remove(&reference.chain()) {
                    self.missing.push_back(run);
                }
                // The catalog returns custody for exactly the requested references.
                debug_assert!(describes::<H>(&custody, reference, epoch));
                self.output_mut(sequence)?.custody = Some(custody);
                local += 1;
            } else {
                let chain = reference.chain();
                let extends = runs.get(&chain).is_some_and(|run| {
                    run.outputs.len() < max_fetch
                        && run.outputs.last().is_some_and(|previous| {
                            previous.reference.height().get().checked_add(1)
                                == Some(reference.height().get())
                        })
                });
                if !extends && let Some(run) = runs.remove(&chain) {
                    self.missing.push_back(run);
                }
                runs.entry(chain)
                    .or_insert_with(|| MissingRun {
                        outputs: Vec::with_capacity(max_fetch.min(count)),
                    })
                    .outputs
                    .push(MissingOutput {
                        sequence,
                        reference,
                    });
            }
        }
        self.missing.extend(runs.into_values());
        self.ready += local;
        Ok(local)
    }

    /// Applies a peer fetch for a missing run, returning how many outputs it resolved.
    ///
    /// Outputs the fetch did not return form a shorter run that is fetched again.
    pub(super) fn on_fetch(&mut self, fetch: CustodyFetch<H, B>) -> Result<usize, Error> {
        let CustodyFetch { run, result } = fetch;
        let fetched_blocks = result?;
        // The fetcher returns a non-empty prefix of the run, newest first.
        debug_assert!(!fetched_blocks.is_empty() && fetched_blocks.len() <= run.outputs.len());
        let fetched = fetched_blocks.len();
        for (output, fetched) in run.outputs.iter().rev().zip(fetched_blocks) {
            debug_assert_eq!(fetched.reference(), output.reference);
            let (custody, block) = fetched.into_parts();
            debug_assert!(describes::<H>(&custody, output.reference, self.epoch));
            let staged = self.output_mut(output.sequence)?;
            staged.custody = Some(custody);
            staged.block = Some(block);
        }
        let remaining = run.outputs.len() - fetched;
        if remaining > 0 {
            self.missing.push_back(MissingRun {
                outputs: run.outputs.into_iter().take(remaining).collect(),
            });
        }
        self.ready += fetched;
        Ok(fetched)
    }

    /// Returns the references of `count` staged outputs starting at sequence `start`.
    fn references(&self, start: usize, count: usize) -> Result<Vec<BlockRef<H::Digest>>, Error> {
        let first = self
            .staged
            .front()
            .ok_or(Error::Invalid("custody window is empty"))?
            .sequence;
        let offset = start
            .checked_sub(first)
            .ok_or(Error::Invalid("custody lookup precedes its window"))?;
        let references = self
            .staged
            .iter()
            .skip(offset)
            .take(count)
            .map(|output| output.reference)
            .collect::<Vec<_>>();
        (references.len() == count)
            .then_some(references)
            .ok_or(Error::Invalid("custody lookup exceeds its window"))
    }

    /// Returns the staged output with sequence `sequence`.
    fn output_mut(&mut self, sequence: usize) -> Result<&mut StagedOutput<H, B>, Error> {
        let first = self
            .staged
            .front()
            .ok_or(Error::Invalid("custody window is empty"))?
            .sequence;
        self.staged
            .get_mut(
                sequence
                    .checked_sub(first)
                    .ok_or(Error::Invalid("custody completion precedes its window"))?,
            )
            .ok_or(Error::Invalid("custody completion exceeds its window"))
    }
}

/// Returns whether `custody` is the durable row of block `reference` in `epoch`.
fn describes<H: Hasher>(
    custody: &CustodyRef<H::Digest>,
    reference: BlockRef<H::Digest>,
    epoch: Epoch,
) -> bool {
    let header = custody.meta().header();
    custody.reference() == reference
        && header.epoch() == epoch
        && header.block_ref::<H>() == reference
}

impl<I, C, F, S, K, Q, H, V, B> Core<I, C, F, S, K, Q, H, V, B>
where
    I: Absorb<V, H::Digest>,
    C: CatalogPort<H, V, B>,
    F: Fetcher<H, V, B>,
    S: HistoryStack<H>,
    K: BlockStack<H::Digest>,
    Q: LqcVerifier<H, V>,
    H: Hasher,
    V: Variant,
    B: Body<H>,
    Error: From<C::Error> + From<F::Error> + From<S::Error> + From<K::Error>,
{
    /// Resolves the custody of every output `stream` plans above `emitted` and adds them to
    /// `batch` in order.
    ///
    /// `forward` gives each chain's authenticated path where the walk found one; other chains
    /// read their references from the block stack, which must be empty afterwards.
    #[tracing::instrument(
        name = "multimmit.marshal.synchronizer.resolve_custody",
        level = "info",
        skip_all,
        fields(
            window = self.bounds.custody_window_outputs,
            batch = self.bounds.custody_batch_outputs,
        )
    )]
    pub(super) async fn drive<J>(
        &mut self,
        stream: &mut J,
        emitted: &[BlockRef<H::Digest>],
        forward: &[Option<Branch<H::Digest>>],
        batch: &mut PublicationBatch<H, V, B>,
    ) -> Result<(), Error>
    where
        J: Iterator<Item = Slot<H::Digest>>,
    {
        let mut window = CustodyWindow::new(
            self.epoch,
            WindowBounds {
                capacity: self.bounds.custody_window_outputs,
                batch: self.bounds.custody_batch_outputs,
                max_fetch: self.bounds.max_fetch_blocks,
                max_fetches: self.bounds.backfill_concurrency,
            },
        );
        self.metrics.windows.inc();
        loop {
            let mut planned = 0u64;
            while window.has_room() {
                match self.next_staged(stream, emitted, forward).await? {
                    Some(StagedSlot { slot, reference }) => {
                        window.push(slot, reference)?;
                        planned += 1;
                    }
                    None => window.finish(),
                }
            }
            self.metrics.planned_outputs.inc_by(planned);
            window.schedule_lookups(|references| {
                let lookup = self.catalog.wait_for_custody(references);
                async move { lookup.await.map_err(Error::from) }
            })?;
            window.schedule_fetches(|references| {
                let mut fetcher = self.fetcher.clone();
                async move {
                    fetcher
                        .blocks(FetchReason::FinalizedBody, references)
                        .await
                        .map_err(Error::from)
                }
            });

            let mut emitted_any = false;
            while let Some(ready) = window.pop_ready() {
                self.emit_output(ready.slot, ready.custody, ready.block, batch)
                    .await?;
                emitted_any = true;
            }
            if emitted_any {
                continue;
            }
            if window.is_done() {
                break;
            }
            if window.is_stalled() {
                return Err(Error::Invalid("planned output custody is missing"));
            }
            if window.block() {
                self.metrics.blocked_prefixes.inc();
            }
            self.metrics
                .pressure(window.lookups(), window.fetches(), window.ready());

            select! {
                completion = window.next_completion() => match completion {
                    Completion::Lookup(lookup) => {
                        let local = window.on_lookup(lookup)?;
                        self.metrics
                            .local_outputs
                            .inc_by(u64::try_from(local).unwrap_or(u64::MAX));
                    }
                    Completion::Fetch(fetch) => {
                        let fetched = window.on_fetch(fetch)?;
                        self.metrics
                            .fetched_outputs
                            .inc_by(u64::try_from(fetched).unwrap_or(u64::MAX));
                    }
                },
                absorbed = self.inbox.absorb() => {
                    if let Some(absorbed) = absorbed? {
                        self.apply(absorbed);
                    }
                },
            }
        }
        self.metrics.pressure(0, 0, 0);
        for chain in 0..emitted.len() {
            if self.block_stack.read_oldest(chain).await?.is_some() {
                return Err(Error::Invalid(
                    "staged producer block is outside the ordering stream",
                ));
            }
        }
        Ok(())
    }

    /// Returns the next slot of `stream` above `emitted`, with its producer reference.
    async fn next_staged<J>(
        &mut self,
        stream: &mut J,
        emitted: &[BlockRef<H::Digest>],
        forward: &[Option<Branch<H::Digest>>],
    ) -> Result<Option<StagedSlot<H::Digest>>, Error>
    where
        J: Iterator<Item = Slot<H::Digest>>,
    {
        for slot in stream {
            let chain = slot.tip().chain().get() as usize;
            let frontier = emitted.get(chain).ok_or(Error::Invalid(
                "ordering slot chain is outside the frontier",
            ))?;
            if slot.height() <= frontier.height() {
                continue;
            }
            let reference = match forward.get(chain).and_then(Option::as_ref) {
                Some(path) => path.get(slot.height()),
                None => self.block_stack.read_oldest(chain).await?,
            }
            .ok_or(Error::Invalid(
                "ordering slot is missing its producer commitment",
            ))?;
            return Ok(Some(StagedSlot { slot, reference }));
        }
        Ok(None)
    }
}

/// A slot of the ordering stream with the producer reference that fills it.
struct StagedSlot<D: Digest> {
    slot: Slot<D>,
    reference: BlockRef<D>,
}
