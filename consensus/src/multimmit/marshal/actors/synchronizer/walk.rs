//! Concurrent producer-chain ancestry walks toward the common frontiers of a pass.

use super::{
    actor::Core,
    inbox::Absorb,
    mailbox::Error,
    ports::{CatalogPort, Fetcher, HeaderSegments},
};
use crate::{
    multimmit::{
        marshal::{
            actors::{backfill::SharedHeaders, metrics::FetchReason},
            protocol::{
                ancestry::{self, Ancestry},
                paths::Branch,
            },
            storage::scratch::{BlockStack, HistoryStack},
            types::LqcVerifier,
            wire::MAX_SEGMENT_ITEMS,
        },
        types::{BlockRef, Body, TransactionBlockHeader},
    },
    types::Height,
};
use commonware_cryptography::{Digest, Hasher, bls12381::primitives::variant::Variant};
use commonware_macros::select;
use commonware_utils::futures::{AbortablePool, Aborter, OptionFuture};
use std::{cmp::Ordering, collections::VecDeque, future::Future, iter, mem};

/// One producer chain's ancestry walk and the references it stages for output.
pub(super) struct ProducerWalk<D: Digest> {
    ancestry: Ancestry<D>,
    /// Highest height the ordering stream will emit on this chain, if any.
    stage_max: Option<Height>,
    /// Height of this chain's emitted frontier; references at or below it are never staged.
    emitted: Height,
    /// History tips the walk must pass through, ascending by height.
    boundaries: Vec<BlockRef<D>>,
}

impl<D: Digest> ProducerWalk<D> {
    /// Starts the walk from `target` down to the common frontier with `emitted`.
    pub(super) fn new(
        target: BlockRef<D>,
        emitted: BlockRef<D>,
        stage_max: Option<Height>,
    ) -> Result<Self, ancestry::Error> {
        Ok(Self {
            ancestry: Ancestry::common(target, emitted)?,
            stage_max,
            emitted: emitted.height(),
            boundaries: Vec::new(),
        })
    }

    /// Starts one chain's walk across a window of history openings whose tips on the chain are
    /// `tips`, oldest first.
    ///
    /// The walk descends from the higher of the newest tip and `emitted` to the lower of the
    /// oldest tip and `emitted`, and must pass through every tip and `emitted`. It stages the
    /// references above `emitted` up to the newest tip.
    pub(super) fn window(
        tips: &[BlockRef<D>],
        emitted: BlockRef<D>,
        ordered: BlockRef<D>,
    ) -> Result<Self, Error> {
        let (Some(first), Some(target)) = (tips.first().copied(), tips.last().copied()) else {
            return Err(Error::Invalid("history window is empty"));
        };
        let high = match target.height().cmp(&emitted.height()) {
            Ordering::Greater => target,
            Ordering::Less => emitted,
            Ordering::Equal if target == emitted => target,
            Ordering::Equal => {
                return Err(Error::Invalid(
                    "history target conflicts with the emitted frontier",
                ));
            }
        };
        let low = match first.height().cmp(&emitted.height()) {
            Ordering::Less => first,
            Ordering::Greater => emitted,
            Ordering::Equal if first == emitted => first,
            Ordering::Equal => {
                return Err(Error::Invalid(
                    "first history target conflicts with the emitted frontier",
                ));
            }
        };
        if low.height() < ordered.height() {
            return Err(Error::Invalid(
                "history window precedes the ordering frontier",
            ));
        }
        let ancestry = Ancestry::common(high, low)?;
        let mut boundaries = Vec::with_capacity(tips.len() + 1);
        for reference in tips.iter().copied().chain(iter::once(emitted)) {
            if reference == low {
                continue;
            }
            if reference.height() <= low.height() {
                return Err(Error::Invalid(
                    "history boundary precedes the recovery interval",
                ));
            }
            boundaries.push(reference);
        }
        boundaries.sort_unstable_by_key(|reference| reference.height());
        if boundaries
            .windows(2)
            .any(|pair| pair[0].height() == pair[1].height() && pair[0] != pair[1])
        {
            return Err(Error::Invalid(
                "history boundaries conflict at one producer height",
            ));
        }
        boundaries.dedup_by_key(|reference| reference.height());
        Ok(Self {
            ancestry,
            stage_max: (target.height() > emitted.height()).then_some(target.height()),
            emitted: emitted.height(),
            boundaries,
        })
    }

    /// Returns the references the walk descends from and to.
    pub(super) const fn bounds(&self) -> ancestry::Bounds<D> {
        self.ancestry.bounds()
    }

    /// Returns whether `reference` is above the emitted frontier and within the ordering stream.
    fn stages(&self, reference: BlockRef<D>) -> bool {
        self.stage_max
            .is_some_and(|maximum| reference.height() <= maximum)
            && reference.height() > self.emitted
    }

    /// Checks `reference` against the history boundary at its height, if any.
    fn pass_boundary(&mut self, reference: BlockRef<D>) -> Result<(), Error> {
        if let Some(boundary) = self
            .boundaries
            .pop_if(|boundary| boundary.height() == reference.height())
            && boundary != reference
        {
            return Err(Error::Invalid(
                "producer ancestry conflicts with a history boundary",
            ));
        }
        Ok(())
    }
}

/// The result of walking every producer chain of a pass.
pub(super) struct WalkPlan<D: Digest> {
    /// Resolved common frontier on every chain.
    pub common: Vec<BlockRef<D>>,
    /// Authenticated forward path per chain, where the path cache already covered the walk.
    ///
    /// Chains without a path staged their references in the block stack.
    pub forward: Vec<Option<Branch<D>>>,
}

/// A completed header fetch for one producer ancestry walk.
struct ProducerFetch<D: Digest> {
    /// Index of the walk's producer chain.
    chain: usize,
    /// Newest header requested from peers.
    request: BlockRef<D>,
    result: Result<SharedHeaders<D>, Error>,
}

/// One walk whose next header is looked up in the catalog.
struct Scheduled<D: Digest> {
    chain: usize,
    request: BlockRef<D>,
    max_items: usize,
}

/// The state of one pass's ancestry walks.
///
/// Walks advance through known ancestry first: the path cache, then cached headers. Unknown
/// ancestry is looked up in the catalog in one batch at a time, and chains the catalog misses are
/// fetched from peers, at most `backfill_concurrency` at once. A header hint for a chain being
/// looked up or fetched advances it at once.
pub(super) struct AncestryWalker<D: Digest> {
    walks: Vec<ProducerWalk<D>>,
    /// Chains whose walk still needs a header, in rotation order.
    ready: VecDeque<usize>,
    fetches: AbortablePool<'static, ProducerFetch<D>>,
    /// Handle of each chain's peer fetch, if any.
    aborters: Vec<Option<Aborter>>,
    /// Walks covered by the catalog lookup in flight; empty when none is.
    scheduled: Vec<Scheduled<D>>,
    forward: Vec<Option<Branch<D>>>,
}

impl<D: Digest> AncestryWalker<D> {
    fn walk(&mut self, chain: usize) -> Result<&mut ProducerWalk<D>, Error> {
        self.walks.get_mut(chain).ok_or(Error::Invalid(
            "completed producer chain is outside the frontier",
        ))
    }

    /// Returns whether `chain`'s walk still needs `request`.
    fn needs(&self, chain: usize, request: BlockRef<D>) -> bool {
        self.walks
            .get(chain)
            .is_some_and(|walk| walk.ancestry.next() == Some(request))
    }

    /// Requeues `chain` if its walk still needs headers.
    fn requeue(&mut self, chain: usize) {
        if self.walks[chain].ancestry.next().is_some() {
            self.ready.push_back(chain);
        }
    }

    /// Forgets the lookup in flight once no walk still needs any of its requests, returning
    /// whether it did.
    ///
    /// A walk only moves toward older ancestors, so a lookup whose request has been passed cannot
    /// contribute to that walk, even if its catalog reply arrives later.
    fn drop_stale_lookup(&mut self) -> bool {
        let stale = !self.scheduled.is_empty()
            && self
                .scheduled
                .iter()
                .all(|scheduled| !self.needs(scheduled.chain, scheduled.request));
        if stale {
            self.scheduled.clear();
        }
        stale
    }

    /// Returns whether no walk needs a header and nothing is in flight.
    fn is_done(&self) -> bool {
        self.ready.is_empty() && self.fetches.is_empty() && self.scheduled.is_empty()
    }

    /// Returns the common frontiers and forward paths once every walk finished.
    fn finish(self) -> Result<WalkPlan<D>, Error> {
        let common = self
            .walks
            .into_iter()
            .map(|walk| {
                if !walk.boundaries.is_empty() {
                    return Err(Error::Invalid(
                        "producer ancestry did not reach every history boundary",
                    ));
                }
                walk.ancestry
                    .finish()
                    .ok_or(Error::Invalid("common-frontier walk did not finish"))
            })
            .collect::<Result<_, _>>()?;
        Ok(WalkPlan {
            common,
            forward: self.forward,
        })
    }
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
    /// Walks producer ancestry from `targets` to their common frontiers with `emitted`, staging
    /// the references at or below `stage_max` in the block stack.
    #[tracing::instrument(
        name = "multimmit.marshal.synchronizer.stage_ancestry",
        level = "debug",
        skip_all,
        fields(chains = targets.len())
    )]
    pub(super) async fn stage(
        &mut self,
        mut stage_max: Vec<Option<Height>>,
        targets: &[BlockRef<H::Digest>],
        emitted: &[BlockRef<H::Digest>],
    ) -> Result<WalkPlan<H::Digest>, Error> {
        if targets.len() != emitted.len() {
            return Err(Error::Invalid("frontier lengths differ"));
        }
        if stage_max.len() != targets.len() {
            return Err(Error::Invalid(
                "ordering and producer frontier lengths differ",
            ));
        }
        for ((maximum, target), emitted) in stage_max.iter_mut().zip(targets).zip(emitted) {
            if maximum.is_some_and(|height| height > target.height()) {
                return Err(Error::Invalid("ordering slot is outside resolved ancestry"));
            }
            if maximum.is_some_and(|height| height <= emitted.height()) {
                *maximum = None;
            }
        }
        let walks = targets
            .iter()
            .zip(emitted)
            .zip(stage_max)
            .map(|((target, emitted), stage_max)| ProducerWalk::new(*target, *emitted, stage_max))
            .collect::<Result<Vec<_>, ancestry::Error>>()?;
        self.walk(walks, FetchReason::Finality).await
    }

    /// Resolves the common frontiers of `targets` and `emitted` without staging anything.
    pub(super) async fn common_frontiers(
        &mut self,
        targets: &[BlockRef<H::Digest>],
        emitted: &[BlockRef<H::Digest>],
    ) -> Result<Vec<BlockRef<H::Digest>>, Error> {
        if targets.len() != emitted.len() {
            return Err(Error::Invalid("frontier lengths differ"));
        }
        let walks = targets
            .iter()
            .zip(emitted)
            .map(|(target, emitted)| ProducerWalk::new(*target, *emitted, None))
            .collect::<Result<Vec<_>, ancestry::Error>>()?;
        Ok(self.walk(walks, FetchReason::StateSync).await?.common)
    }

    /// Runs `walks` to completion.
    ///
    /// Resets the block stack first: it holds the references of exactly one walk, which the
    /// following custody window consumes.
    #[tracing::instrument(
        name = "multimmit.marshal.synchronizer.walk_producers",
        level = "debug",
        skip_all,
        fields(chains = walks.len(), reason = ?reason)
    )]
    pub(super) async fn walk(
        &mut self,
        walks: Vec<ProducerWalk<H::Digest>>,
        reason: FetchReason,
    ) -> Result<WalkPlan<H::Digest>, Error> {
        self.block_stack.reset().await?;
        let mut walker = self.start_walk(walks)?;
        let mut lookup = OptionFuture::default();
        loop {
            if walker.drop_stale_lookup() {
                *lookup = None;
            }
            let advanced = self.advance_known(&mut walker).await?;
            if lookup.is_none() && !walker.scheduled.is_empty() {
                *lookup = Some(Box::pin(self.lookup(&walker.scheduled)));
            }
            if advanced {
                continue;
            }
            if walker.is_done() {
                break;
            }
            select! {
                fetched = walker.fetches.next_completed() => {
                    let Ok(fetched) = fetched else { continue };
                    self.on_fetch(&mut walker, fetched).await?;
                },
                headers = &mut lookup => {
                    *lookup = None;
                    self.on_lookup(&mut walker, headers?, reason).await?;
                },
                absorbed = self.inbox.absorb() => {
                    let Some(absorbed) = absorbed? else { continue };
                    if let Some(reference) = self.apply(absorbed) {
                        self.on_header(&mut walker, reference).await?;
                    }
                },
            }
        }
        walker.finish()
    }

    /// Builds the walker, completing walks that the path cache already covers.
    fn start_walk(
        &self,
        mut walks: Vec<ProducerWalk<H::Digest>>,
    ) -> Result<AncestryWalker<H::Digest>, Error> {
        let mut forward = (0..self.codec.chains()).map(|_| None).collect::<Vec<_>>();
        for (chain, walk) in walks.iter_mut().enumerate() {
            let ancestry::Bounds { low, high } = walk.ancestry.bounds();
            let Some(path) = self.commitments.resolve(low, high) else {
                continue;
            };
            if walk
                .boundaries
                .iter()
                .any(|boundary| path.get(boundary.height()) != Some(*boundary))
            {
                return Err(Error::Invalid(
                    "producer ancestry conflicts with a history boundary",
                ));
            }
            walk.boundaries.clear();
            walk.ancestry = Ancestry::common(low, low)?;
            forward[chain] = Some(path);
        }
        let ready = walks
            .iter()
            .enumerate()
            .filter_map(|(chain, walk)| walk.ancestry.next().map(|_| chain))
            .collect();
        let aborters = (0..walks.len()).map(|_| None).collect();
        Ok(AncestryWalker {
            walks,
            ready,
            fetches: AbortablePool::default(),
            aborters,
            scheduled: Vec::new(),
            forward,
        })
    }

    /// Looks up the next headers of the `scheduled` walks in the catalog.
    fn lookup(
        &self,
        scheduled: &[Scheduled<H::Digest>],
    ) -> impl Future<Output = Result<HeaderSegments<H::Digest>, Error>> + Send + 'static {
        let lookup = self.catalog.header_segments(
            scheduled
                .iter()
                .map(|scheduled| (scheduled.request, scheduled.max_items))
                .collect(),
            usize::MAX,
        );
        async move { lookup.await.map_err(Error::from) }
    }

    /// Advances every ready walk once through known ancestry, and schedules a catalog lookup for
    /// the ready walks it cannot advance while no lookup is in flight.
    ///
    /// Returns whether any walk advanced.
    async fn advance_known(
        &mut self,
        walker: &mut AncestryWalker<H::Digest>,
    ) -> Result<bool, Error> {
        let available = if walker.scheduled.is_empty() {
            self.bounds
                .backfill_concurrency
                .saturating_sub(walker.fetches.len())
        } else {
            0
        };
        let mut requests = Vec::with_capacity(available.min(walker.ready.len()));
        let mut advanced = false;
        for _ in 0..walker.ready.len() {
            let chain = walker
                .ready
                .pop_front()
                .expect("the ready walk count is fixed");
            let request = walker.walks[chain]
                .ancestry
                .next()
                .ok_or(Error::Invalid("scheduled producer walk is complete"))?;
            if let Some(parent) = self.commitments.parent(request) {
                let walk = walker.walk(chain)?;
                walk.ancestry.accept_parent(parent)?;
                self.stage_reference(walk, request).await?;
                walker.requeue(chain);
                advanced = true;
            } else if let Some(header) = self.headers.get(&request).cloned() {
                let walk = walker.walk(chain)?;
                walk.ancestry.accept::<H>(self.epoch, &header)?;
                self.stage_reference(walk, request).await?;
                walker.requeue(chain);
                advanced = true;
            } else if requests.len() < available {
                requests.push(Scheduled {
                    chain,
                    request,
                    max_items: walker.walks[chain]
                        .ancestry
                        .remaining()
                        .min(MAX_SEGMENT_ITEMS),
                });
            } else {
                walker.ready.push_back(chain);
            }
        }
        if !requests.is_empty() {
            walker.scheduled = requests;
        }
        Ok(advanced)
    }

    /// Applies a catalog header lookup, fetching from peers the chains the catalog misses.
    async fn on_lookup(
        &mut self,
        walker: &mut AncestryWalker<H::Digest>,
        headers: HeaderSegments<H::Digest>,
        reason: FetchReason,
    ) -> Result<(), Error> {
        if headers.len() != walker.scheduled.len() {
            return Err(Error::Invalid("catalog header batch cardinality mismatch"));
        }
        let scheduled = mem::take(&mut walker.scheduled);
        for (Scheduled { chain, request, .. }, headers) in scheduled.into_iter().zip(headers) {
            if !walker.needs(chain, request) {
                continue;
            }
            if !headers.is_empty() {
                self.accept_headers(walker, chain, request, &headers)
                    .await?;
                continue;
            }
            let mut fetcher = self.fetcher.clone();
            walker.aborters[chain] = Some(walker.fetches.push(async move {
                let result = fetcher.headers(reason, request).await.map_err(Error::from);
                ProducerFetch {
                    chain,
                    request,
                    result,
                }
            }));
        }
        Ok(())
    }

    /// Applies a peer header fetch.
    async fn on_fetch(
        &mut self,
        walker: &mut AncestryWalker<H::Digest>,
        fetched: ProducerFetch<H::Digest>,
    ) -> Result<(), Error> {
        let ProducerFetch {
            chain,
            request,
            result,
        } = fetched;
        walker.aborters[chain] = None;
        self.accept_headers(walker, chain, request, result?.as_slice())
            .await
    }

    /// Applies a header hint for `reference` when a walk is looking it up or fetching it.
    ///
    /// The hint authenticates ancestry, not custody. Body lookup and durable publication still
    /// follow the completed walk's output plan.
    async fn on_header(
        &mut self,
        walker: &mut AncestryWalker<H::Digest>,
        reference: BlockRef<H::Digest>,
    ) -> Result<(), Error> {
        let chain = reference.chain().get() as usize;
        if !walker.needs(chain, reference) {
            return Ok(());
        }
        let fetching = walker.aborters[chain].take().is_some();
        let looking_up = walker
            .scheduled
            .iter()
            .any(|scheduled| scheduled.chain == chain && scheduled.request == reference);
        if fetching || looking_up {
            let header = self
                .headers
                .get(&reference)
                .cloned()
                .expect("the received header is cached");
            self.accept_headers(walker, chain, reference, &[header])
                .await?;
        }
        Ok(())
    }

    /// Advances `chain`'s walk through a header segment that starts at `request`.
    ///
    /// Segments are authenticated against their request before they arrive here: validated at
    /// backfill delivery, read from local storage, or found by their own identity.
    async fn accept_headers(
        &mut self,
        walker: &mut AncestryWalker<H::Digest>,
        chain: usize,
        request: BlockRef<H::Digest>,
        headers: &[TransactionBlockHeader<H::Digest>],
    ) -> Result<(), Error> {
        if headers.is_empty() {
            return Err(Error::Invalid("resolved producer header segment is empty"));
        }
        let mut expected = request;
        for header in headers {
            if walker.walks[chain].ancestry.next().is_none() {
                break;
            }
            let walk = walker.walk(chain)?;
            walk.ancestry.accept::<H>(self.epoch, header)?;
            self.stage_reference(walk, expected).await?;
            expected = header.parent_ref();
            self.insert_header(header.clone());
        }
        walker.requeue(chain);
        Ok(())
    }

    /// Checks `reference` against its walk's history boundary and stages it when the ordering
    /// stream emits it.
    async fn stage_reference(
        &mut self,
        walk: &mut ProducerWalk<H::Digest>,
        reference: BlockRef<H::Digest>,
    ) -> Result<(), Error> {
        walk.pass_boundary(reference)?;
        if walk.stages(reference) {
            self.block_stack.push(reference).await?;
        }
        Ok(())
    }
}
