//! In-memory stacks, fetcher, catalog, and custody ports for driving the synchronizer.

use super::*;

#[derive(Clone, Copy, Debug, thiserror::Error)]
#[error("mock port failure")]
pub(super) struct MockError;

impl From<MockError> for Error {
    fn from(_: MockError) -> Self {
        Self::Invalid("mock port failure")
    }
}

#[derive(Default)]
pub(super) struct MockStack {
    pub(super) links: Vec<HistoryLink<Sha256>>,
    pub(super) cursor: Option<usize>,
    pub(super) high_water: usize,
    pub(super) writes_since_reset: usize,
    pub(super) retired_segments: usize,
}

impl HistoryStack<Sha256> for MockStack {
    type Error = MockError;

    async fn reset(&mut self) -> Result<(), Self::Error> {
        self.retired_segments += usize::from(self.writes_since_reset > 0);
        self.writes_since_reset = 0;
        self.links.clear();
        self.cursor = None;
        Ok(())
    }

    async fn push(&mut self, link: HistoryLink<Sha256>) -> Result<(), Self::Error> {
        self.links.push(link);
        self.writes_since_reset += 1;
        self.high_water = self.high_water.max(self.links.len());
        Ok(())
    }

    async fn read_oldest(&mut self) -> Result<Option<HistoryLink<Sha256>>, Self::Error> {
        let cursor = self.cursor.get_or_insert(self.links.len());
        if *cursor == 0 {
            return Ok(None);
        }
        *cursor -= 1;
        Ok(Some(self.links[*cursor].clone()))
    }
}

#[derive(Default)]
pub(super) struct MockBlockStack {
    pub(super) blocks: Vec<Vec<BlockRef<Sha256Digest>>>,
    pub(super) writes_since_reset: usize,
    pub(super) retired_segments: usize,
}

impl BlockStack<Sha256Digest> for MockBlockStack {
    type Error = MockError;

    async fn reset(&mut self) -> Result<(), Self::Error> {
        self.retired_segments += usize::from(self.writes_since_reset > 0);
        self.writes_since_reset = 0;
        self.blocks.clear();
        Ok(())
    }

    async fn push(&mut self, block: BlockRef<Sha256Digest>) -> Result<(), Self::Error> {
        let chain = block.chain().get() as usize;
        if self.blocks.len() <= chain {
            self.blocks.resize_with(chain + 1, Vec::new);
        }
        self.blocks[chain].push(block);
        self.writes_since_reset += 1;
        Ok(())
    }

    async fn read_oldest(
        &mut self,
        chain: usize,
    ) -> Result<Option<BlockRef<Sha256Digest>>, Self::Error> {
        Ok(self.blocks.get_mut(chain).and_then(Vec::pop))
    }
}

pub(super) type MockBlocks = Arc<Mutex<BTreeMap<BlockRef<Sha256Digest>, Arc<TestBlock>>>>;

pub(super) struct HeaderGate {
    pub(super) started: oneshot::Sender<()>,
    pub(super) release: oneshot::Receiver<()>,
}

#[derive(Clone, Default)]
pub(super) struct MockFetcher {
    pub(super) histories: Vec<(Sha256Digest, Arc<TipRecord<Sha256Digest>>)>,
    pub(super) blocks: Arc<Vec<Vec<Arc<TestBlock>>>>,
    pub(super) catalog_blocks: MockBlocks,
    pub(super) block_reasons: Arc<Mutex<Vec<FetchReason>>>,
    pub(super) history_calls: Arc<AtomicUsize>,
    pub(super) block_calls: Arc<AtomicUsize>,
    pub(super) range_calls: Arc<AtomicUsize>,
    pub(super) catalog_block_calls: Option<Arc<AtomicUsize>>,
    pub(super) fetch_batch_starts: Arc<Mutex<Vec<usize>>>,
    pub(super) block_active: Arc<AtomicUsize>,
    pub(super) block_peak: Arc<AtomicUsize>,
    pub(super) yield_block_fetches: bool,
    pub(super) fetch_delay_by_height: bool,
    pub(super) range_limit: Option<usize>,
    pub(super) gates: Option<Arc<FetchGates>>,
    pub(super) header_gate: Arc<Mutex<Option<HeaderGate>>>,
    pub(super) fetch_requires: Option<(BlockRef<Sha256Digest>, usize)>,
}

impl MockFetcher {
    async fn block(
        &mut self,
        reason: FetchReason,
        reference: BlockRef<Sha256Digest>,
    ) -> Result<CustodiedBlock<Sha256, TestBody>, MockError> {
        self.block_reasons.lock().push(reason);
        self.block_calls.fetch_add(1, Ordering::Relaxed);
        if let Some(calls) = &self.catalog_block_calls {
            self.fetch_batch_starts
                .lock()
                .push(calls.load(Ordering::Relaxed));
        }
        let block = self
            .blocks
            .get(reference.chain().get() as usize)
            .and_then(|blocks| blocks.iter().find(|block| block.reference() == reference))
            .cloned()
            .ok_or(MockError)?;
        if let Some((gated, required)) = self.fetch_requires
            && reference == gated
        {
            commonware_runtime::utils::reschedule().await;
            if self.block_calls.load(Ordering::Relaxed) < required {
                return Err(MockError);
            }
        }
        if self.yield_block_fetches {
            let active = self.block_active.fetch_add(1, Ordering::Relaxed) + 1;
            self.block_peak.fetch_max(active, Ordering::Relaxed);
            commonware_runtime::utils::reschedule().await;
            self.block_active.fetch_sub(1, Ordering::Relaxed);
        }
        if self.fetch_delay_by_height {
            for _ in 0..reference.height().get() {
                commonware_runtime::utils::reschedule().await;
            }
        }
        if let Some(gates) = &self.gates {
            gates.fetch(reference.chain().get() as usize).await?;
        }
        self.catalog_blocks
            .lock()
            .insert(reference, Arc::clone(&block));
        Ok(CustodiedBlock::new(CustodyRef::for_test(&block), block)
            .expect("test custody describes its block"))
    }
}

impl Fetcher<Sha256, MinPk, TestBody> for MockFetcher {
    type Error = MockError;

    async fn history(
        &mut self,
        _reason: FetchReason,
        _view: View,
        mut commitment: Sha256Digest,
    ) -> Result<SharedHistory<Sha256Digest>, Self::Error> {
        self.history_calls.fetch_add(1, Ordering::Relaxed);
        let mut records = Vec::new();
        while let Some(record) = self
            .histories
            .iter()
            .find(|(candidate, _)| *candidate == commitment)
            .map(|(_, record)| Arc::clone(record))
        {
            commitment = record.parent();
            records.push(record);
        }
        (!records.is_empty())
            .then(|| Arc::new(records))
            .ok_or(MockError)
    }

    async fn headers(
        &mut self,
        _reason: FetchReason,
        mut reference: BlockRef<Sha256Digest>,
    ) -> Result<SharedHeaders<Sha256Digest>, Self::Error> {
        let gate = self.header_gate.lock().take();
        if let Some(gate) = gate {
            gate.started.send(()).map_err(|_| MockError)?;
            gate.release.await.map_err(|_| MockError)?;
        }
        let chain = self
            .blocks
            .get(reference.chain().get() as usize)
            .ok_or(MockError)?;
        let mut headers = Vec::new();
        while let Some(block) = chain.iter().find(|block| block.reference() == reference) {
            let header = block.header().clone();
            reference = BlockRef::new(
                reference.chain(),
                Height::new(reference.height().get().saturating_sub(1)),
                header.parent(),
            );
            headers.push(header);
        }
        (!headers.is_empty())
            .then(|| Arc::new(headers))
            .ok_or(MockError)
    }

    async fn blocks(
        &mut self,
        reason: FetchReason,
        references: Vec<BlockRef<Sha256Digest>>,
    ) -> Result<Vec<CustodiedBlock<Sha256, TestBody>>, Self::Error> {
        self.range_calls.fetch_add(1, Ordering::Relaxed);
        let limit = self.range_limit.unwrap_or(references.len());
        let mut custody = Vec::with_capacity(limit.min(references.len()));
        for reference in references.into_iter().take(limit) {
            custody.push(self.block(reason, reference).await?);
        }
        Ok(custody)
    }
}

pub(super) struct FetchGateState {
    pub(super) active: usize,
    pub(super) peak: usize,
    pub(super) active_by_chain: [usize; 3],
    pub(super) peak_by_chain: [usize; 3],
    pub(super) starts: Vec<usize>,
    pub(super) receivers: [Option<oneshot::Receiver<()>>; 3],
    pub(super) release_initial_fast: Option<oneshot::Sender<()>>,
    pub(super) release_straggler: Option<oneshot::Sender<()>>,
    pub(super) progressed_around_straggler: bool,
}

pub(super) struct FetchGates(pub(super) Mutex<FetchGateState>);

impl FetchGates {
    pub(super) fn new() -> Self {
        let (release_straggler, straggler) = oneshot::channel();
        let (release_initial_fast, initial_fast) = oneshot::channel();
        Self(Mutex::new(FetchGateState {
            active: 0,
            peak: 0,
            active_by_chain: [0; 3],
            peak_by_chain: [0; 3],
            starts: Vec::new(),
            receivers: [Some(straggler), Some(initial_fast), None],
            release_initial_fast: Some(release_initial_fast),
            release_straggler: Some(release_straggler),
            progressed_around_straggler: false,
        }))
    }

    async fn fetch(&self, chain: usize) -> Result<(), MockError> {
        let (receiver, release) = {
            let mut state = self.0.lock();
            assert_eq!(state.active_by_chain[chain], 0);
            state.active += 1;
            state.peak = state.peak.max(state.active);
            state.active_by_chain[chain] = 1;
            state.peak_by_chain[chain] = state.peak_by_chain[chain].max(1);
            state.starts.push(chain);
            let receiver = state.receivers[chain].take();
            let release = if state.active_by_chain[0] == 1 && state.active_by_chain[1] == 1 {
                state.release_initial_fast.take()
            } else if chain == 2 && state.release_straggler.is_some() {
                assert_eq!(state.active_by_chain[0], 1);
                state.progressed_around_straggler = true;
                state.release_straggler.take()
            } else {
                None
            };
            (receiver, release)
        };
        if let Some(release) = release {
            release.send(()).map_err(|_| MockError)?;
        }
        if let Some(receiver) = receiver {
            receiver.await.map_err(|_| MockError)?;
        }
        let mut state = self.0.lock();
        state.active -= 1;
        state.active_by_chain[chain] = 0;
        Ok(())
    }
}

/// Order in which mock ports were called, shared between mocks.
pub(super) type CallLog = Arc<Mutex<Vec<&'static str>>>;

#[derive(Default)]
pub(super) struct MockVerifier {
    pub(super) valid: bool,
    pub(super) calls: CallLog,
}

impl LqcVerifier<Sha256, MinPk> for MockVerifier {
    type Error = MockError;

    async fn verify(&mut self, _: &Lqc<MinPk, Sha256Digest>) -> Result<(), Self::Error> {
        self.calls.lock().push("verify");
        self.valid.then_some(()).ok_or(MockError)
    }
}

pub(super) struct MockCatalog {
    pub(super) checkpoint: Checkpoint<Sha256Digest>,
    pub(super) latest: Option<Arc<Lqc<MinPk, Sha256Digest>>>,
    pub(super) blocks: MockBlocks,
    pub(super) block_batches: Arc<Mutex<Vec<Vec<BlockRef<Sha256Digest>>>>>,
    pub(super) block_calls: Arc<AtomicUsize>,
    pub(super) header_limits: Arc<Mutex<Vec<Vec<usize>>>>,
    pub(super) header_gate: Arc<Mutex<Option<HeaderGate>>>,
    pub(super) outputs: Vec<BlockRef<Sha256Digest>>,
    pub(super) handoff: Vec<BlockRef<Sha256Digest>>,
    pub(super) batches: Vec<usize>,
    pub(super) history_commits: usize,
    pub(super) selected: Vec<CertificateId<Sha256Digest>>,
    pub(super) selected_calls: Arc<Mutex<Vec<CertificateId<Sha256Digest>>>>,
    /// Every committed L-QC, by certificate identity.
    pub(super) proofs: BTreeMap<CertificateId<Sha256Digest>, Arc<Lqc<MinPk, Sha256Digest>>>,
    pub(super) commit_calls: Arc<AtomicUsize>,
    pub(super) commit_waiters: Option<CommitWaiters>,
    pub(super) commit_start_gate: Option<(oneshot::Sender<()>, oneshot::Receiver<()>)>,
    pub(super) installed: usize,
    pub(super) calls: CallLog,
}

impl CatalogPort<Sha256, MinPk, TestBody> for MockCatalog {
    type Error = MockError;
    type CommitToken = oneshot::Receiver<Result<(), MockError>>;

    async fn checkpoint(&mut self) -> Result<Checkpoint<Sha256Digest>, Self::Error> {
        Ok(self.checkpoint.clone())
    }

    async fn latest_lqc(&mut self) -> Result<Option<Arc<Lqc<MinPk, Sha256Digest>>>, Self::Error> {
        Ok(self.latest.take())
    }

    async fn lqc(
        &mut self,
        id: CertificateId<Sha256Digest>,
    ) -> Result<Option<Arc<Lqc<MinPk, Sha256Digest>>>, Self::Error> {
        Ok(self.proofs.get(&id).cloned())
    }

    async fn final_lqc(&mut self, id: CertificateId<Sha256Digest>) -> Result<bool, Self::Error> {
        Ok(self.selected.contains(&id))
    }

    fn header_segments(
        &self,
        requests: Vec<(BlockRef<Sha256Digest>, usize)>,
        _max_bytes: usize,
    ) -> impl Future<Output = Result<HeaderSegments<Sha256Digest>, Self::Error>> + Send + 'static
    {
        let gate = Arc::clone(&self.header_gate);
        let limits = Arc::clone(&self.header_limits);
        let blocks = Arc::clone(&self.blocks);
        async move {
            let gate = gate.lock().take();
            if let Some(gate) = gate {
                gate.started.send(()).map_err(|_| MockError)?;
                gate.release.await.map_err(|_| MockError)?;
            }
            limits
                .lock()
                .push(requests.iter().map(|(_, max_items)| *max_items).collect());
            Ok(requests
                .into_iter()
                .map(|(mut reference, max_items)| {
                    let mut headers = Vec::new();
                    while headers.len() < max_items {
                        let Some(block) = blocks.lock().get(&reference).cloned() else {
                            break;
                        };
                        let header = block.header().clone();
                        reference = BlockRef::new(
                            reference.chain(),
                            Height::new(reference.height().get().saturating_sub(1)),
                            header.parent(),
                        );
                        headers.push(header);
                    }
                    headers
                })
                .collect())
        }
    }

    fn wait_for_custody(
        &self,
        references: Vec<BlockRef<Sha256Digest>>,
    ) -> impl Future<Output = Result<CustodyValues<Sha256Digest>, Self::Error>> + Send + 'static
    {
        let blocks = Arc::clone(&self.blocks);
        let batches = Arc::clone(&self.block_batches);
        let calls = Arc::clone(&self.block_calls);
        async move {
            calls.fetch_add(1, Ordering::Relaxed);
            batches.lock().push(references.clone());
            Ok(references
                .into_iter()
                .map(|reference| {
                    blocks.lock().get(&reference).cloned().map(|block| {
                        assert_eq!(block.reference(), reference);
                        CustodyRef::for_test(&block)
                    })
                })
                .collect())
        }
    }

    async fn start_commit(
        &mut self,
        batch: Commit<Sha256, MinPk>,
        handoff: Vec<delivery::HotOutput<Sha256, TestBody>>,
    ) -> Result<Self::CommitToken, Self::Error> {
        self.commit_calls.fetch_add(1, Ordering::Relaxed);
        self.calls.lock().push("commit");
        self.batches.push(batch.outputs.len());
        self.outputs
            .extend(batch.outputs.iter().map(OutputRow::reference));
        self.handoff
            .extend(handoff.into_iter().map(|output| output.block.reference()));
        self.history_commits += batch.history.len();
        for selected in batch.selected {
            self.selected.push(selected.id);
            self.selected_calls.lock().push(selected.id);
            self.proofs.insert(selected.id, selected.proof);
        }
        self.checkpoint = batch.checkpoint;
        let (completion, token) = oneshot::channel();
        if let Some(waiters) = &self.commit_waiters {
            waiters.lock().push_back(completion);
        } else {
            let _ = completion.send(Ok(()));
        }
        if let Some((started, release)) = self.commit_start_gate.take() {
            let _ = started.send(());
            release.await.map_err(|_| MockError)?;
        }
        Ok(token)
    }

    async fn wait_commit(token: Self::CommitToken) -> Result<(), Self::Error> {
        token.await.unwrap_or(Err(MockError))
    }

    async fn install(
        &mut self,
        checkpoint: Checkpoint<Sha256Digest>,
        _: PendingFloors,
        _: Arc<Lqc<MinPk, Sha256Digest>>,
        _: Arc<TipRecord<Sha256Digest>>,
    ) -> Result<(), Self::Error> {
        self.checkpoint = checkpoint;
        self.installed += 1;
        Ok(())
    }
}
