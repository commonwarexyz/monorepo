use crate::{DataSource, Indexer, OrderedData, PersistentStore, Verifiable};
use alto_types::{Block, Finalization, Finalized, Notarization, Notarized, Seed};
use bytes::Bytes;
use commonware_cryptography::sha256::Digest;
use commonware_p2p::{Receiver, Recipients, Sender};
use futures::channel::{mpsc, oneshot};
use futures::future::JoinHandle;
use futures::stream::StreamExt;
use futures::{select, FutureExt, FuturesUnordered};
use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::time::Interval;

#[derive(Clone, Debug)]
pub struct NotarizedBlock {
    pub view: u64,
    pub notarization: Notarized,
}

impl OrderedData for NotarizedBlock {
    type Index = u64;
    fn index(&self) -> Self::Index {
        self.view
    }
}

#[derive(Clone, Debug)]
pub struct FinalizationData {
    pub height: u64,
    pub view: u64,
    pub finalization: Finalization,
}

impl OrderedData for FinalizationData {
    type Index = u64;
    fn index(&self) -> Self::Index {
        self.height
    }
}

#[derive(Clone, Debug)]
pub struct FinalizedBlock {
    pub height: u64,
    pub block: Block,
}

impl OrderedData for FinalizedBlock {
    type Index = u64;
    fn index(&self) -> Self::Index {
        self.height
    }
}

// Configuration for Synchronizer
pub struct SynchronizerConfig {
    pub mailbox_size: usize,
    pub activity_timeout: u64, // In views
}

// Messages for the Synchronizer
#[derive(Debug)]
pub enum SyncMessage {
    Get {
        view: Option<u64>,
        payload: Digest,
        response: oneshot::Sender<Block>,
    },
    Broadcast {
        payload: Block,
    },
    Verified {
        view: u64,
        payload: Block,
    },
    Notarized {
        proof: Notarization,
        seed: Seed,
    },
    Finalized {
        proof: Finalization,
        seed: Seed,
    },
}

// Fetch key for DataSource
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum FetchKey {
    Notarized(u64),
    Finalized(u64),
}

// Synchronizer actor
pub struct Synchronizer<DS, PSV, PSN, PSF, PSB, IX, NetS, NetR>
where
    DS: DataSource + Send + Sync + 'static,
    PSV: PersistentStore<VerifiedBlock> + Send + Sync + 'static,
    PSN: PersistentStore<NotarizedBlock> + Send + Sync + 'static,
    PSF: PersistentStore<FinalizationData> + Send + Sync + 'static,
    PSB: PersistentStore<FinalizedBlock> + Send + Sync + 'static,
    IX: Indexer<FinalizedBlock> + Send + Sync + 'static,
    NetS: Sender + Send + Sync + 'static,
    NetR: Receiver + Send + Sync + 'static,
{
    config: SynchronizerConfig,
    data_source: Arc<DS>,
    store_verified: Arc<PSV>,
    store_notarized: Arc<PSN>,
    store_finalized: Arc<PSF>,
    store_blocks: Arc<PSB>,
    indexer: Option<IX>,
    network_sender: NetS,
    network_receiver: NetR,
    mailbox: mpsc::Receiver<SyncMessage>,
    waiters: HashMap<Digest, Vec<oneshot::Sender<Block>>>,
    last_processed_view: Arc<Mutex<u64>>,
    active_fetches: FuturesUnordered<JoinHandle<(FetchKey, Result<Option<Bytes>, DS::Error>)>>,
}

impl<DS, PSV, PSN, PSF, PSB, IX, NetS, NetR> Synchronizer<DS, PSV, PSN, PSF, PSB, IX, NetS, NetR>
where
    DS: DataSource + Send + Sync + 'static,
    PSV: PersistentStore<VerifiedBlock> + Send + Sync + 'static,
    PSN: PersistentStore<NotarizedBlock> + Send + Sync + 'static,
    PSF: PersistentStore<FinalizationData> + Send + Sync + 'static,
    PSB: PersistentStore<FinalizedBlock> + Send + Sync + 'static,
    IX: Indexer<FinalizedBlock> + Send + Sync + 'static,
    NetS: Sender + Send + Sync + 'static,
    NetR: Receiver + Send + Sync + 'static,
{
    pub fn new(
        config: SynchronizerConfig,
        data_source: DS,
        store_verified: PSV,
        store_notarized: PSN,
        store_finalized: PSF,
        store_blocks: PSB,
        indexer: Option<IX>,
        network_sender: NetS,
        network_receiver: NetR,
    ) -> (Self, mpsc::Sender<SyncMessage>) {
        let (sender, mailbox) = mpsc::channel(config.mailbox_size);
        let synchronizer = Self {
            config,
            data_source: Arc::new(data_source),
            store_verified: Arc::new(store_verified),
            store_notarized: Arc::new(store_notarized),
            store_finalized: Arc::new(store_finalized),
            store_blocks: Arc::new(store_blocks),
            indexer,
            network_sender,
            network_receiver,
            mailbox,
            waiters: HashMap::new(),
            last_processed_view: Arc::new(Mutex::new(0)),
            active_fetches: FuturesUnordered::new(),
        };
        (synchronizer, sender)
    }

    pub async fn run(mut self) {
        // Spawn finalizer task
        let finalizer = self.spawn_finalizer();

        // Main event loop
        loop {
            select! {
                msg = self.mailbox.next() => {
                    if let Some(msg) = msg {
                        self.handle_message(msg).await;
                    } else {
                        break; // Mailbox closed
                    }
                }
                broadcast = self.network_receiver.recv().fuse() => {
                    if let Ok((sender, message)) = broadcast {
                        self.handle_broadcast(sender, message).await;
                    }
                }
                fetch_result = self.active_fetches.next() => {
                    if let Some((key, result)) = fetch_result {
                        self.process_fetch_result(key, result).await;
                    }
                }
            }
        }

        // Cleanup: wait for finalizer to complete if needed
        finalizer.await;
    }

    async fn handle_message(&mut self, msg: SyncMessage) {
        match msg {
            SyncMessage::Get {
                view,
                payload,
                response,
            } => {
                if let Some(block) = self.get_block(&payload).await {
                    let _ = response.send(block);
                } else {
                    if let Some(view) = view {
                        self.fetch(FetchKey::Notarized(view)).await;
                    }
                    self.waiters.entry(payload).or_default().push(response);
                }
            }
            SyncMessage::Broadcast { payload } => {
                let serialized = Bytes::from(payload.serialize().into_vec());
                self.network_sender
                    .send(Recipients::All, serialized, true)
                    .await;
            }
            SyncMessage::Verified { view, payload } => {
                let verified = VerifiedBlock {
                    view,
                    block: payload,
                };
                self.store_verified
                    .put(&verified)
                    .await
                    .expect("Failed to store verified block");
            }
            SyncMessage::Notarized { proof, seed } => {
                if let Some(block) = self.get_block(&proof.payload).await {
                    let notarized = NotarizedBlock {
                        view: proof.view,
                        notarization: Notarized::new(proof.clone(), block),
                    };
                    self.store_notarized
                        .put(&notarized)
                        .await
                        .expect("Failed to store notarized block");
                    if let Some(indexer) = &self.indexer {
                        let seed_bytes = seed.serialize().into();
                        indexer.seed_upload(seed_bytes).await;
                    }
                } else {
                    self.fetch(FetchKey::Notarized(proof.view)).await;
                }
            }
            SyncMessage::Finalized { proof, seed } => {
                if let Some(block) = self.get_block(&proof.payload).await {
                    let height = block.height;
                    let finalization = FinalizationData {
                        height,
                        view: proof.view,
                        finalization: proof.clone(),
                    };
                    self.store_finalized
                        .put(&finalization)
                        .await
                        .expect("Failed to store finalization");
                    let finalized_block = FinalizedBlock { height, block };
                    self.store_blocks
                        .put(&finalized_block)
                        .await
                        .expect("Failed to store finalized block");
                    self.prune_stores(proof.view).await;
                    if let Some(indexer) = &self.indexer {
                        let seed_bytes = seed.serialize().into();
                        indexer.seed_upload(seed_bytes).await;
                    }
                } else {
                    self.fetch(FetchKey::Digest(proof.payload)).await;
                }
            }
        }
    }

    async fn handle_broadcast(&mut self, sender: Vec<u8>, message: Bytes) {
        if let Some(block) = Block::deserialize(&message) {
            if let Some(waiters) = self.waiters.remove(&block.digest()) {
                for waiter in waiters {
                    let _ = waiter.send(block.clone());
                }
            }
        }
    }

    async fn fetch(&mut self, key: FetchKey) {
        let data_source = self.data_source.clone();
        let fetch_handle = tokio::spawn(async move {
            let result = data_source.fetch_item(key.clone()).await;
            (key, result)
        });
        self.active_fetches.push(fetch_handle);
    }

    async fn process_fetch_result(
        &mut self,
        key: FetchKey,
        result: Result<Option<Bytes>, DS::Error>,
    ) {
        if let Ok(Some(data)) = result {
            match key {
                FetchKey::Notarized(view) => {
                    if let Some(notarized) = Notarized::deserialize(None, &data) {
                        let notarized_block = NotarizedBlock {
                            view,
                            notarization: notarized.clone(),
                        };
                        self.store_notarized
                            .put(&notarized_block)
                            .await
                            .expect("Failed to store notarized block");
                        if let Some(waiters) = self.waiters.remove(&notarized.block.digest()) {
                            for waiter in waiters {
                                let _ = waiter.send(notarized.block.clone());
                            }
                        }
                    }
                }
                FetchKey::Finalized(height) => {
                    if let Some(finalized) = Finalized::deserialize(None, &data) {
                        let finalization_data = FinalizationData {
                            height,
                            view: finalized.proof.view,
                            finalization: finalized.proof.clone(),
                        };
                        self.store_finalized
                            .put(&finalization_data)
                            .await
                            .expect("Failed to store finalization");
                        let finalized_block = FinalizedBlock {
                            height,
                            block: finalized.block.clone(),
                        };
                        self.store_blocks
                            .put(&finalized_block)
                            .await
                            .expect("Failed to store finalized block");
                        self.prune_stores(finalized.proof.view).await;
                        if let Some(waiters) = self.waiters.remove(&finalized.block.digest()) {
                            for waiter in waiters {
                                let _ = waiter.send(finalized.block.clone());
                            }
                        }
                    }
                }
                FetchKey::Digest(digest) => {
                    if let Some(block) = Block::deserialize(&data) {
                        if block.digest() == digest {
                            let finalized_block = FinalizedBlock {
                                height: block.height,
                                block: block.clone(),
                            };
                            self.store_blocks
                                .put(&finalized_block)
                                .await
                                .expect("Failed to store block");
                            if let Some(waiters) = self.waiters.remove(&digest) {
                                for waiter in waiters {
                                    let _ = waiter.send(block);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    async fn get_block(&self, digest: &Digest) -> Option<Block> {
        if let Ok(Some(verified)) = self.store_verified.get_by_key(digest).await {
            return Some(verified.block);
        }
        if let Ok(Some(notarized)) = self.store_notarized.get_by_key(digest).await {
            return Some(notarized.notarization.block);
        }
        if let Ok(Some(finalized)) = self.store_blocks.get_by_key(digest).await {
            return Some(finalized.block);
        }
        None
    }

    async fn prune_stores(&self, latest_view: u64) {
        let last_processed_view = *self.last_processed_view.lock().await;
        let min_view = last_processed_view.saturating_sub(self.config.activity_timeout);
        self.store_verified
            .prune(min_view)
            .await
            .expect("Failed to prune verified store");
        self.store_notarized
            .prune(min_view)
            .await
            .expect("Failed to prune notarized store");
    }

    fn spawn_finalizer(&self) -> JoinHandle<()> {
        let store_blocks = self.store_blocks.clone();
        let data_source = self.data_source.clone();
        let indexer = self.indexer.clone();
        let last_processed_view = self.last_processed_view.clone();
        tokio::spawn(async move {
            let mut last_indexed = 0;
            loop {
                let next = last_indexed + 1;
                if let Ok(Some(block)) = store_blocks.get(next).await {
                    if let Some(indexer) = &indexer {
                        indexer.index(&block).await.expect("Failed to index block");
                    }
                    last_indexed = next;
                    if let Ok(Some(finalization)) = store_blocks.get(next).await {
                        *last_processed_view.lock().await = finalization.view;
                    }
                } else {
                    let key = FetchKey::Finalized(next);
                    if let Ok(Some(data)) = data_source.fetch_item(key).await {
                        if let Some(finalized) = Finalized::deserialize(None, &data) {
                            let finalized_block = FinalizedBlock {
                                height: next,
                                block: finalized.block,
                            };
                            store_blocks
                                .put(&finalized_block)
                                .await
                                .expect("Failed to store fetched finalized block");
                        }
                    } else {
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
            }
        })
    }
}
