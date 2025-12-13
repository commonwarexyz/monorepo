use crate::execution::{evm_env, execute_txs};
use crate::types::{block_id, Block, BlockId, StateRoot, Tx};
use alloy_evm::revm::{
    database::InMemoryDB,
    primitives::{Address, B256, U256},
    state::AccountInfo,
    Database as _,
};
use bytes::Bytes;
use commonware_consensus::{
    simplex::types::{Activity, Context},
    types::Epoch,
    Automaton as ConsensusAutomaton, Relay as ConsensusRelay, Reporter as ConsensusReporter,
};
use commonware_codec::Encode as _;
use commonware_cryptography::{ed25519, sha256, Hasher as _};
use commonware_p2p::{Recipients, Sender as P2pSender};
use futures::{
    channel::{mpsc, oneshot},
    SinkExt, StreamExt,
};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

pub type ConsensusDigest = sha256::Digest;
pub type PublicKey = ed25519::PublicKey;
pub type FinalizationEvent = (u32, ConsensusDigest);

#[derive(Clone, Copy, Debug)]
pub struct BlockCodecCfg {
    pub max_txs: usize,
    pub max_calldata_bytes: usize,
}

#[derive(Clone, Debug)]
struct BlockEntry {
    block: Block,
    db: InMemoryDB,
}

#[derive(Clone, Debug, Default)]
struct ChainStore {
    by_digest: BTreeMap<ConsensusDigest, BlockEntry>,
    by_id: BTreeMap<BlockId, ConsensusDigest>,
}

impl ChainStore {
    fn insert(&mut self, digest: ConsensusDigest, entry: BlockEntry) {
        self.by_id.insert(entry.block.id(), digest);
        self.by_digest.insert(digest, entry);
    }

    fn get_by_digest(&self, digest: &ConsensusDigest) -> Option<&BlockEntry> {
        self.by_digest.get(digest)
    }
}

#[derive(Debug)]
pub enum Message {
    Genesis {
        epoch: Epoch,
        response: oneshot::Sender<ConsensusDigest>,
    },
    SetGenesisTx {
        tx: Option<Tx>,
    },
    QueryBalance {
        digest: ConsensusDigest,
        address: Address,
        response: oneshot::Sender<Option<U256>>,
    },
    QueryStateRoot {
        digest: ConsensusDigest,
        response: oneshot::Sender<Option<StateRoot>>,
    },
    Propose {
        context: Context<ConsensusDigest, PublicKey>,
        response: oneshot::Sender<ConsensusDigest>,
    },
    Verify {
        context: Context<ConsensusDigest, PublicKey>,
        digest: ConsensusDigest,
        response: oneshot::Sender<bool>,
    },
    BlockReceived {
        from: PublicKey,
        bytes: Bytes,
    },
    Broadcast {
        digest: ConsensusDigest,
    },
    Report {
        activity: Activity<
            commonware_consensus::simplex::signing_scheme::bls12381_threshold::Scheme<
                PublicKey,
                commonware_cryptography::bls12381::primitives::variant::MinSig,
            >,
            ConsensusDigest,
        >,
    },
}

/// Mailbox for the chain application.
#[derive(Clone)]
pub struct Mailbox<S> {
    sender: mpsc::Sender<Message>,
    gossip: S,
    store: Arc<Mutex<ChainStore>>,
}

impl<S> Mailbox<S> {
    fn new(sender: mpsc::Sender<Message>, gossip: S, store: Arc<Mutex<ChainStore>>) -> Self {
        Self {
            sender,
            gossip,
            store,
        }
    }

    pub async fn deliver_block(&self, from: PublicKey, bytes: Bytes) {
        let mut sender = self.sender.clone();
        let _ = sender
            .send(Message::BlockReceived { from, bytes })
            .await;
    }

    pub async fn set_genesis_tx(&self, tx: Option<Tx>) {
        let mut sender = self.sender.clone();
        let _ = sender.send(Message::SetGenesisTx { tx }).await;
    }

    pub async fn query_balance(&self, digest: ConsensusDigest, address: Address) -> Option<U256> {
        let (response, receiver) = oneshot::channel();
        let mut sender = self.sender.clone();
        let _ = sender
            .send(Message::QueryBalance {
                digest,
                address,
                response,
            })
            .await;
        receiver.await.unwrap_or(None)
    }

    pub async fn query_state_root(&self, digest: ConsensusDigest) -> Option<StateRoot> {
        let (response, receiver) = oneshot::channel();
        let mut sender = self.sender.clone();
        let _ = sender
            .send(Message::QueryStateRoot { digest, response })
            .await;
        receiver.await.unwrap_or(None)
    }
}

impl<S> ConsensusAutomaton for Mailbox<S>
where
    S: Clone + Send + Sync + 'static,
{
    type Context = Context<ConsensusDigest, PublicKey>;
    type Digest = ConsensusDigest;

    async fn genesis(&mut self, epoch: Epoch) -> Self::Digest {
        let (response, receiver) = oneshot::channel();
        self.sender
            .send(Message::Genesis { epoch, response })
            .await
            .expect("failed to send genesis");
        receiver.await.expect("failed to receive genesis")
    }

    async fn propose(&mut self, context: Self::Context) -> oneshot::Receiver<Self::Digest> {
        let (response, receiver) = oneshot::channel();
        if self
            .sender
            .send(Message::Propose { context, response })
            .await
            .is_err()
        {
            return receiver;
        }
        receiver
    }

    async fn verify(
        &mut self,
        context: Self::Context,
        payload: Self::Digest,
    ) -> oneshot::Receiver<bool> {
        let (response, receiver) = oneshot::channel();
        if self
            .sender
            .send(Message::Verify {
                context,
                digest: payload,
                response,
            })
            .await
            .is_err()
        {
            return receiver;
        }
        receiver
    }
}

impl<S> ConsensusRelay for Mailbox<S>
where
    S: P2pSender<PublicKey = PublicKey> + Clone + Send + Sync + 'static,
{
    type Digest = ConsensusDigest;

    async fn broadcast(&mut self, payload: Self::Digest) {
        let bytes = {
            let store = self.store.lock().expect("store lock poisoned");
            store
                .get_by_digest(&payload)
                .map(|entry| entry.block.encode())
        };
        let Some(bytes) = bytes else {
            return;
        };

        let _ = self
            .gossip
            .send(Recipients::All, Bytes::copy_from_slice(bytes.as_ref()), true)
            .await;
    }
}

impl<S> ConsensusReporter for Mailbox<S>
where
    S: Clone + Send + Sync + 'static,
{
    type Activity = Activity<
        commonware_consensus::simplex::signing_scheme::bls12381_threshold::Scheme<
            PublicKey,
            commonware_cryptography::bls12381::primitives::variant::MinSig,
        >,
        ConsensusDigest,
    >;

    async fn report(&mut self, activity: Self::Activity) {
        let _ = self.sender.send(Message::Report { activity }).await;
    }
}

/// Chain application actor.
pub struct Application {
    node: u32,
    codec: BlockCodecCfg,
    finalized: mpsc::UnboundedSender<FinalizationEvent>,
    genesis_alloc: Vec<(Address, U256)>,
    genesis_tx: Option<Tx>,
    store: Arc<Mutex<ChainStore>>,
    received: BTreeMap<ConsensusDigest, Block>,
    pending_verifies: BTreeMap<ConsensusDigest, Vec<(Context<ConsensusDigest, PublicKey>, oneshot::Sender<bool>)>>,
}

impl Application {
    pub fn new<S>(
        node: u32,
        codec: BlockCodecCfg,
        mailbox_size: usize,
        gossip: S,
        finalized: mpsc::UnboundedSender<FinalizationEvent>,
        genesis_alloc: Vec<(Address, U256)>,
        genesis_tx: Option<Tx>,
    ) -> (Self, Mailbox<S>, mpsc::Receiver<Message>)
    where
        S: Clone + Send + Sync + 'static,
    {
        let (sender, receiver) = mpsc::channel(mailbox_size);
        let store = Arc::new(Mutex::new(ChainStore::default()));
        (
            Self {
                node,
                codec,
                finalized,
                genesis_alloc,
                genesis_tx,
                store: store.clone(),
                received: BTreeMap::new(),
                pending_verifies: BTreeMap::new(),
            },
            Mailbox::new(sender, gossip, store),
            receiver,
        )
    }

    fn digest_for_block(&self, block: &Block) -> ConsensusDigest {
        let mut hasher = commonware_cryptography::Sha256::default();
        let id = block_id(block);
        hasher.update(id.0.as_slice());
        hasher.finalize()
    }

    fn genesis_block(&self) -> Block {
        Block {
            parent: BlockId(B256::ZERO),
            height: 0,
            prevrandao: B256::ZERO,
            state_root: StateRoot(B256::ZERO),
            txs: Vec::new(),
        }
    }

    fn block_cfg(&self) -> crate::types::BlockCfg {
        crate::types::BlockCfg {
            max_txs: self.codec.max_txs,
            tx: crate::types::TxCfg {
                max_calldata_bytes: self.codec.max_calldata_bytes,
            },
        }
    }

    fn decode_block(&self, bytes: Bytes) -> anyhow::Result<Block> {
        use commonware_codec::Decode as _;
        Ok(Block::decode_cfg(bytes.as_ref(), &self.block_cfg())?)
    }

    fn encode_block(&self, block: &Block) -> Bytes {
        use commonware_codec::Encode as _;
        Bytes::copy_from_slice(block.encode().as_ref())
    }

    fn build_child_block(&self, parent: &Block, prevrandao: B256, txs: Vec<Tx>) -> Block {
        Block {
            parent: parent.id(),
            height: parent.height + 1,
            prevrandao,
            state_root: parent.state_root,
            txs,
        }
    }

    fn execute_block(
        &self,
        parent: &BlockEntry,
        mut child: Block,
    ) -> anyhow::Result<(ConsensusDigest, BlockEntry)> {
        let (db, outcome) = execute_txs(
            parent.db.clone(),
            evm_env(child.height, child.prevrandao),
            parent.block.state_root,
            &child.txs,
        )?;

        child.state_root = outcome.state_root;
        let digest = self.digest_for_block(&child);
        Ok((digest, BlockEntry { block: child, db }))
    }

    fn try_verify_and_insert(
        &mut self,
        expected_digest: ConsensusDigest,
        context: &Context<ConsensusDigest, PublicKey>,
        block: Block,
    ) -> anyhow::Result<bool> {
        let clears_genesis_tx = block.height == 1;
        if self.digest_for_block(&block) != expected_digest {
            return Ok(false);
        }
        let parent = {
            let store = self.store.lock().expect("store lock poisoned");
            store.get_by_digest(&context.parent.1).cloned()
        };
        let Some(parent) = parent else {
            return Ok(false);
        };

        if block.parent != parent.block.id() {
            return Ok(false);
        }
        if block.height != parent.block.height + 1 {
            return Ok(false);
        }

        let (db, outcome) = execute_txs(
            parent.db.clone(),
            evm_env(block.height, block.prevrandao),
            parent.block.state_root,
            &block.txs,
        )?;
        if outcome.state_root != block.state_root {
            return Ok(false);
        }

        {
            let mut store = self.store.lock().expect("store lock poisoned");
            store.insert(
                expected_digest,
                BlockEntry {
                    block,
                    db,
                },
            );
        }
        if clears_genesis_tx {
            self.genesis_tx = None;
        }
        Ok(true)
    }

    pub async fn run(mut self, mut mailbox: mpsc::Receiver<Message>) {
        while let Some(message) = mailbox.next().await {
            match message {
                Message::Genesis { epoch: _, response } => {
                    let genesis_block = self.genesis_block();
                    let digest = self.digest_for_block(&genesis_block);
                    let mut db = InMemoryDB::default();
                    for (address, balance) in self.genesis_alloc.iter().copied() {
                        db.insert_account_info(
                            address,
                            AccountInfo {
                                balance,
                                nonce: 0,
                                ..Default::default()
                            },
                        );
                    }
                    let mut store = self.store.lock().expect("store lock poisoned");
                    store.insert(
                        digest,
                        BlockEntry {
                            block: genesis_block,
                            db,
                        },
                    );
                    let _ = response.send(digest);
                }
                Message::SetGenesisTx { tx } => {
                    self.genesis_tx = tx;
                }
                Message::QueryBalance {
                    digest,
                    address,
                    response,
                } => {
                    let entry = {
                        let store = self.store.lock().expect("store lock poisoned");
                        store.get_by_digest(&digest).cloned()
                    };
                    let value = entry
                        .and_then(|mut e| e.db.basic(address).ok().flatten())
                        .map(|info| info.balance);
                    let _ = response.send(value);
                }
                Message::QueryStateRoot { digest, response } => {
                    let entry = {
                        let store = self.store.lock().expect("store lock poisoned");
                        store.get_by_digest(&digest).cloned()
                    };
                    let _ = response.send(entry.map(|e| e.block.state_root));
                }
                Message::Propose { context, response } => {
                    let parent = {
                        let store = self.store.lock().expect("store lock poisoned");
                        store.get_by_digest(&context.parent.1).cloned()
                    };
                    let Some(parent) = parent else { continue; };
                    let prevrandao = B256::from(context.parent.1 .0);
                    let txs = if parent.block.height == 0 {
                        self.genesis_tx.clone().into_iter().collect()
                    } else {
                        Vec::new()
                    };
                    let child = self.build_child_block(&parent.block, prevrandao, txs);
                    if let Ok((digest, entry)) = self.execute_block(&parent, child) {
                        let clears_genesis_tx = entry.block.height == 1;
                        {
                            let mut store = self.store.lock().expect("store lock poisoned");
                            store.insert(digest, entry);
                        }
                        if clears_genesis_tx {
                            self.genesis_tx = None;
                        }
                        let _ = response.send(digest);
                    }
                }
                Message::Verify {
                    context,
                    digest,
                    response,
                } => {
                    let already = {
                        let store = self.store.lock().expect("store lock poisoned");
                        store.get_by_digest(&digest).is_some()
                    };
                    if already {
                        let _ = response.send(true);
                        continue;
                    }

                    if let Some(block) = self.received.get(&digest).cloned() {
                        match self.try_verify_and_insert(digest, &context, block) {
                            Ok(ok) => {
                                let _ = response.send(ok);
                            }
                            Err(_) => {
                                let _ = response.send(false);
                            }
                        }
                        continue;
                    }

                    self.pending_verifies
                        .entry(digest)
                        .or_default()
                        .push((context, response));
                }
                Message::BlockReceived { from: _, bytes } => {
                    let Ok(block) = self.decode_block(bytes.clone()) else {
                        continue;
                    };
                    let digest = self.digest_for_block(&block);
                    self.received.entry(digest).or_insert(block);

                    if let Some(pending) = self.pending_verifies.remove(&digest) {
                        for (context, response) in pending {
                            let block = match self.received.get(&digest).cloned() {
                                Some(b) => b,
                                None => {
                                    let _ = response.send(false);
                                    continue;
                                }
                            };
                            let ok =
                                self.try_verify_and_insert(digest, &context, block).unwrap_or(false);
                            let _ = response.send(ok);
                        }
                    }
                }
                Message::Broadcast { digest: _ } => {}
                Message::Report { activity } => {
                    if let Activity::Finalization(finalization) = activity {
                        let _ = self
                            .finalized
                            .unbounded_send((self.node, finalization.proposal.payload));
                    }
                }
            }
        }
    }
}
