use super::store::{BlockEntry, ChainStore};
use super::{BlockCodecCfg, ConsensusDigest, FinalizationEvent, Message, PublicKey};
use crate::execution::{evm_env, execute_txs};
use crate::types::{block_id, Block, BlockId, StateRoot, Tx};
use alloy_evm::revm::{
    database::InMemoryDB,
    primitives::{Address, B256, U256},
    state::AccountInfo,
    Database as _,
};
use bytes::Bytes;
use commonware_consensus::simplex::types::{Activity, Context};
use commonware_cryptography::{Hasher as _, Sha256};
use futures::{
    channel::{mpsc, oneshot},
    StreamExt as _,
};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use super::Mailbox;

/// Chain application actor.
pub struct Application {
    node: u32,
    codec: BlockCodecCfg,
    finalized: mpsc::UnboundedSender<FinalizationEvent>,
    genesis_alloc: Vec<(Address, U256)>,
    genesis_tx: Option<Tx>,
    store: Arc<Mutex<ChainStore>>,
    received: BTreeMap<ConsensusDigest, Block>,
    pending_verifies:
        BTreeMap<ConsensusDigest, Vec<(Context<ConsensusDigest, PublicKey>, oneshot::Sender<bool>)>>,
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
        let mut hasher = Sha256::default();
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
            store.insert(expected_digest, BlockEntry { block, db });
        }
        if clears_genesis_tx {
            self.genesis_tx = None;
        }
        Ok(true)
    }

    pub async fn run(mut self, mut mailbox: mpsc::Receiver<Message>) {
        while let Some(message) = mailbox.next().await {
            match message {
                Message::Genesis { epoch, response } => {
                    let _ = epoch;
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
                    store.insert(digest, BlockEntry { block: genesis_block, db });
                    let _ = response.send(digest);
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
                    let Some(parent) = parent else {
                        continue;
                    };
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
                Message::BlockReceived { from, bytes } => {
                    let _ = from;
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
