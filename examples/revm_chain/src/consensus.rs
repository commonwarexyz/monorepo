use crate::execution::{evm_env, execute_txs};
use crate::types::{block_id, Block, BlockId, StateRoot, Tx};
use alloy_evm::revm::{
    database::InMemoryDB,
    primitives::{B256, Bytes},
};
use commonware_consensus::{
    simplex::types::{Activity, Context},
    types::Epoch,
    Automaton as ConsensusAutomaton, Relay as ConsensusRelay, Reporter as ConsensusReporter,
};
use commonware_cryptography::{ed25519, sha256, Hasher as _};
use futures::{
    channel::{mpsc, oneshot},
    SinkExt, StreamExt,
};
use std::collections::BTreeMap;

pub type ConsensusDigest = sha256::Digest;
pub type PublicKey = ed25519::PublicKey;

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
    Propose {
        context: Context<ConsensusDigest, PublicKey>,
        response: oneshot::Sender<ConsensusDigest>,
    },
    Verify {
        context: Context<ConsensusDigest, PublicKey>,
        digest: ConsensusDigest,
        response: oneshot::Sender<bool>,
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
pub struct Mailbox {
    sender: mpsc::Sender<Message>,
}

impl Mailbox {
    pub(super) const fn new(sender: mpsc::Sender<Message>) -> Self {
        Self { sender }
    }
}

impl ConsensusAutomaton for Mailbox {
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

impl ConsensusRelay for Mailbox {
    type Digest = ConsensusDigest;

    async fn broadcast(&mut self, payload: Self::Digest) {
        let _ = self.sender.send(Message::Broadcast { digest: payload }).await;
    }
}

impl ConsensusReporter for Mailbox {
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
    codec: BlockCodecCfg,
    store: ChainStore,
}

impl Application {
    pub fn new(codec: BlockCodecCfg, mailbox_size: usize) -> (Self, Mailbox, mpsc::Receiver<Message>) {
        let (sender, receiver) = mpsc::channel(mailbox_size);
        (
            Self {
                codec,
                store: ChainStore::default(),
            },
            Mailbox::new(sender),
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

    pub async fn run(mut self, mut mailbox: mpsc::Receiver<Message>) {
        while let Some(message) = mailbox.next().await {
            match message {
                Message::Genesis { epoch: _, response } => {
                    let genesis_block = self.genesis_block();
                    let digest = self.digest_for_block(&genesis_block);
                    self.store.insert(
                        digest,
                        BlockEntry {
                            block: genesis_block,
                            db: InMemoryDB::default(),
                        },
                    );
                    let _ = response.send(digest);
                }
                Message::Propose { context, response } => {
                    let Some(parent) = self.store.get_by_digest(&context.parent.1).cloned()
                    else {
                        continue;
                    };
                    let child = self.build_child_block(&parent.block, B256::ZERO, Vec::new());
                    if let Ok((digest, entry)) = self.execute_block(&parent, child) {
                        self.store.insert(digest, entry);
                        let _ = response.send(digest);
                    }
                }
                Message::Verify {
                    context,
                    digest,
                    response,
                } => {
                    let Some(_parent) = self.store.get_by_digest(&context.parent.1) else {
                        let _ = response.send(false);
                        continue;
                    };
                    let ok = self.store.get_by_digest(&digest).is_some();
                    let _ = response.send(ok);
                }
                Message::Broadcast { digest: _ } => {}
                Message::Report { activity: _ } => {}
            }
        }
    }
}
