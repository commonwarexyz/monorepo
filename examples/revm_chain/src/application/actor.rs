use super::{
    store::{BlockEntry, ChainStore},
    ApplicationRequest, BlockCodecCfg, Handle,
};
use crate::consensus::{ConsensusDigest, ConsensusRequest, FinalizationEvent, PublicKey};
use crate::execution::{evm_env, execute_txs};
use crate::types::{block_id, Block, BlockId, StateRoot, Tx};
use alloy_evm::revm::{
    database::InMemoryDB,
    primitives::{keccak256, Address, B256, U256},
    state::AccountInfo,
    Database as _,
};
use bytes::Bytes;
use commonware_consensus::simplex::signing_scheme::bls12381_threshold::Seedable as _;
use commonware_consensus::simplex::types::{Activity, Context};
use commonware_cryptography::{Hasher as _, Sha256};
use futures::{
    channel::{mpsc, oneshot},
    StreamExt as _,
};
use std::collections::BTreeMap;

type ThresholdActivity = <crate::consensus::Mailbox as commonware_consensus::Reporter>::Activity;

/// Chain application actor.
pub struct Application<S> {
    node: u32,
    codec: BlockCodecCfg,
    finalized: mpsc::UnboundedSender<FinalizationEvent>,
    genesis_alloc: Vec<(Address, U256)>,
    genesis_tx: Option<Tx>,
    store: ChainStore,
    received: BTreeMap<ConsensusDigest, Block>,
    pending_verifies: BTreeMap<
        ConsensusDigest,
        Vec<(Context<ConsensusDigest, PublicKey>, oneshot::Sender<bool>)>,
    >,
    gossip: S,
    consensus: mpsc::Receiver<ConsensusRequest>,
    control: mpsc::Receiver<ApplicationRequest>,
}

enum Input {
    Consensus(ConsensusRequest),
    Control(ApplicationRequest),
}

struct Runtime<S> {
    node: u32,
    block_cfg: crate::types::BlockCfg,
    finalized: mpsc::UnboundedSender<FinalizationEvent>,
    genesis_alloc: Vec<(Address, U256)>,
    genesis_tx: Option<Tx>,
    store: ChainStore,
    received: BTreeMap<ConsensusDigest, Block>,
    pending_verifies: BTreeMap<
        ConsensusDigest,
        Vec<(Context<ConsensusDigest, PublicKey>, oneshot::Sender<bool>)>,
    >,
    gossip: S,
}

impl<S> Application<S>
where
    S: commonware_p2p::Sender<PublicKey = PublicKey> + Clone + Send + Sync + 'static,
{
    pub fn new(
        node: u32,
        codec: BlockCodecCfg,
        mailbox_size: usize,
        gossip: S,
        finalized: mpsc::UnboundedSender<FinalizationEvent>,
        genesis_alloc: Vec<(Address, U256)>,
        genesis_tx: Option<Tx>,
    ) -> (Self, crate::consensus::Mailbox, Handle) {
        let (consensus_sender, consensus) = mpsc::channel(mailbox_size);
        let (control_sender, control) = mpsc::channel(mailbox_size);
        let consensus_mailbox = crate::consensus::Mailbox::new(consensus_sender);
        let handle = Handle::new(control_sender);
        (
            Self {
                node,
                codec,
                finalized,
                genesis_alloc,
                genesis_tx,
                store: ChainStore::default(),
                received: BTreeMap::new(),
                pending_verifies: BTreeMap::new(),
                gossip: gossip.clone(),
                consensus,
                control,
            },
            consensus_mailbox,
            handle,
        )
    }

    fn digest_for_block(block: &Block) -> ConsensusDigest {
        let mut hasher = Sha256::default();
        let id = block_id(block);
        hasher.update(id.0.as_slice());
        hasher.finalize()
    }

    fn genesis_block() -> Block {
        Block {
            parent: BlockId(B256::ZERO),
            height: 0,
            prevrandao: B256::ZERO,
            state_root: StateRoot(B256::ZERO),
            txs: Vec::new(),
        }
    }

    fn block_cfg(codec: BlockCodecCfg) -> crate::types::BlockCfg {
        crate::types::BlockCfg {
            max_txs: codec.max_txs,
            tx: crate::types::TxCfg {
                max_calldata_bytes: codec.max_calldata_bytes,
            },
        }
    }

    fn decode_block(bytes: Bytes, cfg: &crate::types::BlockCfg) -> anyhow::Result<Block> {
        use commonware_codec::Decode as _;
        Ok(Block::decode_cfg(bytes.as_ref(), cfg)?)
    }

    fn build_child_block(parent: &Block, prevrandao: B256, txs: Vec<Tx>) -> Block {
        Block {
            parent: parent.id(),
            height: parent.height + 1,
            prevrandao,
            state_root: parent.state_root,
            txs,
        }
    }

    fn execute_block(
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
        let digest = Self::digest_for_block(&child);
        Ok((
            digest,
            BlockEntry {
                block: child,
                db,
                seed: None,
            },
        ))
    }

    fn try_verify_and_insert(
        store: &mut ChainStore,
        genesis_tx: &mut Option<Tx>,
        expected_digest: ConsensusDigest,
        context: &Context<ConsensusDigest, PublicKey>,
        block: Block,
    ) -> anyhow::Result<bool> {
        let clears_genesis_tx = block.height == 1;
        if Self::digest_for_block(&block) != expected_digest {
            return Ok(false);
        }
        let parent = store.get_by_digest(&context.parent.1).cloned();
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

        store.insert(
            expected_digest,
            BlockEntry {
                block,
                db,
                seed: None,
            },
        );
        if clears_genesis_tx {
            *genesis_tx = None;
        }
        Ok(true)
    }

    fn encode_block(block: &Block) -> Bytes {
        use commonware_codec::Encode as _;
        Bytes::copy_from_slice(block.encode().as_ref())
    }

    pub async fn run(self) {
        let Application {
            node,
            codec,
            finalized,
            genesis_alloc,
            genesis_tx,
            store,
            received,
            pending_verifies,
            gossip,
            consensus,
            control,
        } = self;

        let block_cfg = Self::block_cfg(codec);
        let mut runtime = Runtime {
            node,
            block_cfg,
            finalized,
            genesis_alloc,
            genesis_tx,
            store,
            received,
            pending_verifies,
            gossip,
        };
        let mut inbox =
            futures::stream::select(consensus.map(Input::Consensus), control.map(Input::Control));

        while let Some(event) = inbox.next().await {
            runtime.handle_input(event).await;
        }
    }
}

impl<S> Runtime<S>
where
    S: commonware_p2p::Sender<PublicKey = PublicKey> + Clone + Send + Sync + 'static,
{
    async fn handle_input(&mut self, input: Input) {
        match input {
            Input::Consensus(message) => self.handle_consensus(message).await,
            Input::Control(message) => self.handle_control(message),
        }
    }

    async fn handle_consensus(&mut self, message: ConsensusRequest) {
        match message {
            ConsensusRequest::Genesis { epoch, response } => {
                self.handle_genesis(epoch, response);
            }
            ConsensusRequest::Propose { context, response } => {
                self.handle_propose(context, response);
            }
            ConsensusRequest::Verify {
                context,
                digest,
                response,
            } => {
                self.handle_verify(context, digest, response);
            }
            ConsensusRequest::Broadcast { digest } => {
                self.handle_broadcast(digest).await;
            }
            ConsensusRequest::Report { activity } => {
                self.handle_report(activity);
            }
        }
    }

    fn handle_control(&mut self, message: ApplicationRequest) {
        match message {
            ApplicationRequest::QueryBalance {
                digest,
                address,
                response,
            } => self.handle_query_balance(digest, address, response),
            ApplicationRequest::QueryStateRoot { digest, response } => {
                self.handle_query_state_root(digest, response);
            }
            ApplicationRequest::QuerySeed { digest, response } => {
                self.handle_query_seed(digest, response)
            }
            ApplicationRequest::BlockReceived { from, bytes } => {
                self.handle_block_received(from, bytes);
            }
        }
    }

    fn handle_genesis(
        &mut self,
        epoch: commonware_consensus::types::Epoch,
        response: oneshot::Sender<ConsensusDigest>,
    ) {
        assert_eq!(epoch, commonware_consensus::types::Epoch::zero());

        let genesis_block = Application::<S>::genesis_block();
        let digest = Application::<S>::digest_for_block(&genesis_block);
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

        self.store.insert(
            digest,
            BlockEntry {
                block: genesis_block,
                db,
                seed: Some(B256::ZERO),
            },
        );
        let _ = response.send(digest);
    }

    fn handle_query_balance(
        &mut self,
        digest: ConsensusDigest,
        address: Address,
        response: oneshot::Sender<Option<U256>>,
    ) {
        let entry = self.store.get_by_digest(&digest).cloned();
        let value = entry
            .and_then(|mut e| e.db.basic(address).ok().flatten())
            .map(|info| info.balance);
        let _ = response.send(value);
    }

    fn handle_query_state_root(
        &mut self,
        digest: ConsensusDigest,
        response: oneshot::Sender<Option<StateRoot>>,
    ) {
        let entry = self.store.get_by_digest(&digest).cloned();
        let _ = response.send(entry.map(|e| e.block.state_root));
    }

    fn handle_query_seed(
        &mut self,
        digest: ConsensusDigest,
        response: oneshot::Sender<Option<B256>>,
    ) {
        let entry = self.store.get_by_digest(&digest);
        let _ = response.send(entry.and_then(|e| e.seed));
    }

    fn handle_propose(
        &mut self,
        context: Context<ConsensusDigest, PublicKey>,
        response: oneshot::Sender<ConsensusDigest>,
    ) {
        let parent = self.store.get_by_digest(&context.parent.1).cloned();
        let Some(parent) = parent else {
            return;
        };

        let prevrandao = parent.seed.unwrap_or(B256::from(context.parent.1 .0));
        let txs = if parent.block.height == 0 {
            self.genesis_tx.clone().into_iter().collect()
        } else {
            Vec::new()
        };
        let child = Application::<S>::build_child_block(&parent.block, prevrandao, txs);
        if let Ok((digest, entry)) = Application::<S>::execute_block(&parent, child) {
            let clears_genesis_tx = entry.block.height == 1;
            self.store.insert(digest, entry);
            if clears_genesis_tx {
                self.genesis_tx = None;
            }
            let _ = response.send(digest);
        }
    }

    fn handle_verify(
        &mut self,
        context: Context<ConsensusDigest, PublicKey>,
        digest: ConsensusDigest,
        response: oneshot::Sender<bool>,
    ) {
        if self.store.get_by_digest(&digest).is_some() {
            let _ = response.send(true);
            return;
        }

        if let Some(block) = self.received.get(&digest).cloned() {
            let ok = Application::<S>::try_verify_and_insert(
                &mut self.store,
                &mut self.genesis_tx,
                digest,
                &context,
                block,
            )
            .unwrap_or(false);
            if ok {
                self.received.remove(&digest);
            }
            let _ = response.send(ok);
            return;
        }

        self.pending_verifies
            .entry(digest)
            .or_default()
            .push((context, response));
    }

    fn handle_block_received(&mut self, from: PublicKey, bytes: Bytes) {
        let _ = from;
        let Ok(block) = Application::<S>::decode_block(bytes, &self.block_cfg) else {
            return;
        };

        let digest = Application::<S>::digest_for_block(&block);
        if self.store.get_by_digest(&digest).is_none() {
            self.received.entry(digest).or_insert(block);
        }
        self.flush_pending_verifies(digest);
    }

    fn flush_pending_verifies(&mut self, digest: ConsensusDigest) {
        let Some(pending) = self.pending_verifies.remove(&digest) else {
            return;
        };

        if self.store.get_by_digest(&digest).is_some() {
            for (_, response) in pending {
                let _ = response.send(true);
            }
            self.received.remove(&digest);
            return;
        }

        for (context, response) in pending {
            if self.store.get_by_digest(&digest).is_some() {
                let _ = response.send(true);
                continue;
            }
            let block = match self.received.get(&digest).cloned() {
                Some(b) => b,
                None => {
                    let _ = response.send(false);
                    continue;
                }
            };
            let ok = Application::<S>::try_verify_and_insert(
                &mut self.store,
                &mut self.genesis_tx,
                digest,
                &context,
                block,
            )
            .unwrap_or(false);
            if ok {
                self.received.remove(&digest);
            }
            let _ = response.send(ok);
        }
    }

    async fn handle_broadcast(&mut self, digest: ConsensusDigest) {
        let bytes = self
            .store
            .get_by_digest(&digest)
            .map(|entry| Application::<S>::encode_block(&entry.block));
        let Some(bytes) = bytes else {
            return;
        };
        let _ = self
            .gossip
            .send(commonware_p2p::Recipients::All, bytes, true)
            .await;
    }

    fn handle_report(&mut self, activity: ThresholdActivity) {
        match activity {
            Activity::Notarization(notarization) => {
                self.update_seed(
                    notarization.proposal.payload,
                    Self::seed_hash_from_seed(notarization.seed()),
                );
            }
            Activity::Finalization(finalization) => {
                self.update_seed(
                    finalization.proposal.payload,
                    Self::seed_hash_from_seed(finalization.seed()),
                );
                let _ = self
                    .finalized
                    .unbounded_send((self.node, finalization.proposal.payload));
            }
            _ => {}
        }
    }

    fn seed_hash_from_seed(seed: impl commonware_codec::Encode) -> B256 {
        keccak256(seed.encode())
    }

    fn update_seed(&mut self, digest: ConsensusDigest, seed_hash: B256) {
        if let Some(entry) = self.store.get_by_digest_mut(&digest) {
            entry.seed = Some(seed_hash);
        }
    }
}
