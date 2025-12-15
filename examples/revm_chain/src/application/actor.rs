//! Chain application actor.
//!
//! Owns per-node chain logic: proposing/verifying blocks, maintaining per-block EVM snapshots, and
//! tracking consensus seed output for EVM `prevrandao`.
//!
//! The consensus engine orders only opaque digests. Full blocks are delivered out-of-band
//! (see `BlockSync`) and cached until consensus requests verification.

use super::{
    block_sync::BlockSync,
    store::{BlockEntry, ChainStore},
    ApplicationRequest, BlockCodecCfg, Handle,
};
use crate::{
    consensus::{
        digest_for_block, ConsensusDigest, ConsensusRequest, FinalizationEvent, PublicKey,
    },
    execution::{evm_env, execute_txs},
    types::{Block, BlockId, StateRoot, Tx, TxId},
};
use alloy_evm::revm::{
    database::InMemoryDB,
    primitives::{keccak256, Address, B256, U256},
    state::AccountInfo,
    Database as _,
};
use commonware_consensus::simplex::{
    signing_scheme::bls12381_threshold::Seedable as _,
    types::{Activity, Context},
};
use futures::{
    channel::{mpsc, oneshot},
    StreamExt as _,
};
use std::collections::{BTreeMap, BTreeSet};

type ThresholdActivity = <crate::consensus::Mailbox as commonware_consensus::Reporter>::Activity;

/// Chain application actor.
///
/// This actor owns "chain state" for a single node:
/// - a local store of verified blocks (keyed by the digest that consensus orders),
/// - the corresponding EVM state snapshots used to re-execute proposals deterministically,
/// - and a small control plane used by the simulation harness to query outcomes.
pub struct Application<S> {
    node: u32,
    codec: BlockCodecCfg,
    finalized: mpsc::UnboundedSender<FinalizationEvent>,
    genesis_alloc: Vec<(Address, U256)>,
    store: ChainStore,
    gossip: S,
    consensus: mpsc::Receiver<ConsensusRequest>,
    control: mpsc::Receiver<ApplicationRequest>,
}

/// Merged stream item for the application inbox.
enum Input {
    Consensus(Box<ConsensusRequest>),
    Control(Box<ApplicationRequest>),
}

/// Mutable runtime state for the application actor.
struct Runtime<S> {
    node: u32,
    finalized: mpsc::UnboundedSender<FinalizationEvent>,
    genesis_alloc: Vec<(Address, U256)>,
    /// Node-local mempool used for deterministic block construction.
    ///
    /// This is intentionally minimal:
    /// - transactions are submitted via the simulation control plane (see `ApplicationRequest::SubmitTx`)
    /// - ordering is deterministic (`BTreeMap` by `TxId`)
    /// - transactions are pruned only after finalization
    mempool: BTreeMap<TxId, Tx>,
    max_txs: usize,
    store: ChainStore,
    sync: BlockSync<S>,
}

impl<S> Application<S>
where
    S: commonware_p2p::Sender<PublicKey = PublicKey> + Clone + Send + Sync + 'static,
{
    /// Create a new application actor and the handles used by consensus and the simulation.
    pub fn new(
        node: u32,
        codec: BlockCodecCfg,
        mailbox_size: usize,
        gossip: S,
        finalized: mpsc::UnboundedSender<FinalizationEvent>,
        genesis_alloc: Vec<(Address, U256)>,
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
                store: ChainStore::default(),
                gossip,
                consensus,
                control,
            },
            consensus_mailbox,
            handle,
        )
    }

    const fn genesis_block() -> Block {
        Block {
            parent: BlockId(B256::ZERO),
            height: 0,
            prevrandao: B256::ZERO,
            state_root: StateRoot(B256::ZERO),
            txs: Vec::new(),
        }
    }

    const fn block_cfg(codec: BlockCodecCfg) -> crate::types::BlockCfg {
        crate::types::BlockCfg {
            max_txs: codec.max_txs,
            tx: crate::types::TxCfg {
                max_calldata_bytes: codec.max_calldata_bytes,
            },
        }
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
        let digest = digest_for_block(&child);
        Ok((
            digest,
            BlockEntry {
                block: child,
                db,
                seed: None,
            },
        ))
    }

    /// Start the actor event loop.
    pub async fn run(self) {
        let Self {
            node,
            codec,
            finalized,
            genesis_alloc,
            store,
            gossip,
            consensus,
            control,
        } = self;

        let block_cfg = Self::block_cfg(codec);
        let sync = BlockSync::new(block_cfg, gossip);
        let mut runtime = Runtime {
            node,
            finalized,
            genesis_alloc,
            mempool: BTreeMap::new(),
            max_txs: block_cfg.max_txs,
            store,
            sync,
        };
        let mut inbox = futures::stream::select(
            consensus.map(|m| Input::Consensus(Box::new(m))),
            control.map(|m| Input::Control(Box::new(m))),
        );

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
            Input::Consensus(message) => self.handle_consensus(*message).await,
            Input::Control(message) => self.handle_control(*message),
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
                self.sync
                    .handle_verify_request(&mut self.store, context, digest, response);
            }
            ConsensusRequest::Broadcast { digest } => {
                self.sync.broadcast_block(&self.store, digest).await;
            }
            ConsensusRequest::Report { activity } => {
                self.handle_report(activity);
            }
        }
    }

    fn handle_control(&mut self, message: ApplicationRequest) {
        match message {
            ApplicationRequest::SubmitTx { tx, response } => self.handle_submit_tx(tx, response),
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
                self.sync
                    .handle_block_received(&mut self.store, from, bytes);
            }
        }
    }

    fn handle_submit_tx(&mut self, tx: Tx, response: oneshot::Sender<bool>) {
        let id = tx.id();
        let inserted = self.mempool.insert(id, tx).is_none();
        let _ = response.send(inserted);
    }

    fn handle_genesis(
        &mut self,
        epoch: commonware_consensus::types::Epoch,
        response: oneshot::Sender<ConsensusDigest>,
    ) {
        assert_eq!(epoch, commonware_consensus::types::Epoch::zero());

        let genesis_block = Application::<S>::genesis_block();
        let digest = digest_for_block(&genesis_block);
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

        let included = self.included_tx_ids(&parent);
        let txs = self
            .mempool
            .iter()
            .filter(|(tx_id, _)| !included.contains(tx_id))
            .take(self.max_txs)
            .map(|(_, tx)| tx.clone())
            .collect::<Vec<_>>();
        let child = Application::<S>::build_child_block(&parent.block, prevrandao, txs);
        if let Ok((digest, entry)) = Application::<S>::execute_block(&parent, child) {
            self.store.insert(digest, entry);
            let _ = response.send(digest);
        }
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
                if let Some(entry) = self.store.get_by_digest(&finalization.proposal.payload) {
                    for tx in entry.block.txs.iter() {
                        self.mempool.remove(&tx.id());
                    }
                }
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

    fn included_tx_ids(&self, parent: &BlockEntry) -> BTreeSet<TxId> {
        let mut included = BTreeSet::new();
        let mut cursor = &parent.block;
        loop {
            for tx in cursor.txs.iter() {
                included.insert(tx.id());
            }
            if cursor.height == 0 {
                break;
            }
            let Some(next) = self.store.get_by_id(&cursor.parent) else {
                break;
            };
            cursor = &next.block;
        }
        included
    }
}
