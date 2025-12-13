use super::{
    store::{BlockEntry, ChainStore},
    BlockCodecCfg, ControlMessage, Handle,
};
use crate::consensus::{ConsensusDigest, FinalizationEvent, IngressMessage, PublicKey};
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
    ingress: mpsc::Receiver<IngressMessage>,
    control: mpsc::Receiver<ControlMessage>,
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
        let (ingress_sender, ingress) = mpsc::channel(mailbox_size);
        let (control_sender, control) = mpsc::channel(mailbox_size);
        let consensus = crate::consensus::Mailbox::new(ingress_sender);
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
                ingress,
                control,
            },
            consensus,
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
        enum Event {
            Ingress(IngressMessage),
            Control(ControlMessage),
        }

        let Application {
            node,
            codec,
            finalized,
            genesis_alloc,
            mut genesis_tx,
            mut store,
            mut received,
            mut pending_verifies,
            mut gossip,
            ingress,
            control,
        } = self;

        let cfg = Self::block_cfg(codec);
        let mut inbox =
            futures::stream::select(ingress.map(Event::Ingress), control.map(Event::Control));

        while let Some(event) = inbox.next().await {
            match event {
                Event::Ingress(IngressMessage::Genesis { epoch, response }) => {
                    assert_eq!(epoch, commonware_consensus::types::Epoch::zero());
                    let genesis_block = Self::genesis_block();
                    let digest = Self::digest_for_block(&genesis_block);
                    let mut db = InMemoryDB::default();
                    for (address, balance) in genesis_alloc.iter().copied() {
                        db.insert_account_info(
                            address,
                            AccountInfo {
                                balance,
                                nonce: 0,
                                ..Default::default()
                            },
                        );
                    }
                    store.insert(
                        digest,
                        BlockEntry {
                            block: genesis_block,
                            db,
                            seed: Some(B256::ZERO),
                        },
                    );
                    let _ = response.send(digest);
                }
                Event::Control(ControlMessage::QueryBalance {
                    digest,
                    address,
                    response,
                }) => {
                    let entry = store.get_by_digest(&digest).cloned();
                    let value = entry
                        .and_then(|mut e| e.db.basic(address).ok().flatten())
                        .map(|info| info.balance);
                    let _ = response.send(value);
                }
                Event::Control(ControlMessage::QueryStateRoot { digest, response }) => {
                    let entry = store.get_by_digest(&digest).cloned();
                    let _ = response.send(entry.map(|e| e.block.state_root));
                }
                Event::Control(ControlMessage::QuerySeed { digest, response }) => {
                    let entry = store.get_by_digest(&digest);
                    let _ = response.send(entry.and_then(|e| e.seed));
                }
                Event::Ingress(IngressMessage::Propose { context, response }) => {
                    let parent = store.get_by_digest(&context.parent.1).cloned();
                    let Some(parent) = parent else {
                        continue;
                    };
                    let prevrandao = parent.seed.unwrap_or(B256::from(context.parent.1 .0));
                    let txs = if parent.block.height == 0 {
                        genesis_tx.clone().into_iter().collect()
                    } else {
                        Vec::new()
                    };
                    let child = Self::build_child_block(&parent.block, prevrandao, txs);
                    if let Ok((digest, entry)) = Self::execute_block(&parent, child) {
                        let clears_genesis_tx = entry.block.height == 1;
                        store.insert(digest, entry);
                        if clears_genesis_tx {
                            genesis_tx = None;
                        }
                        let _ = response.send(digest);
                    }
                }
                Event::Ingress(IngressMessage::Verify {
                    context,
                    digest,
                    response,
                }) => {
                    let already = store.get_by_digest(&digest).is_some();
                    if already {
                        let _ = response.send(true);
                        continue;
                    }

                    if let Some(block) = received.get(&digest).cloned() {
                        match Self::try_verify_and_insert(
                            &mut store,
                            &mut genesis_tx,
                            digest,
                            &context,
                            block,
                        ) {
                            Ok(ok) => {
                                let _ = response.send(ok);
                            }
                            Err(_) => {
                                let _ = response.send(false);
                            }
                        }
                        continue;
                    }

                    pending_verifies
                        .entry(digest)
                        .or_default()
                        .push((context, response));
                }
                Event::Control(ControlMessage::BlockReceived { from, bytes }) => {
                    let _ = from;
                    let Ok(block) = Self::decode_block(bytes.clone(), &cfg) else {
                        continue;
                    };
                    let digest = Self::digest_for_block(&block);
                    received.entry(digest).or_insert(block);

                    if let Some(pending) = pending_verifies.remove(&digest) {
                        for (context, response) in pending {
                            let block = match received.get(&digest).cloned() {
                                Some(b) => b,
                                None => {
                                    let _ = response.send(false);
                                    continue;
                                }
                            };
                            let ok = Self::try_verify_and_insert(
                                &mut store,
                                &mut genesis_tx,
                                digest,
                                &context,
                                block,
                            )
                            .unwrap_or(false);
                            let _ = response.send(ok);
                        }
                    }
                }
                Event::Ingress(IngressMessage::Broadcast { digest }) => {
                    let bytes = store
                        .get_by_digest(&digest)
                        .map(|entry| Self::encode_block(&entry.block));
                    let Some(bytes) = bytes else {
                        continue;
                    };
                    let _ = gossip
                        .send(commonware_p2p::Recipients::All, bytes, true)
                        .await;
                }
                Event::Ingress(IngressMessage::Report { activity }) => match activity {
                    Activity::Notarization(notarization) => {
                        use commonware_codec::Encode as _;
                        let seed_hash = keccak256(notarization.seed().encode());
                        if let Some(entry) = store.get_by_digest_mut(&notarization.proposal.payload)
                        {
                            entry.seed = Some(seed_hash);
                        }
                    }
                    Activity::Finalization(finalization) => {
                        use commonware_codec::Encode as _;
                        let seed_hash = keccak256(finalization.seed().encode());
                        if let Some(entry) = store.get_by_digest_mut(&finalization.proposal.payload)
                        {
                            entry.seed = Some(seed_hash);
                        }
                        let _ = finalized.unbounded_send((node, finalization.proposal.payload));
                    }
                    _ => {}
                },
            }
        }
    }
}
