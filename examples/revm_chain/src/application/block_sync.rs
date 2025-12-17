//! Out-of-band block dissemination (gossip) for the example chain.
//!
//! Threshold-simplex orders opaque `ConsensusDigest`s. The full block bytes are delivered
//! separately. This module owns:
//! - receiving and decoding gossiped blocks,
//! - caching received blocks until consensus asks to verify them,
//! - deferring verification requests until the corresponding bytes arrive,
//! - broadcasting full blocks when the consensus engine requests it.

use super::store::{BlockEntry, ChainStore};
use crate::{
    consensus::{digest_for_block, ConsensusDigest, PublicKey},
    execution::{evm_env, execute_txs},
    types::Block,
};
use bytes::Bytes;
use commonware_consensus::simplex::types::Context;
use futures::channel::oneshot;
use std::collections::BTreeMap;

struct VerifyRequest {
    context: Context<ConsensusDigest, PublicKey>,
    response: oneshot::Sender<bool>,
}

type VerifyRequestsByDigest = BTreeMap<ConsensusDigest, Vec<VerifyRequest>>;

/// Owns out-of-band block dissemination for a node.
///
/// Consensus orders digests. This component ensures full block bytes are available for verification
/// by caching received blocks and deferring verification requests until the bytes arrive.
pub(super) struct BlockSync<S> {
    block_cfg: crate::types::BlockCfg,
    // NOTE: These caches are intentionally unbounded to keep the example focused on wiring.
    // Production code should add a block fetch/resolver path and bound these with pruning or an LRU.
    received: BTreeMap<ConsensusDigest, Block>,
    pending_verify_requests: VerifyRequestsByDigest,
    gossip: S,
}

impl<S> BlockSync<S>
where
    S: commonware_p2p::Sender<PublicKey = PublicKey> + Clone + Send + Sync + 'static,
{
    pub(super) const fn new(block_cfg: crate::types::BlockCfg, gossip: S) -> Self {
        Self {
            block_cfg,
            received: BTreeMap::new(),
            pending_verify_requests: BTreeMap::new(),
            gossip,
        }
    }

    pub(super) fn handle_verify_request(
        &mut self,
        store: &mut ChainStore,
        context: Context<ConsensusDigest, PublicKey>,
        digest: ConsensusDigest,
        response: oneshot::Sender<bool>,
    ) {
        if store.get_by_digest(&digest).is_some() {
            let ok = verify_stored_block_against_context(store, &context, &digest);
            let _ = response.send(ok);
            return;
        }

        if let Some(block) = self.received.get(&digest).cloned() {
            let ok = try_verify_and_insert(store, digest, &context, block).unwrap_or(false);
            if ok {
                self.received.remove(&digest);
            }
            let _ = response.send(ok);
            return;
        }

        self.pending_verify_requests
            .entry(digest)
            .or_default()
            .push(VerifyRequest { context, response });
    }

    pub(super) fn handle_block_received(
        &mut self,
        store: &mut ChainStore,
        from: PublicKey,
        bytes: Bytes,
    ) {
        // `from` is currently unused, but is kept to make it clear where the bytes came from.
        let _ = from;
        let Ok(block) = decode_block(bytes, &self.block_cfg) else {
            return;
        };

        let digest = digest_for_block(&block);
        if store.get_by_digest(&digest).is_none() {
            self.received.entry(digest).or_insert(block);
        }
        self.flush_pending_verifies(store, digest);
    }

    pub(super) async fn broadcast_block(&mut self, store: &ChainStore, digest: ConsensusDigest) {
        let bytes = store
            .get_by_digest(&digest)
            .map(|entry| encode_block(&entry.block));
        let Some(bytes) = bytes else {
            return;
        };
        let _ = self
            .gossip
            .send(commonware_p2p::Recipients::All, bytes, true)
            .await;
    }

    fn flush_pending_verifies(&mut self, store: &mut ChainStore, digest: ConsensusDigest) {
        let Some(pending) = self.pending_verify_requests.remove(&digest) else {
            return;
        };

        if store.get_by_digest(&digest).is_some() {
            for request in pending {
                let ok = verify_stored_block_against_context(store, &request.context, &digest);
                let _ = request.response.send(ok);
            }
            self.received.remove(&digest);
            return;
        }

        for request in pending {
            if store.get_by_digest(&digest).is_some() {
                let ok = verify_stored_block_against_context(store, &request.context, &digest);
                let _ = request.response.send(ok);
                continue;
            }
            let block = match self.received.get(&digest).cloned() {
                Some(b) => b,
                None => {
                    let _ = request.response.send(false);
                    continue;
                }
            };
            let ok = try_verify_and_insert(store, digest, &request.context, block).unwrap_or(false);
            if ok {
                self.received.remove(&digest);
            }
            let _ = request.response.send(ok);
        }
    }
}

fn decode_block(bytes: Bytes, cfg: &crate::types::BlockCfg) -> anyhow::Result<Block> {
    use commonware_codec::Decode as _;
    Ok(Block::decode_cfg(bytes.as_ref(), cfg)?)
}

fn encode_block(block: &Block) -> Bytes {
    use commonware_codec::Encode as _;
    Bytes::copy_from_slice(block.encode().as_ref())
}

fn verify_stored_block_against_context(
    store: &ChainStore,
    context: &Context<ConsensusDigest, PublicKey>,
    digest: &ConsensusDigest,
) -> bool {
    let Some(entry) = store.get_by_digest(digest) else {
        return false;
    };
    let Some(parent) = store.get_by_digest(&context.parent.1) else {
        return false;
    };
    entry.block.parent == parent.block.id() && entry.block.height == parent.block.height + 1
}

fn try_verify_and_insert(
    store: &mut ChainStore,
    expected_digest: ConsensusDigest,
    context: &Context<ConsensusDigest, PublicKey>,
    block: Block,
) -> anyhow::Result<bool> {
    if digest_for_block(&block) != expected_digest {
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
    Ok(true)
}
