use super::state::Shared;
use crate::{
    consensus::{digest_for_block, ConsensusDigest, PublicKey},
    execution::{evm_env, execute_txs},
    types::{Block, TxId},
};
use alloy_evm::revm::primitives::B256;
use commonware_consensus::{
    marshal::ingress::mailbox::AncestorStream,
    simplex::{signing_scheme::Scheme, types::Context},
    Application, VerifyingApplication,
};
use commonware_runtime::{Clock, Metrics, Spawner};
use futures::StreamExt as _;
use rand::Rng;
use std::{collections::BTreeSet, marker::PhantomData};

#[derive(Clone)]
pub(crate) struct RevmApplication<S> {
    max_txs: usize,
    state: Shared,
    _scheme: PhantomData<S>,
}

impl<S> RevmApplication<S> {
    pub(crate) const fn new(max_txs: usize, state: Shared) -> Self {
        Self {
            max_txs,
            state,
            _scheme: PhantomData,
        }
    }
}

impl<E, S> Application<E> for RevmApplication<S>
where
    E: Rng + Spawner + Metrics + Clock,
    S: Scheme<PublicKey = PublicKey>,
{
    type SigningScheme = S;
    type Context = Context<ConsensusDigest, PublicKey>;
    type Block = Block;

    async fn genesis(&mut self) -> Self::Block {
        self.state.genesis_block()
    }

    async fn propose(
        &mut self,
        _context: (E, Self::Context),
        mut ancestry: AncestorStream<Self::SigningScheme, Self::Block>,
    ) -> Option<Self::Block> {
        let parent = ancestry.next().await?;

        let mut included = BTreeSet::<TxId>::new();
        for tx in parent.txs.iter() {
            included.insert(tx.id());
        }
        while let Some(block) = ancestry.next().await {
            for tx in block.txs.iter() {
                included.insert(tx.id());
            }
        }

        let parent_digest = digest_for_block(&parent);
        let parent_state = self.state.parent_state(&parent_digest).await?;
        let seed_hash = self.state.seed_for_parent(&parent_digest).await;
        let prevrandao = seed_hash.unwrap_or_else(|| B256::from(parent_digest.0));

        let txs = self.state.build_txs(self.max_txs, &included).await;

        let mut child = Block {
            parent: parent.id(),
            height: parent.height + 1,
            prevrandao,
            state_root: parent.state_root,
            txs,
        };

        let (db, outcome) = execute_txs(
            parent_state.db,
            evm_env(child.height, child.prevrandao),
            parent.state_root,
            &child.txs,
        )
        .ok()?;
        child.state_root = outcome.state_root;

        let digest = digest_for_block(&child);
        self.state.insert_verified(digest, child.clone(), db).await;
        Some(child)
    }
}

impl<E, S> VerifyingApplication<E> for RevmApplication<S>
where
    E: Rng + Spawner + Metrics + Clock,
    S: Scheme<PublicKey = PublicKey>,
{
    async fn verify(
        &mut self,
        _context: (E, Self::Context),
        mut ancestry: AncestorStream<Self::SigningScheme, Self::Block>,
    ) -> bool {
        let block = match ancestry.next().await {
            Some(block) => block,
            None => return false,
        };
        let parent = match ancestry.next().await {
            Some(block) => block,
            None => return false,
        };

        let parent_digest = digest_for_block(&parent);
        let Some(parent_state) = self.state.parent_state(&parent_digest).await else {
            return false;
        };

        let (db, outcome) = match execute_txs(
            parent_state.db,
            evm_env(block.height, block.prevrandao),
            parent.state_root,
            &block.txs,
        ) {
            Ok(result) => result,
            Err(_) => return false,
        };
        if outcome.state_root != block.state_root {
            return false;
        }

        let digest = digest_for_block(&block);
        self.state.insert_verified(digest, block, db).await;
        true
    }
}
