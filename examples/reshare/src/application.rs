//! Stateful application that records each block's height in QMDB.

use crate::types::{Block, Database, Scheme};
use commonware_consensus::{
    Heightable as _, marshal::ancestry::Ancestry, simplex::types::Context, types::Height,
};
use commonware_cryptography::{
    Digestible as _, bls12381::primitives::variant::MinSig, ed25519, sha256,
};
use commonware_glue::{
    dkg::reshare::Input as ReshareInput,
    stateful::{
        Application, ExecutionError, Input, Proposed,
        db::{DatabaseSet, Merkleized as _, MerkleizedOf, Unmerkleized as _, UnmerkleizedOf},
    },
};
use commonware_runtime::{BufferPooler, Clock, Metrics, Spawner, Storage};
use commonware_storage::qmdb::sync::Target;
use commonware_utils::{non_empty_range, sequence::U64};
use futures::StreamExt;
use rand::Rng;

const HEIGHT_KEY: U64 = U64::new(0);

/// Application logic: every non-genesis block writes its height to one fixed key.
#[derive(Clone)]
pub struct App {
    genesis: Block,
}

impl App {
    /// Create the application with its genesis block.
    pub const fn new(genesis: Block) -> Self {
        Self { genesis }
    }

    async fn execute<E: Spawner + Metrics + Clock + Storage + BufferPooler>(
        height: Height,
        batches: UnmerkleizedOf<Database<E>, E>,
    ) -> Result<MerkleizedOf<Database<E>, E>, ExecutionError> {
        Ok(batches
            .write(HEIGHT_KEY, Some(U64::new(height.get())))
            .merkleize()
            .await?)
    }
}

impl<E> Application<E> for App
where
    E: Rng + Spawner + Metrics + Clock + Storage + BufferPooler,
{
    type SigningScheme = Scheme;
    type Context = Context<sha256::Digest, ed25519::PublicKey>;
    type Block = Block;
    type Databases = Database<E>;
    type Provider = ();
    type Input = ReshareInput<(), MinSig, ed25519::PrivateKey>;

    async fn genesis(&mut self) -> Self::Block {
        self.genesis.clone()
    }

    async fn propose(
        &mut self,
        context: (E, Self::Context),
        mut ancestry: impl Ancestry<Self::Block>,
        batches: UnmerkleizedOf<Self::Databases, E>,
        input: Input<Self::Input, Self::Provider>,
    ) -> Result<Option<Proposed<Self, E>>, ExecutionError> {
        // The `reshare::Application` wrapper selected and fetched the payload.
        let payload = input.upstream.payload;
        let Some(parent) = ancestry.next().await else {
            return Ok(None);
        };
        let height = parent.height().next();
        let merkleized = Self::execute(height, batches).await?;
        let bounds = merkleized.bounds();
        let block = Block {
            context: context.1,
            parent: parent.digest(),
            height,
            state_root: merkleized.root(),
            range: non_empty_range!(bounds.inactivity_floor, bounds.tip.size),
            payload,
        };
        Ok(Some(Proposed { block, merkleized }))
    }

    async fn verify(
        &mut self,
        _context: (E, Self::Context),
        mut ancestry: impl Ancestry<Self::Block>,
        batches: UnmerkleizedOf<Self::Databases, E>,
    ) -> Result<Option<MerkleizedOf<Self::Databases, E>>, ExecutionError> {
        // Validation from higher layers:
        // - Epoch validation is handled by `Deferred`
        // - QMDB root / range validation is handled by `stateful::Application`
        // - Reshare `Payload` validation is handled by `reshare::Application`

        let Some(block) = ancestry.next().await else {
            return Ok(None);
        };
        let merkleized = Self::execute(block.height(), batches).await?;
        Ok(Some(merkleized))
    }

    async fn apply(
        &mut self,
        _context: (E, Self::Context),
        block: &Self::Block,
        batches: UnmerkleizedOf<Self::Databases, E>,
    ) -> Result<MerkleizedOf<Self::Databases, E>, ExecutionError> {
        Self::execute(block.height(), batches).await
    }

    fn sync_targets(block: &Self::Block) -> <Self::Databases as DatabaseSet<E>>::SyncTargets {
        Target::new(block.state_root, block.range.clone())
    }
}
