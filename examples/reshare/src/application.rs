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
        Application, Input, Proposed,
        db::{DatabaseSet, Merkleized as _, Unmerkleized as _},
    },
};
use commonware_runtime::{BufferPooler, Clock, Metrics, Spawner, Storage};
use commonware_storage::{mmr::Location, qmdb::sync::Target};
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
        batches: <Database<E> as DatabaseSet<E>>::Unmerkleized,
    ) -> <Database<E> as DatabaseSet<E>>::Merkleized {
        batches
            .write(HEIGHT_KEY, Some(U64::new(height.get())))
            .merkleize()
            .await
            .expect("height write must merkleize")
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
        batches: <Self::Databases as DatabaseSet<E>>::Unmerkleized,
        input: Input<Self::Input, Self::Provider>,
    ) -> Option<Proposed<Self, E>> {
        // The `reshare::Application` wrapper selected and fetched the payload.
        let payload = input.upstream.payload;
        let parent = ancestry.next().await?;
        let height = parent.height().next();
        let merkleized = Self::execute(height, batches).await;
        let bounds = merkleized.bounds();
        let block = Block {
            context: context.1,
            parent: parent.digest(),
            height,
            state_root: merkleized.root(),
            range: non_empty_range!(bounds.inactivity_floor, Location::new(bounds.total_size)),
            payload,
        };
        Some(Proposed { block, merkleized })
    }

    async fn verify(
        &mut self,
        _context: (E, Self::Context),
        mut ancestry: impl Ancestry<Self::Block>,
        batches: <Self::Databases as DatabaseSet<E>>::Unmerkleized,
    ) -> Option<<Self::Databases as DatabaseSet<E>>::Merkleized> {
        // Validation from higher layers:
        // - Epoch validation is handled by `Deferred`
        // - QMDB root / range validation is handled by `stateful::Application`
        // - Reshare `Payload` validation is handled by `reshare::Application`

        let block = ancestry.next().await?;
        let merkleized = Self::execute(block.height(), batches).await;
        Some(merkleized)
    }

    async fn apply(
        &mut self,
        _context: (E, Self::Context),
        block: &Self::Block,
        batches: <Self::Databases as DatabaseSet<E>>::Unmerkleized,
    ) -> <Self::Databases as DatabaseSet<E>>::Merkleized {
        Self::execute(block.height(), batches).await
    }

    fn sync_targets(block: &Self::Block) -> <Self::Databases as DatabaseSet<E>>::SyncTargets {
        Target::new(block.state_root, block.range.clone())
    }
}
