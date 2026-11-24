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
        Application, ExecutionError, Finality, Input, Proposed,
        db::{DatabaseSet, Unmerkleized as _},
    },
};
use commonware_runtime::{Clock, Metrics, Spawner, Storage};
use commonware_storage::qmdb::sync::Target;
use commonware_utils::sequence::U64;
use futures::StreamExt;

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

    async fn execute<E: Spawner + Metrics + Clock + Storage>(
        height: Height,
        batches: <Database<E> as DatabaseSet<E>>::Unmerkleized,
    ) -> Result<<Database<E> as DatabaseSet<E>>::Merkleized, ExecutionError> {
        Ok(batches
            .write(HEIGHT_KEY, Some(U64::new(height.get())))
            .merkleize()
            .await?)
    }
}

impl<E> Application<E> for App
where
    E: Spawner + Metrics + Clock + Storage,
{
    type SigningScheme = Scheme;
    type Context = Context<sha256::Digest, ed25519::PublicKey>;
    type Block = Block;
    type Databases = Database<E>;
    type Captured = ();
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
    ) -> Result<Option<Proposed<Self, E>>, ExecutionError> {
        // The `reshare::Application` wrapper selected and fetched the payload.
        let payload = input.upstream.payload;
        let Some(parent) = ancestry.next().await else {
            return Ok(None);
        };
        let height = parent.height().next();
        let merkleized = Self::execute(height, batches).await?;
        let block = Block::new(
            context.1,
            parent.digest(),
            height,
            merkleized.target(),
            payload,
        );
        Ok(Some(Proposed { block, merkleized }))
    }

    async fn process(
        &mut self,
        _context: (E, Self::Context),
        ancestry: impl Ancestry<Self::Block>,
        batches: <Self::Databases as DatabaseSet<E>>::Unmerkleized,
        _finality: Finality,
    ) -> Result<Option<<Self::Databases as DatabaseSet<E>>::Merkleized>, ExecutionError> {
        // TODO (#5509): Explore direct composition of stateful and DKG validation.
        //
        // Validation from higher layers:
        // - Epoch validation is handled by `Deferred`
        // - QMDB root / range validation is handled by `stateful::Application`
        // - Reshare `Payload` validation is handled by `reshare::Application`
        let Some(block) = ancestry.peek() else {
            return Ok(None);
        };
        let height = block.height();
        Ok(Some(Self::execute(height, batches).await?))
    }

    async fn capture(
        &mut self,
        _context: (E, Self::Context),
        _block: &Self::Block,
        _batches: &<Self::Databases as DatabaseSet<E>>::Merkleized,
        _readers: <Self::Databases as DatabaseSet<E>>::Readers,
    ) {
    }

    async fn finalized(
        &mut self,
        _context: (E, Self::Context),
        _block: &Self::Block,
        _captured: Self::Captured,
        _readers: <Self::Databases as DatabaseSet<E>>::Readers,
    ) {
    }

    fn sync_targets(block: &Self::Block) -> <Self::Databases as DatabaseSet<E>>::SyncTargets {
        Target {
            root: block.state_root,
            range: block.range.clone(),
        }
    }
}
