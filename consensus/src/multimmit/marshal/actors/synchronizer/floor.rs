//! Verification and installation of a floor checkpoint.

use super::{
    actor::Core,
    inbox::Absorb,
    mailbox::Error,
    ports::{CatalogPort, Fetcher},
};
use crate::{
    Viewable as _,
    multimmit::{
        marshal::{
            protocol::floor,
            storage::{
                catalog_state::{Checkpoint, CheckpointParts, PendingFloors, frontier_index},
                scratch::{BlockStack, HistoryStack},
            },
            types::{Floor, LqcVerifier},
        },
        types::{Body, HistoryRecord, Lqc},
    },
    types::View,
};
use commonware_cryptography::{Hasher, bls12381::primitives::variant::Variant};
use std::sync::Arc;

/// A floor checkpoint that passed verification, ready for catalog installation.
struct VerifiedFloor<H: Hasher, V: Variant> {
    checkpoint: Checkpoint<H::Digest>,
    prune: PendingFloors,
    proof: Arc<Lqc<V, H::Digest>>,
    history: Arc<HistoryRecord<H::Digest>>,
}

impl<I, C, F, S, K, Q, H, V, B> Core<I, C, F, S, K, Q, H, V, B>
where
    I: Absorb<V, H::Digest>,
    C: CatalogPort<H, V, B>,
    F: Fetcher<H, V, B>,
    S: HistoryStack<H>,
    K: BlockStack<H::Digest>,
    Q: LqcVerifier<H, V>,
    H: Hasher,
    V: Variant,
    B: Body<H>,
    Error: From<C::Error> + From<F::Error> + From<S::Error> + From<K::Error>,
{
    /// Verifies `candidate` and installs it as the next floor generation.
    #[tracing::instrument(
        name = "multimmit.marshal.synchronizer.apply_floor",
        level = "info",
        skip_all
    )]
    pub(super) async fn install_floor(
        &mut self,
        candidate: Floor<V, H::Digest>,
    ) -> Result<(), Error> {
        let floor_generation = self
            .floor_generation
            .checked_add(1)
            .ok_or(Error::GenerationExhausted)?;
        let verified = self.verify_floor(floor_generation, candidate).await?;
        self.install_verified(verified).await
    }

    /// Checks `candidate` against the current state and verifies its L-QC's signature.
    async fn verify_floor(
        &mut self,
        floor_generation: u64,
        candidate: Floor<V, H::Digest>,
    ) -> Result<VerifiedFloor<H, V>, Error> {
        let Floor { lqc, opening } = candidate;
        if lqc.view() <= self.floor_view {
            return Err(Error::Invalid("floor is stale"));
        }
        // Check the floor's shape before paying for its signature.
        let (view, _) =
            floor::validate::<H, V>(&self.state, &lqc, &opening, self.epoch, self.codec)?;
        let floor_index = frontier_index(opening.tips())
            .ok_or(Error::Invalid("floor frontier overflows the output index"))?;
        self.verifier
            .verify(&lqc)
            .await
            .map_err(|error| Error::Verify(Box::new(error)))?;

        let history_index = Some(self.next_history_index()?);
        let checkpoint = Checkpoint::try_from(CheckpointParts {
            epoch: self.epoch,
            floor_generation,
            archive_layout: self.archive_layout,
            floor: lqc.id::<H>(),
            view,
            history: lqc.leader().history(),
            history_index,
            ordered: opening.tips().to_vec(),
            floor_index,
            emitted: opening.tips().to_vec(),
        })
        .map_err(|_| Error::Invalid("floor checkpoint is not canonical"))?;
        let pending = View::new(lqc.view().get().saturating_add(1));
        let prune = PendingFloors {
            lqc: pending,
            history: pending,
            blocks: opening.tips().iter().map(|tip| tip.height()).collect(),
        };
        Ok(VerifiedFloor {
            checkpoint,
            prune,
            proof: lqc,
            history: opening,
        })
    }

    /// Installs `verified` once every started commit is durable, then adopts the installed
    /// checkpoint.
    async fn install_verified(&mut self, verified: VerifiedFloor<H, V>) -> Result<(), Error> {
        self.finish_commits().await?;
        let view = verified.proof.view();
        self.catalog
            .install(
                verified.checkpoint,
                verified.prune,
                verified.proof,
                verified.history,
            )
            .await?;
        let checkpoint = self.catalog.checkpoint().await?;
        self.adopt(&checkpoint, view)?;
        self.headers.clear();
        Ok(())
    }
}
