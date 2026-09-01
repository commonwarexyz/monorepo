//! Verification and installation of a floor checkpoint.

use super::{
    actor::Core,
    inbox::Absorb,
    mailbox::Error,
    ports::{CatalogPort, Fetcher},
};
use crate::{
    Epochable as _, Viewable as _,
    multimmit::{
        marshal::{
            protocol::{floor, order::HistoryState},
            storage::{
                catalog_state::{Checkpoint, CheckpointParts, PendingFloors},
                scratch::{BlockStack, HistoryStack},
            },
            types::{Floor, LqcVerifier},
        },
        types::{Body, Lqc, TipRecord},
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
    history: Arc<TipRecord<H::Digest>>,
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

    /// Verifies the anchor of `candidate`, checks its frontiers against the current state, and
    /// authenticates the ancestry between its emitted frontier and the anchor's final tips.
    async fn verify_floor(
        &mut self,
        floor_generation: u64,
        candidate: Floor<V, H::Digest>,
    ) -> Result<VerifiedFloor<H, V>, Error> {
        let anchor_id = candidate.anchor.id::<H>();
        if candidate.anchor.epoch() != self.epoch || candidate.anchor.view() <= self.floor_view {
            return Err(Error::Invalid(
                "floor anchor is stale or has an epoch mismatch",
            ));
        }
        self.verifier
            .verify(&candidate.anchor)
            .await
            .map_err(|error| Error::Verify(Box::new(error)))?;
        let floor::Frontiers {
            history,
            ordered,
            target,
        } = floor::validate::<H, V>(
            &self.state,
            &candidate.anchor,
            &candidate.history,
            &candidate.emitted,
            self.codec,
        )?;
        let common = self.common_frontiers(&target, &candidate.emitted).await?;
        HistoryState::new(history, ordered.clone(), candidate.emitted.clone())?
            .validate_reconciliation(&target, &common)?;

        let history_index = Some(match self.history_index {
            Some(index) => index.checked_add(1).ok_or(Error::HistoryIndexExhausted)?,
            None => 0,
        });
        let checkpoint = Checkpoint::try_from(CheckpointParts {
            epoch: self.epoch,
            floor_generation,
            archive_layout: self.archive_layout,
            floor: anchor_id,
            history,
            history_index,
            ordered,
            emitted: candidate.emitted.clone(),
            committed: self.committed,
        })
        .map_err(|_| Error::Invalid("floor checkpoint is not canonical"))?;
        let pending = View::new(candidate.anchor.view().get().saturating_add(1));
        let prune = PendingFloors {
            lqc: pending,
            history: pending,
            blocks: candidate
                .emitted
                .iter()
                .map(|reference| reference.height())
                .collect(),
        };
        Ok(VerifiedFloor {
            checkpoint,
            prune,
            proof: candidate.anchor,
            history: candidate.history,
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
        self.floor_generation = checkpoint.floor_generation();
        self.floor = checkpoint.floor();
        self.floor_view = view;
        self.history_index = checkpoint.history_index();
        self.committed = checkpoint.committed();
        self.state = HistoryState::new(
            checkpoint.history(),
            checkpoint.ordered().to_vec(),
            checkpoint.emitted().to_vec(),
        )?;
        self.headers.clear();
        Ok(())
    }
}
