//! The floor installation protocol: begin, archive, finish.

use super::CatalogStore;
use crate::{
    Epochable as _, Viewable as _,
    multimmit::{
        marshal::storage::{
            Error,
            catalog_state::{Checkpoint, PendingFloors},
            pending::ChainFloors,
        },
        types::{Body, Lqc, TipRecord},
    },
};
use commonware_codec::{Decode as _, Encode as _};
use commonware_cryptography::{Digest, Hasher, bls12381::primitives::variant::Variant};
use commonware_storage::{Context, translator::Translator};
use futures::future::try_join_all;
use std::{collections::BTreeSet, sync::Arc};

/// A verified state-sync floor to install.
pub(crate) struct InstallRequest<V: Variant, D: Digest> {
    /// Checkpoint the installation publishes.
    pub(crate) checkpoint: Checkpoint<D>,
    /// Pending-storage floors applied with the checkpoint.
    pub(crate) floors: PendingFloors,
    /// The floor L-QC.
    pub(crate) proof: Arc<Lqc<V, D>>,
    /// The history opening the floor L-QC's leader committed to.
    pub(crate) history: Arc<TipRecord<D>>,
}

/// The decoded artifacts that establish an installed checkpoint.
pub(super) struct InstallArtifacts<V: Variant, H: Hasher> {
    pub(super) proof: Arc<Lqc<V, H::Digest>>,
    pub(super) history: Arc<TipRecord<H::Digest>>,
}

impl<T, E, H, V, B> CatalogStore<T, E, H, V, B>
where
    T: Translator,
    E: Context,
    H: Hasher,
    V: Variant,
    B: Body<H>,
    B::Cfg: Clone,
{
    /// Installs a floor with its authenticated artifacts.
    ///
    /// The caller has verified that the request's L-QC and history establish its checkpoint.
    pub(crate) async fn install(
        &mut self,
        request: InstallRequest<V, H::Digest>,
    ) -> Result<(), Error> {
        let InstallRequest {
            checkpoint,
            floors,
            proof,
            history,
        } = request;
        self.begin_install(checkpoint.clone(), floors, &proof, &history)
            .await?;
        self.archive_install(&checkpoint, InstallArtifacts { proof, history })
            .await?;
        self.finish_install().await
    }

    /// Completes a durably begun installation before catalog reads become available.
    pub(crate) async fn recover_install(&mut self) -> Result<(), Error> {
        let Some(install) = self.state.install() else {
            return Ok(());
        };
        let checkpoint = install.checkpoint.clone();
        let artifacts = self.install_artifacts()?;
        self.archive_install(&checkpoint, artifacts).await?;
        self.finish_install().await
    }

    /// Durably records the installation intent while the current checkpoint stays visible.
    pub(super) async fn begin_install(
        &mut self,
        checkpoint: Checkpoint<H::Digest>,
        floors: PendingFloors,
        proof: &Lqc<V, H::Digest>,
        history: &TipRecord<H::Digest>,
    ) -> Result<(), Error> {
        let state = self
            .state
            .begin(
                checkpoint,
                proof.view(),
                self.allocated_lqc_index,
                floors,
                proof.encode(),
                history.encode(),
            )
            .map_err(|_| Error::Invalid("floor install intent is not canonical"))?;
        let lqc_index = state.lqc_index();
        self.sync_state(state).await?;
        self.allocated_lqc_index = lqc_index;
        Ok(())
    }

    /// Makes the floor L-QC and history opening durable in the finalized archives.
    pub(super) async fn archive_install(
        &mut self,
        checkpoint: &Checkpoint<H::Digest>,
        artifacts: InstallArtifacts<V, H>,
    ) -> Result<(), Error> {
        let lqc_index = self
            .state
            .lqc_index()
            .filter(|_| self.state.install().is_some())
            .ok_or(Error::Inconsistent("floor install L-QC index is missing"))?;
        let history_index = checkpoint
            .history_index()
            .ok_or(Error::Inconsistent("installed floor has no history index"))?;
        let InstallArtifacts { proof, history } = artifacts;
        let lqc = self.final_lqc.take()?;
        let histories = self.final_history.take()?;
        let (lqc, histories) = futures::try_join!(
            async move {
                lqc.put(lqc_index, proof.id::<H>().get(), proof)
                    .await?
                    .sync()
                    .await
            },
            async move {
                histories
                    .put(history_index, history.commitment::<H>(), history)
                    .await?
                    .sync()
                    .await
            },
        )?;
        self.final_lqc.restore(lqc);
        self.final_history.restore(histories);
        Ok(())
    }

    /// Applies the pending floors, then publishes the installed checkpoint.
    pub(super) async fn finish_install(&mut self) -> Result<(), Error> {
        let floors = self
            .state
            .install()
            .map(|install| install.floors.clone())
            .ok_or(Error::Inconsistent("floor install is not prepared"))?;
        let ready = self
            .state
            .finish()
            .ok_or(Error::Inconsistent("floor install is not prepared"))?;
        self.prune_install(floors).await?;
        let lqc_index = ready.lqc_index();
        self.sync_state(ready).await?;
        self.accepted_lqc_index = lqc_index;
        self.allocated_lqc_index = lqc_index;
        self.accepted_cleanup = Default::default();
        Ok(())
    }

    /// Decodes the artifacts recorded by the pending installation and checks that they establish
    /// its checkpoint.
    fn install_artifacts(&self) -> Result<InstallArtifacts<V, H>, Error> {
        let install = self
            .state
            .install()
            .ok_or(Error::Inconsistent("floor install intent is missing"))?;
        let proof = Lqc::<V, H::Digest>::decode_cfg(install.proof.clone(), &self.codec_config)?;
        let history =
            TipRecord::<H::Digest>::decode_cfg(install.history.clone(), &self.codec_config)?;
        let checkpoint = &install.checkpoint;
        if proof.id::<H>() != checkpoint.floor()
            || proof.epoch() != checkpoint.epoch()
            || proof.leader().history() != checkpoint.history()
            || history.commitment::<H>() != checkpoint.history()
        {
            return Err(Error::Inconsistent(
                "floor install artifacts do not establish checkpoint",
            ));
        }
        Ok(InstallArtifacts {
            proof: Arc::new(proof),
            history: Arc::new(history),
        })
    }

    /// Prunes pending archives to the installation's floors.
    ///
    /// A prunable namespace keeps a chain's pending blocks when the current emitted block is
    /// already a finalized row, because application pruning still owns those bodies. Immutable
    /// promotion may still be copying a pre-install output, so an immutable namespace keeps every
    /// chain; retaining custody is safe across every crash cut, and the durable promotion cursor
    /// reclaims it after restart.
    async fn prune_install(&mut self, floors: PendingFloors) -> Result<(), Error> {
        let retained = if self.prunable_blocks {
            let blocks = self.final_blocks.get()?;
            try_join_all(
                self.checkpoint()
                    .emitted()
                    .iter()
                    .map(|reference| async move {
                        Ok::<_, Error>(blocks.get_by_key(&reference.digest()).await?.is_some())
                    }),
            )
            .await?
        } else {
            vec![true; self.pending_blocks.chain_count()]
        };
        let block_floors = floors
            .blocks
            .into_iter()
            .zip(retained)
            .map(|(floor, retained)| (!retained).then_some(floor))
            .collect::<ChainFloors>();
        let unpinned = BTreeSet::new();
        let lqc = self.pending_lqc.take()?;
        let history = self.pending_history.take()?;
        let blocks = &mut self.pending_blocks;
        let (lqc, history, _) = futures::try_join!(
            async move { Ok::<_, Error>(lqc.prune(floors.lqc.get()).await?) },
            async move { Ok::<_, Error>(history.prune(floors.history.get()).await?) },
            blocks.prune(&block_floors, &unpinned),
        )?;
        self.pending_lqc.restore(lqc);
        self.pending_history.restore(history);
        Ok(())
    }
}
