//! Buffering pending admissions and starting their durability cuts.

use super::{Admission, CatalogStore, Footprint, StagedAdmission, start_sync_if};
use crate::multimmit::{
    marshal::storage::{
        Error,
        archive::{PendingHistory, PendingLqc, put_once},
        pending::Append,
    },
    scheme::Scheme,
    types::{BlockRef, Body, TransactionBlock},
};
use commonware_cryptography::Hasher;
use commonware_runtime::Handle;
use commonware_storage::{Context, translator::Translator};
use futures::{FutureExt as _, future::BoxFuture};
use std::{
    iter::{Peekable, from_fn, once},
    sync::Arc,
};

/// The journal an admission holds until [`CatalogStore::finish_admission`] returns it.
pub(crate) enum AdmissionWrite<T, E, H, S, B>
where
    T: Translator,
    E: Context,
    H: Hasher,
    S: Scheme,
    B: Body<H>,
{
    /// The pending L-QC archive.
    Lqc(PendingLqc<T, E, H, S>),
    /// The pending history archive.
    History(PendingHistory<T, E, H>),
    /// The pending block segment writer and the rows it appended.
    Block(Append<E, H, B>),
}

/// A started admission write.
pub(crate) type AdmissionFuture<T, E, H, S, B> =
    BoxFuture<'static, Result<AdmissionWrite<T, E, H, S, B>, Error>>;

/// A started admission write, or `None` when the admission writes nothing.
pub(crate) type StartedAdmission<T, E, H, S, B> = Option<AdmissionFuture<T, E, H, S, B>>;

/// A producer block and its reference.
type BlockAdmission<H, B> = (BlockRef<<H as Hasher>::Digest>, Arc<TransactionBlock<H, B>>);

impl<H, S, B> Admission<H, S, B>
where
    H: Hasher,
    S: Scheme,
    B: Body<H>,
{
    /// Returns the block of a block admission, or the admission itself otherwise.
    pub(crate) fn into_block(self) -> Result<BlockAdmission<H, B>, Self> {
        match self {
            Self::Block(reference, block) => Ok((reference, block)),
            other => Err(other),
        }
    }
}

/// Takes the next admission from `writes` if it is a block.
fn next_block<H, S, B>(
    writes: &mut Peekable<impl Iterator<Item = Admission<H, S, B>>>,
) -> Option<BlockAdmission<H, B>>
where
    H: Hasher,
    S: Scheme,
    B: Body<H>,
{
    writes
        .next_if(|write| matches!(write, Admission::Block(..)))
        .and_then(|write| write.into_block().ok())
}

impl<T, E, H, S, B> CatalogStore<T, E, H, S, B>
where
    T: Translator,
    E: Context,
    H: Hasher,
    S: Scheme,
    B: Body<H>,
{
    /// Returns the pending families a batch must make durable, or `None` when it needs no cut.
    ///
    /// Rejects the batch before any write if a block is below its chain's custody floor.
    pub(crate) fn admission_footprint(
        &self,
        writes: &[StagedAdmission<H, S, B>],
    ) -> Result<Option<Footprint>, Error> {
        let mut footprint = Footprint::default();
        for write in writes {
            match &write.admission {
                Admission::Lqc(..) => footprint.lqc |= write.durable,
                Admission::History(..) => footprint.history |= write.durable,
                Admission::Block(reference, _) => {
                    if !self.pending_blocks.admits(*reference) {
                        return Err(Error::Invalid("producer block is below the custody floor"));
                    }
                    footprint.blocks = true;
                }
            }
        }
        Ok(footprint.any(|touched| *touched).then_some(footprint))
    }

    /// Starts writing the next admission, or a run of consecutive block admissions up to the
    /// end of the current pending segment.
    ///
    /// Until [`Self::finish_admission`] returns the journal, the catalog may read retained
    /// indexes and finalized block metadata or plan immutable body reads, but must not perform
    /// another storage mutation. Returns `None` when every block in the run is already stored,
    /// in which case no journal is lent. Dropping or failing the write makes this store unusable.
    pub(crate) fn start_admission(
        &mut self,
        writes: &mut Peekable<impl Iterator<Item = Admission<H, S, B>>>,
    ) -> Result<StartedAdmission<T, E, H, S, B>, Error> {
        // Boxed to keep the admission future small.
        Ok(Some(match writes.next().expect("admission is available") {
            Admission::Lqc(view, id, proof) => {
                let lqc = self.pending_lqc.take()?;
                async move {
                    let lqc = put_once(lqc, view.get(), id.get(), proof).await?;
                    Ok(AdmissionWrite::Lqc(lqc))
                }
                .boxed()
            }
            Admission::History(view, commitment, record) => {
                let history = self.pending_history.take()?;
                async move {
                    let history = put_once(history, view.get(), commitment, record).await?;
                    Ok(AdmissionWrite::History(history))
                }
                .boxed()
            }
            Admission::Block(reference, block) => {
                let run = once((reference, block)).chain(from_fn(|| next_block(writes)));
                let Some(append) = self.pending_blocks.start_put(run)? else {
                    return Ok(None);
                };
                async move { Ok(AdmissionWrite::Block(append.run().await?)) }.boxed()
            }
        }))
    }

    /// Returns journal ownership and publishes any appended block metadata into custody indexes.
    pub(crate) fn finish_admission(
        &mut self,
        write: AdmissionWrite<T, E, H, S, B>,
    ) -> Result<(), Error> {
        match write {
            AdmissionWrite::Lqc(lqc) => self.pending_lqc.restore(lqc),
            AdmissionWrite::History(history) => self.pending_history.restore(history),
            AdmissionWrite::Block(append) => self.pending_blocks.finish_put(append)?,
        }
        Ok(())
    }

    /// Starts the pending-archive durability cut accumulated by the catalog.
    pub(crate) async fn start_admission_sync(
        &mut self,
        footprint: Footprint,
    ) -> Result<Vec<Handle<()>>, Error> {
        let lqc = self.pending_lqc.take()?;
        let history = self.pending_history.take()?;
        let blocks = &mut self.pending_blocks;
        let ((lqc, lqc_sync), (history, history_sync), block_syncs) = futures::try_join!(
            start_sync_if(lqc, footprint.lqc),
            start_sync_if(history, footprint.history),
            async move {
                if footprint.blocks {
                    blocks.start_sync().await
                } else {
                    Ok(Vec::new())
                }
            },
        )?;
        self.pending_lqc.restore(lqc);
        self.pending_history.restore(history);
        Ok(lqc_sync
            .into_iter()
            .chain(history_sync)
            .chain(block_syncs)
            .collect())
    }
}
