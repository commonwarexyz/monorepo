//! What the synchronizer needs from the catalog and from backfill, and their production handles.

use crate::{
    multimmit::{
        actors::util::Completion,
        marshal::{
            actors::{
                backfill::{self, CustodiedBlock, SharedHeaders, SharedHistory},
                catalog, delivery,
                metrics::FetchReason,
            },
            storage::{
                catalog::InstallRequest,
                catalog_state::{Checkpoint, PendingFloors},
                commit::{Commit, CustodyRef},
            },
            types::{CustodyValues, MaybeLqc},
        },
        types::{BlockRef, Body, CertificateId, Lqc, TipRecord, TransactionBlockHeader},
    },
    types::View,
};
use commonware_cryptography::{Hasher, bls12381::primitives::variant::Variant};
use std::{future::Future, sync::Arc};

/// Producer-header segments, one per request.
pub(super) type HeaderSegments<D> = Vec<Vec<TransactionBlockHeader<D>>>;

/// Fetches used by synchronization.
///
/// Every method resolves the requested identity: the returned value is a linked segment
/// beginning at the requested commitment or reference, or the requested blocks with
/// catalog-proven custody. An error means the value could not be resolved, which the synchronizer
/// treats as fatal.
pub(crate) trait Fetcher<H, V, B>: Clone + Send + 'static
where
    H: Hasher,
    V: Variant,
    B: Body<H>,
{
    /// Fetch failure.
    type Error: Send + 'static;

    /// Returns a linked tip-history segment, newest first, that starts at `commitment`.
    ///
    /// `view` is recorded for tracing only.
    fn history(
        &mut self,
        reason: FetchReason,
        view: View,
        commitment: H::Digest,
    ) -> impl Future<Output = Result<SharedHistory<H::Digest>, Self::Error>> + Send;

    /// Returns a linked producer-header segment, newest first, that starts at `reference`.
    fn headers(
        &mut self,
        reason: FetchReason,
        reference: BlockRef<H::Digest>,
    ) -> impl Future<Output = Result<SharedHeaders<H::Digest>, Self::Error>> + Send;

    /// Returns a non-empty prefix of the consecutive producer blocks `references`, newest first,
    /// each with its durable catalog custody.
    fn blocks(
        &mut self,
        reason: FetchReason,
        references: Vec<BlockRef<H::Digest>>,
    ) -> impl Future<Output = Result<Vec<CustodiedBlock<H, B>>, Self::Error>> + Send;
}

/// The catalog requests synchronization issues.
///
/// Lookups that run concurrently with a pass take `&self` and return detached futures.
pub(crate) trait CatalogPort<H, V, B>: Send + 'static
where
    H: Hasher,
    V: Variant,
    B: Body<H>,
{
    /// Catalog failure.
    type Error: Send + 'static;
    /// Completion of a started commit.
    type CommitToken: Send + 'static;

    /// Returns the durable checkpoint.
    fn checkpoint(
        &mut self,
    ) -> impl Future<Output = Result<Checkpoint<H::Digest>, Self::Error>> + Send;

    /// Returns the highest retained L-QC, if any.
    fn latest_lqc(
        &mut self,
    ) -> impl Future<Output = Result<MaybeLqc<V, H::Digest>, Self::Error>> + Send;

    /// Returns the retained L-QC `id`, if any.
    fn lqc(
        &mut self,
        id: CertificateId<H::Digest>,
    ) -> impl Future<Output = Result<MaybeLqc<V, H::Digest>, Self::Error>> + Send;

    /// Returns whether `id` is already a selected finality proof.
    fn final_lqc(
        &mut self,
        id: CertificateId<H::Digest>,
    ) -> impl Future<Output = Result<bool, Self::Error>> + Send;

    /// Returns, for each `(head, max_items)` request, the locally held header segment starting
    /// at `head`, bounded by `max_items` headers and `max_bytes` encoded bytes.
    fn header_segments(
        &self,
        requests: Vec<(BlockRef<H::Digest>, usize)>,
        max_bytes: usize,
    ) -> impl Future<Output = Result<HeaderSegments<H::Digest>, Self::Error>> + Send + 'static;

    /// Waits until each of `references` has durable custody or is known to be missing.
    fn wait_for_custody(
        &self,
        references: Vec<BlockRef<H::Digest>>,
    ) -> impl Future<Output = Result<CustodyValues<H::Digest>, Self::Error>> + Send + 'static;

    /// Starts a checkpoint-last commit of `batch` and hands the bodies in `handoff` to delivery
    /// once its checkpoint is durable.
    ///
    /// Returns once the catalog accepted the commit; [`Self::wait_commit`] resolves when it is
    /// durable. Commits become durable in the order they were started.
    fn start_commit(
        &mut self,
        batch: Commit<H, V>,
        handoff: Vec<delivery::HotOutput<H, B>>,
    ) -> impl Future<Output = Result<Self::CommitToken, Self::Error>> + Send;

    /// Waits until the commit behind `token` is durable.
    fn wait_commit(
        token: Self::CommitToken,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Installs a verified floor: replaces the durable checkpoint, prunes below it, and retains
    /// the anchor `proof` and its tip-history `history`.
    fn install(
        &mut self,
        checkpoint: Checkpoint<H::Digest>,
        prune: PendingFloors,
        proof: Arc<Lqc<V, H::Digest>>,
        history: Arc<TipRecord<H::Digest>>,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;
}

impl<H, V, B> CatalogPort<H, V, B> for catalog::Mailbox<H, V, B>
where
    H: Hasher,
    V: Variant,
    B: Body<H>,
{
    type Error = catalog::Error;
    type CommitToken = Completion<catalog::Error>;

    async fn checkpoint(&mut self) -> Result<Checkpoint<H::Digest>, Self::Error> {
        Self::checkpoint(self).await
    }

    async fn latest_lqc(&mut self) -> Result<MaybeLqc<V, H::Digest>, Self::Error> {
        Self::latest_lqc(self).await
    }

    async fn lqc(
        &mut self,
        id: CertificateId<H::Digest>,
    ) -> Result<MaybeLqc<V, H::Digest>, Self::Error> {
        Self::lqc(self, id).await
    }

    async fn final_lqc(&mut self, id: CertificateId<H::Digest>) -> Result<bool, Self::Error> {
        Self::final_lqc(self, id).await
    }

    fn header_segments(
        &self,
        requests: Vec<(BlockRef<H::Digest>, usize)>,
        max_bytes: usize,
    ) -> impl Future<Output = Result<HeaderSegments<H::Digest>, Self::Error>> + Send + 'static {
        let catalog = self.clone();
        async move { Self::header_segments(&catalog, requests, max_bytes).await }
    }

    fn wait_for_custody(
        &self,
        references: Vec<BlockRef<H::Digest>>,
    ) -> impl Future<Output = Result<CustodyValues<H::Digest>, Self::Error>> + Send + 'static {
        let catalog = self.clone();
        async move { Self::wait_for_custody(&catalog, references).await }
    }

    async fn start_commit(
        &mut self,
        batch: Commit<H, V>,
        handoff: Vec<delivery::HotOutput<H, B>>,
    ) -> Result<Self::CommitToken, Self::Error> {
        Self::start_commit(self, batch, handoff).await
    }

    async fn wait_commit(token: Self::CommitToken) -> Result<(), Self::Error> {
        token.wait().await
    }

    async fn install(
        &mut self,
        checkpoint: Checkpoint<H::Digest>,
        prune: PendingFloors,
        proof: Arc<Lqc<V, H::Digest>>,
        history: Arc<TipRecord<H::Digest>>,
    ) -> Result<(), Self::Error> {
        Self::install(
            self,
            InstallRequest {
                checkpoint,
                floors: prune,
                proof,
                history,
            },
        )
        .await
    }
}

/// Backfill client that returns blocks only with their catalog-proven custody.
pub(crate) struct CustodyFetcher<H, V, B>
where
    H: Hasher,
    V: Variant,
    B: Body<H>,
{
    backfill: backfill::Mailbox<H, V, B>,
    catalog: catalog::Mailbox<H, V, B>,
}

impl<H, V, B> CustodyFetcher<H, V, B>
where
    H: Hasher,
    V: Variant,
    B: Body<H>,
{
    pub(crate) const fn new(
        backfill: backfill::Mailbox<H, V, B>,
        catalog: catalog::Mailbox<H, V, B>,
    ) -> Self {
        Self { backfill, catalog }
    }

    /// Waits for the durable custody of each of `references`.
    async fn confirm_custody(
        &self,
        references: &[BlockRef<H::Digest>],
    ) -> Result<Vec<CustodyRef<H::Digest>>, backfill::Error> {
        let values = self.catalog.wait_for_custody(references.to_vec()).await?;
        if values.len() != references.len() {
            return Err(backfill::Error::Invalid(
                "catalog custody response has invalid cardinality",
            ));
        }
        references
            .iter()
            .zip(values)
            .map(|(reference, custody)| {
                custody
                    .filter(|custody| custody.reference() == *reference)
                    .ok_or(backfill::Error::Invalid(
                        "resolved producer block lacks exact custody",
                    ))
            })
            .collect()
    }
}

impl<H, V, B> Clone for CustodyFetcher<H, V, B>
where
    H: Hasher,
    V: Variant,
    B: Body<H>,
{
    fn clone(&self) -> Self {
        Self::new(self.backfill.clone(), self.catalog.clone())
    }
}

impl<H: Hasher, V: Variant, B: Body<H>> Fetcher<H, V, B> for CustodyFetcher<H, V, B> {
    type Error = backfill::Error;

    async fn history(
        &mut self,
        reason: FetchReason,
        view: View,
        commitment: H::Digest,
    ) -> Result<SharedHistory<H::Digest>, Self::Error> {
        self.backfill.history(reason, view, commitment).await
    }

    async fn headers(
        &mut self,
        reason: FetchReason,
        reference: BlockRef<H::Digest>,
    ) -> Result<SharedHeaders<H::Digest>, Self::Error> {
        self.backfill.headers(reason, reference).await
    }

    async fn blocks(
        &mut self,
        reason: FetchReason,
        references: Vec<BlockRef<H::Digest>>,
    ) -> Result<Vec<CustodiedBlock<H, B>>, Self::Error> {
        let prefix = self.backfill.blocks(reason, references.clone()).await?;
        let blocks = prefix.blocks();
        let custody = self.confirm_custody(&references[..blocks.len()]).await?;
        custody
            .into_iter()
            .zip(blocks)
            .map(|(custody, block)| {
                CustodiedBlock::new(custody, block.clone()).ok_or(backfill::Error::Invalid(
                    "durable custody describes another block",
                ))
            })
            .collect()
    }
}
