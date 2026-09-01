//! Background promotion of finalized bodies into immutable storage.
//!
//! Publication never waits for this actor. A durable catalog checkpoint is the work queue, and
//! the promotion cursor advances only after the corresponding bodies are immutable. Temporary
//! custody is pruned only after that cursor is durable, so every crash cut is replayable.

use super::{
    catalog::{self, CatalogClient},
    metrics,
};
use crate::multimmit::{
    marshal::{
        storage::{
            promotion::{PromotedBody, Store},
            state::StoredRef,
        },
        types::OutputIndex,
    },
    types::{BlockRef, ChainId, TransactionBlock},
};
use commonware_actor::{
    Feedback,
    mailbox::{self, Policy},
};
use commonware_codec::{Codec, EncodeSize as _};
use commonware_cryptography::{Digestible, Hasher, bls12381::primitives::variant::Variant};
use commonware_runtime::{Handle, Metrics as RuntimeMetrics, Spawner};
use commonware_storage::{Context, translator::Translator};
use commonware_utils::channel::oneshot;
use futures::future::try_join_all;
use std::{
    collections::{HashMap, VecDeque},
    num::NonZeroUsize,
    sync::Arc,
};
use tracing::{Instrument as _, Span};

/// Immutable promotion or lookup failed.
#[derive(Clone, Debug, thiserror::Error)]
pub(in crate::multimmit::marshal) enum Error {
    #[error("promoter mailbox is closed")]
    Closed,
    #[error("catalog access failed: {0}")]
    Catalog(#[from] catalog::Error),
    #[error("immutable body storage failed: {0}")]
    Storage(Arc<str>),
    #[error("promoted output {0} is missing its body")]
    Missing(OutputIndex),
}

type Reply<T> = oneshot::Sender<Result<T, Error>>;
type BodyValues<H, B> = Vec<Option<Arc<TransactionBlock<H, B>>>>;

/// One in-memory body offered after checkpoint publication.
pub(in crate::multimmit::marshal) struct HotBody<H, B>
where
    H: Hasher,
    B: Codec + Digestible<Digest = H::Digest>,
{
    pub index: OutputIndex,
    pub block: Arc<TransactionBlock<H, B>>,
    pub encoded_len: u64,
}

pub(in crate::multimmit::marshal) enum Command<H, B>
where
    H: Hasher,
    B: Codec + Digestible<Digest = H::Digest>,
{
    Published {
        through: OutputIndex,
        hot: Vec<HotBody<H, B>>,
    },
    Installed {
        generation: u64,
        through: Option<OutputIndex>,
        frontiers: Vec<BlockRef<H::Digest>>,
    },
    Lookup(Span, Lookup<H, B>),
}

pub(in crate::multimmit::marshal) enum Lookup<H, B>
where
    H: Hasher,
    B: Codec + Digestible<Digest = H::Digest>,
{
    Block(
        BlockRef<H::Digest>,
        Reply<Option<Arc<TransactionBlock<H, B>>>>,
    ),
    Blocks(Vec<BlockRef<H::Digest>>, Reply<BodyValues<H, B>>),
    BlockByDigest(H::Digest, Reply<Option<Arc<TransactionBlock<H, B>>>>),
}

impl<H, B> Policy for Command<H, B>
where
    H: Hasher,
    B: Codec + Digestible<Digest = H::Digest>,
{
    type Overflow = VecDeque<Self>;

    fn handle(overflow: &mut Self::Overflow, command: Self) {
        match command {
            Self::Published { through, .. } => {
                // Only the ready slot may retain hot bodies. Overflow preserves the newest
                // durable target while keeping publication memory within one handoff batch.
                if let Some(Self::Published {
                    through: pending,
                    hot: pending_hot,
                }) = overflow.back_mut()
                {
                    if through > *pending {
                        *pending = through;
                        pending_hot.clear();
                    }
                } else {
                    overflow.push_back(Self::Published {
                        through,
                        hot: Vec::new(),
                    });
                }
            }
            Self::Installed {
                generation,
                through,
                frontiers,
            } => {
                overflow.push_back(Self::Installed {
                    generation,
                    through,
                    frontiers,
                });
            }
            command => overflow.push_back(command),
        }
    }
}

/// Cloneable immutable-body lookup and publication client.
pub(in crate::multimmit::marshal) struct Client<H, B>
where
    H: Hasher,
    B: Codec + Digestible<Digest = H::Digest>,
{
    commands: mailbox::Sender<Command<H, B>>,
}

impl<H, B> Clone for Client<H, B>
where
    H: Hasher,
    B: Codec + Digestible<Digest = H::Digest>,
{
    fn clone(&self) -> Self {
        Self {
            commands: self.commands.clone(),
        }
    }
}

impl<H, B> Client<H, B>
where
    H: Hasher,
    B: Codec + Digestible<Digest = H::Digest>,
{
    pub(in crate::multimmit::marshal) fn published(
        &self,
        through: OutputIndex,
        hot: Vec<HotBody<H, B>>,
    ) -> Feedback {
        self.commands.enqueue(Command::Published { through, hot })
    }

    pub(in crate::multimmit::marshal) fn installed(
        &self,
        generation: u64,
        through: Option<OutputIndex>,
        frontiers: Vec<BlockRef<H::Digest>>,
    ) -> Feedback {
        self.commands.enqueue(Command::Installed {
            generation,
            through,
            frontiers,
        })
    }

    async fn request<T>(&self, make: impl FnOnce(Reply<T>) -> Lookup<H, B>) -> Result<T, Error> {
        let (reply, receiver) = oneshot::channel();
        if self
            .commands
            .enqueue(Command::Lookup(Span::current(), make(reply)))
            == Feedback::Closed
        {
            return Err(Error::Closed);
        }
        receiver.await.unwrap_or(Err(Error::Closed))
    }

    pub(in crate::multimmit::marshal) async fn block(
        &self,
        reference: BlockRef<H::Digest>,
    ) -> Result<Option<Arc<TransactionBlock<H, B>>>, Error> {
        self.request(|reply| Lookup::Block(reference, reply)).await
    }

    pub(in crate::multimmit::marshal) async fn block_by_digest(
        &self,
        digest: H::Digest,
    ) -> Result<Option<Arc<TransactionBlock<H, B>>>, Error> {
        self.request(|reply| Lookup::BlockByDigest(digest, reply))
            .await
    }

    async fn blocks(
        &self,
        references: Vec<BlockRef<H::Digest>>,
    ) -> Result<BodyValues<H, B>, Error> {
        self.request(|reply| Lookup::Blocks(references, reply))
            .await
    }
}

/// Allocates the client before the catalog and promoter actors are spawned.
pub(in crate::multimmit::marshal) fn channel<H, B>(
    metrics: impl RuntimeMetrics,
    capacity: NonZeroUsize,
) -> (Client<H, B>, mailbox::Receiver<Command<H, B>>)
where
    H: Hasher,
    B: Codec + Digestible<Digest = H::Digest>,
{
    let (commands, receiver) = mailbox::new(metrics, capacity);
    (Client { commands }, receiver)
}

struct Promoter<T, E, H, V, B>
where
    T: Translator,
    E: Context,
    H: Hasher,
    V: Variant,
    B: Codec + Digestible<Digest = H::Digest>,
{
    catalog: CatalogClient<H, V, B>,
    store: Store<T, E, H, B>,
    commands: mailbox::Receiver<Command<H, B>>,
    target: Option<OutputIndex>,
    max_items: NonZeroUsize,
    max_bytes: NonZeroUsize,
    pending_floor: Option<(u64, Vec<BlockRef<H::Digest>>)>,
    metrics: metrics::Promoter,
}

impl<T, E, H, V, B> Promoter<T, E, H, V, B>
where
    T: Translator,
    E: Context,
    H: Hasher,
    V: Variant,
    B: Codec + Digestible<Digest = H::Digest>,
{
    #[tracing::instrument(
        name = "multimmit.marshal.promoter.promote",
        level = "info",
        skip_all,
        fields(target = target.get())
    )]
    async fn promote_one(
        &mut self,
        hot: &mut HashMap<OutputIndex, HotBody<H, B>>,
        target: OutputIndex,
    ) -> Result<(), Error> {
        let next = self
            .store
            .through()
            .map_or(Some(OutputIndex::ZERO), OutputIndex::next)
            .ok_or_else(|| Error::Storage(Arc::from("immutable output index exhausted")))?;
        let available = target
            .get()
            .checked_sub(next.get())
            .and_then(|distance| distance.checked_add(1))
            .and_then(|count| usize::try_from(count).ok())
            .unwrap_or(usize::MAX);
        let max_items = NonZeroUsize::new(self.max_items.get().min(available))
            .expect("promotion target includes the next output");
        let refs = self
            .catalog
            .output_refs(next, max_items, self.max_bytes)
            .await?;
        if refs.is_empty() {
            return Err(Error::Missing(next));
        }
        let mut resolved = Vec::with_capacity(refs.len());
        let mut missing = Vec::new();
        let mut hot_count = 0usize;
        let encoded_bytes = refs.iter().fold(0u64, |total, output| {
            total.saturating_add(output.encoded_len)
        });
        for output in &refs {
            if let Some(body) = hot.remove(&output.index)
                && body.block.reference() == output.reference
                && body.encoded_len == output.encoded_len
            {
                hot_count += 1;
                resolved.push(Some(body.block));
                continue;
            }
            missing.push(output.reference);
            resolved.push(None);
        }
        if !missing.is_empty() {
            let bodies = self.catalog.bodies(missing).await?;
            let mut bodies = bodies.into_iter();
            for body in &mut resolved {
                if body.is_none() {
                    *body = bodies.next().flatten();
                }
            }
        }
        let outputs = refs
            .into_iter()
            .zip(resolved)
            .map(|(output, block)| {
                let block = block.ok_or(Error::Missing(output.index))?;
                if block.reference() != output.reference {
                    return Err(Error::Storage(Arc::from(
                        "immutable promotion body has the wrong reference",
                    )));
                }
                if u64::try_from(block.encode_size()).ok() != Some(output.encoded_len) {
                    return Err(Error::Storage(Arc::from(
                        "immutable promotion body has the wrong encoded length",
                    )));
                }
                Ok(PromotedBody {
                    index: output.index,
                    reference: output.reference,
                    block,
                    generation: output.generation,
                })
            })
            .collect::<Result<Vec<_>, Error>>()?;
        let output_count = outputs.len();
        let frontiers = self
            .store
            .promote(outputs)
            .await
            .map_err(|error| Error::Storage(Arc::from(error)))?;
        self.metrics.batch(output_count, encoded_bytes, hot_count);
        self.metrics.progress(self.store.through());
        self.catalog.promoted(frontiers).await?;
        Ok(())
    }

    async fn handle(
        &mut self,
        command: Command<H, B>,
        hot: &mut HashMap<OutputIndex, HotBody<H, B>>,
    ) -> Result<(), Error> {
        match command {
            Command::Published {
                through,
                hot: offered,
            } => {
                self.target = self.target.max(Some(through));
                hot.clear();
                hot.extend(offered.into_iter().map(|body| (body.index, body)));
            }
            Command::Installed {
                generation,
                through,
                frontiers,
            } => {
                self.target = self.target.max(through);
                if self
                    .pending_floor
                    .as_ref()
                    .is_none_or(|(pending, _)| generation >= *pending)
                {
                    self.pending_floor = Some((generation, frontiers));
                }
                hot.clear();
            }
            Command::Lookup(span, lookup) => self.lookup(lookup).instrument(span).await,
        }
        Ok(())
    }

    #[tracing::instrument(
        name = "multimmit.marshal.promoter.lookup.process",
        level = "debug",
        skip_all
    )]
    async fn lookup(&self, lookup: Lookup<H, B>) {
        match lookup {
            Lookup::Block(reference, reply) => {
                let result = self
                    .store
                    .block(reference)
                    .await
                    .map_err(|error| Error::Storage(Arc::from(error)));
                drop(reply.send(result));
            }
            Lookup::Blocks(references, reply) => {
                let store = &self.store;
                let result = try_join_all(references.into_iter().map(|reference| async move {
                    store
                        .block(reference)
                        .await
                        .map_err(|error| Error::Storage(Arc::from(error)))
                }))
                .await;
                drop(reply.send(result));
            }
            Lookup::BlockByDigest(digest, reply) => {
                let result = self
                    .store
                    .block_by_digest(digest)
                    .await
                    .map_err(|error| Error::Storage(Arc::from(error)));
                drop(reply.send(result));
            }
        }
    }

    async fn run(mut self) -> Result<(), Error> {
        let mut hot = HashMap::new();
        self.metrics.progress(self.store.through());
        loop {
            if self.store.through() < self.target {
                self.promote_one(
                    &mut hot,
                    self.target
                        .expect("promotion target is ahead of its cursor"),
                )
                .await?;
                if let Ok(command) = self.commands.try_recv() {
                    self.handle(command, &mut hot).await?;
                }
                continue;
            }
            if let Some((generation, frontiers)) = self.pending_floor.take() {
                let frontiers = self
                    .store
                    .advance_frontiers(generation, frontiers)
                    .await
                    .map_err(|error| Error::Storage(Arc::from(error)))?;
                self.catalog.promoted(frontiers).await?;
                continue;
            }
            let Some(command) = self.commands.recv().await else {
                return Ok(());
            };
            self.handle(command, &mut hot).await?;
        }
    }
}

/// Starts immutable promotion from its durable cursor toward the catalog checkpoint.
#[allow(clippy::too_many_arguments)]
pub(in crate::multimmit::marshal) fn spawn<R, T, E, H, V, B>(
    context: R,
    catalog: CatalogClient<H, V, B>,
    store: Store<T, E, H, B>,
    commands: mailbox::Receiver<Command<H, B>>,
    committed: Option<OutputIndex>,
    generation: u64,
    frontiers: Vec<BlockRef<H::Digest>>,
    max_items: NonZeroUsize,
    max_bytes: NonZeroUsize,
) -> Handle<Result<(), Error>>
where
    R: Spawner + RuntimeMetrics,
    T: Translator,
    E: Context,
    H: Hasher,
    V: Variant,
    B: Codec + Digestible<Digest = H::Digest>,
{
    let metrics = metrics::Promoter::new(&context);
    context.shared(false).spawn(move |_| {
        Promoter {
            catalog,
            store,
            commands,
            target: committed,
            max_items,
            max_bytes,
            pending_floor: Some((generation, frontiers)),
            metrics,
        }
        .run()
    })
}

/// Body access that prefers live custody and falls back to immutable storage.
pub(in crate::multimmit::marshal) struct Bodies<H, V, B>
where
    H: Hasher,
    V: Variant,
    B: Codec + Digestible<Digest = H::Digest>,
{
    catalog: CatalogClient<H, V, B>,
    promoter: Option<Client<H, B>>,
}

impl<H, V, B> Clone for Bodies<H, V, B>
where
    H: Hasher,
    V: Variant,
    B: Codec + Digestible<Digest = H::Digest>,
{
    fn clone(&self) -> Self {
        Self {
            catalog: self.catalog.clone(),
            promoter: self.promoter.clone(),
        }
    }
}

impl<H, V, B> Bodies<H, V, B>
where
    H: Hasher,
    V: Variant,
    B: Codec + Digestible<Digest = H::Digest>,
{
    pub(in crate::multimmit::marshal) const fn new(
        catalog: CatalogClient<H, V, B>,
        promoter: Option<Client<H, B>>,
    ) -> Self {
        Self { catalog, promoter }
    }

    #[tracing::instrument(name = "multimmit.marshal.bodies.block", level = "debug", skip_all)]
    pub(in crate::multimmit::marshal) async fn block(
        &self,
        reference: BlockRef<H::Digest>,
    ) -> Result<Option<Arc<TransactionBlock<H, B>>>, Error> {
        if let Some(block) = self.catalog.block(reference).await? {
            return Ok(Some(block));
        }
        if let Some(promoter) = &self.promoter
            && let Some(block) = promoter.block(reference).await?
        {
            return Ok(Some(block));
        }
        Ok(None)
    }

    #[tracing::instrument(
        name = "multimmit.marshal.bodies.block_by_digest",
        level = "debug",
        skip_all
    )]
    pub(in crate::multimmit::marshal) async fn block_by_digest(
        &self,
        chain: ChainId,
        digest: H::Digest,
    ) -> Result<Option<Arc<TransactionBlock<H, B>>>, Error> {
        if let Some(block) = self.catalog.block_by_digest(chain, digest).await? {
            return Ok(Some(block));
        }
        if let Some(promoter) = &self.promoter
            && let Some(block) = promoter.block_by_digest(digest).await?
            && block.header().chain() == chain
        {
            return Ok(Some(block));
        }
        Ok(None)
    }

    /// Returns exact blocks in request order, preferring live custody over immutable storage.
    #[tracing::instrument(
        name = "multimmit.marshal.bodies.blocks",
        level = "debug",
        skip_all,
        fields(blocks = references.len())
    )]
    pub(in crate::multimmit::marshal) async fn blocks(
        &self,
        references: Vec<BlockRef<H::Digest>>,
    ) -> Result<BodyValues<H, B>, Error> {
        let bodies = self.catalog.bodies(references.clone()).await?;
        self.fill_immutable(&references, bodies).await
    }

    async fn fill_immutable(
        &self,
        references: &[BlockRef<H::Digest>],
        mut bodies: BodyValues<H, B>,
    ) -> Result<BodyValues<H, B>, Error> {
        if let Some(promoter) = &self.promoter {
            let missing = references
                .iter()
                .zip(&bodies)
                .filter_map(|(reference, body)| body.is_none().then_some(*reference))
                .collect::<Vec<_>>();
            if !missing.is_empty() {
                let mut stored = promoter.blocks(missing).await?.into_iter();
                for body in &mut bodies {
                    if body.is_none() {
                        *body = stored.next().flatten();
                    }
                }
            }
        }
        Ok(bodies)
    }

    /// Materializes references obtained from a published catalog checkpoint.
    #[tracing::instrument(
        name = "multimmit.marshal.bodies.materialize",
        level = "info",
        skip_all,
        fields(outputs = refs.len())
    )]
    pub(in crate::multimmit::marshal) async fn materialize(
        &self,
        refs: &[StoredRef<H::Digest>],
    ) -> Result<Vec<Arc<TransactionBlock<H, B>>>, Error> {
        let references = refs
            .iter()
            .map(|output| output.reference)
            .collect::<Vec<_>>();
        let bodies = self.catalog.committed_bodies(references.clone()).await?;
        let bodies = self.fill_immutable(&references, bodies).await?;
        let mut bodies = bodies.into_iter();
        refs.iter()
            .map(|output| {
                bodies
                    .next()
                    .flatten()
                    .filter(|block| {
                        block.reference() == output.reference
                            && u64::try_from(block.encode_size()).ok() == Some(output.encoded_len)
                    })
                    .ok_or(Error::Missing(output.index))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        marshal::mocks::block::EmptyBlock,
        multimmit::{
            config::Limits,
            marshal::{
                actors::delivery,
                config::{ArchiveConfig, Config, Start},
            },
            mocks::Committee,
            types::TransactionBlockHeader,
        },
        types::{Epoch, Height},
    };
    use commonware_cryptography::{Sha256, bls12381::primitives::variant::MinPk};
    use commonware_runtime::{
        Runner as _, Supervisor as _, buffer::paged::CacheRef, deterministic,
    };
    use commonware_storage::translator::TwoCap;
    use commonware_utils::{NZU16, NZUsize, sync::Mutex};
    use futures::poll;
    use std::num::NonZeroU32;
    use tracing::{Subscriber, span};
    use tracing_subscriber::{
        Layer, layer::Context as LayerContext, prelude::*, registry::LookupSpan,
    };

    struct RecordedSpan {
        id: u64,
        name: &'static str,
        parent: Option<u64>,
    }

    #[derive(Clone, Default)]
    struct Spans(Arc<Mutex<Vec<RecordedSpan>>>);

    impl<S: Subscriber + for<'a> LookupSpan<'a>> Layer<S> for Spans {
        fn on_new_span(
            &self,
            attrs: &span::Attributes<'_>,
            id: &span::Id,
            ctx: LayerContext<'_, S>,
        ) {
            let parent = ctx
                .span(id)
                .unwrap()
                .parent()
                .map(|parent| parent.id().into_u64());
            self.0.lock().push(RecordedSpan {
                id: id.into_u64(),
                name: attrs.metadata().name(),
                parent,
            });
        }
    }

    #[test]
    fn lookup_dequeue_preserves_each_caller() {
        let spans = Spans::default();
        tracing::subscriber::with_default(
            tracing_subscriber::registry().with(spans.clone()),
            || {
                deterministic::Runner::default().start(|context| async move {
                    let committee = Committee::<MinPk>::new(41, 6, Limits::new(1, 0).unwrap());
                    let config = Config::<_, MinPk, EmptyBlock<Sha256>>::new(
                        committee.config.epoch(),
                        NonZeroU32::new(committee.codec().chains() as u32).unwrap(),
                        Start::Genesis(committee.config.genesis().clone()),
                        "promoter_tracing".into(),
                        committee.codec(),
                        (),
                        ArchiveConfig::new(
                            TwoCap,
                            CacheRef::from_pooler(&context, NZU16!(1024), NZUsize!(8)),
                        ),
                    )
                    .unwrap();
                    let (delivery, _receiver) = delivery::channel(context.child("delivery"));
                    let (catalog, catalog_handle, client, promoter_handle, _) = config
                        .spawn::<_, Sha256>(context.child("catalog"), delivery)
                        .await
                        .unwrap();
                    let client = client.unwrap();
                    let reference = committee.config.genesis().tips()[0];
                    let callers = [
                        tracing::info_span!("first_lookup"),
                        tracing::info_span!("second_lookup"),
                    ];
                    let first = client.block(reference).instrument(callers[0].clone());
                    let second = client
                        .blocks(vec![reference])
                        .instrument(callers[1].clone());
                    futures::pin_mut!(first, second);
                    assert!(poll!(&mut first).is_pending());
                    assert!(poll!(&mut second).is_pending());
                    assert!(
                        !spans
                            .0
                            .lock()
                            .iter()
                            .any(|span| span.name.ends_with("lookup.process"))
                    );
                    assert!(first.await.unwrap().is_none());
                    assert_eq!(second.await.unwrap().len(), 1);
                    for caller in &callers {
                        assert!(
                            spans.0.lock().iter().any(|span| span.name
                                == "multimmit.marshal.promoter.lookup.process"
                                && span.parent == caller.id().map(|id| id.into_u64())),
                            "each dequeued lookup needs its own processing child"
                        );
                    }
                    let bodies = Bodies::new(catalog, Some(client.clone()));
                    assert!(
                        bodies
                            .block_by_digest(reference.chain(), reference.digest())
                            .await
                            .unwrap()
                            .is_none()
                    );
                    let recorded = spans.0.lock();
                    let rpc = recorded
                        .iter()
                        .find(|span| span.name == "multimmit.marshal.bodies.block_by_digest")
                        .unwrap()
                        .id;
                    assert!(recorded.iter().any(|span| span.name
                        == "multimmit.marshal.promoter.lookup.process"
                        && span.parent == Some(rpc)));
                    drop(recorded);
                    catalog_handle.abort();
                    promoter_handle.unwrap().abort();
                });
            },
        );
    }

    #[test]
    fn publication_overflow_drops_bodies_and_preserves_install_order() {
        let body = EmptyBlock::<Sha256>::new(Sha256::hash(&[b"body parent"]), Height::new(1), 0);
        let header = TransactionBlockHeader::new(
            Epoch::new(1),
            ChainId::new(0),
            Height::new(1),
            Sha256::hash(&[b"producer parent"]),
            body.digest(),
        )
        .unwrap();
        let block = Arc::new(TransactionBlock::<Sha256, _>::new(header, body).unwrap());
        let mut overflow = VecDeque::new();
        Command::handle(
            &mut overflow,
            Command::Published {
                through: OutputIndex::ZERO,
                hot: vec![HotBody {
                    index: OutputIndex::ZERO,
                    encoded_len: u64::try_from(block.encode_size()).unwrap(),
                    block,
                }],
            },
        );
        Command::handle(
            &mut overflow,
            Command::Installed {
                generation: 1,
                through: Some(OutputIndex::ZERO),
                frontiers: Vec::new(),
            },
        );
        Command::handle(
            &mut overflow,
            Command::Published {
                through: OutputIndex::new(1),
                hot: Vec::new(),
            },
        );

        assert_eq!(overflow.len(), 3);
        assert!(matches!(
            &overflow[0],
            Command::Published { through, hot }
                if *through == OutputIndex::ZERO && hot.is_empty()
        ));
        assert!(matches!(
            &overflow[1],
            Command::Installed { generation: 1, .. }
        ));
        assert!(matches!(
            &overflow[2],
            Command::Published { through, hot }
                if *through == OutputIndex::new(1) && hot.is_empty()
        ));
    }
}
