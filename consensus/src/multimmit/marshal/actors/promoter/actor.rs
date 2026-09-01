//! The promoter task.

use super::{
    mailbox::{Lookup, Message, Receiver},
    metrics::Metrics,
    store::{PromotedBody, PromotionStore},
};
use crate::multimmit::{
    actors::util::gated,
    marshal::{
        actors::{catalog, delivery::HotOutput},
        storage::Error as StorageError,
        types::OutputIndex,
    },
    types::{BlockRef, Body},
};
use commonware_cryptography::{Digest, Hasher, bls12381::primitives::variant::Variant};
use commonware_macros::select_loop;
use commonware_runtime::{ContextCell, Handle, Metrics as RuntimeMetrics, Spawner, spawn_cell};
use commonware_storage::{Context, translator::Translator};
use commonware_utils::channel::fallible::OneshotExt as _;
use futures::future::{ready, try_join_all};
use std::{collections::HashMap, num::NonZeroUsize, sync::Arc};
use tracing::Instrument as _;

/// Most messages the promoter handles between two promotion steps while promotion is due.
///
/// Lookups run ahead of promotion, but a steady stream of them cannot stop it: the catalog
/// reclaims pending custody only behind the promoted frontier.
pub(super) const MESSAGES_PER_STEP: usize = 8;

/// Immutable promotion or lookup failed.
#[derive(Clone, Debug, thiserror::Error)]
pub(crate) enum Error {
    /// The promoter stopped before answering.
    #[error("promoter mailbox is closed")]
    Closed,
    /// Catalog access failed.
    #[error("catalog access failed: {0}")]
    Catalog(#[from] catalog::Error),
    /// Immutable storage failed.
    #[error("immutable body storage failed: {0}")]
    Storage(Arc<StorageError>),
    /// A committed output's body is not in custody.
    #[error("promoted output {0} is missing its body")]
    Missing(OutputIndex),
    /// Promotion and the catalog disagree.
    #[error("promotion invariant violated: {0}")]
    Invariant(&'static str),
}

impl From<StorageError> for Error {
    fn from(error: StorageError) -> Self {
        Self::Storage(Arc::new(error))
    }
}

/// Resource bounds of the promoter.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Bounds {
    /// Most outputs one promotion batch copies.
    pub(crate) max_items: NonZeroUsize,
    /// Target encoded bytes of one promotion batch (one larger body is copied alone).
    pub(crate) max_bytes: NonZeroUsize,
}

/// A floor installation the promoter has not yet applied.
pub(crate) struct PendingFloor<D: Digest> {
    /// Floor generation of the installation.
    pub(crate) generation: u64,
    /// Installed frontier, one reference per chain in chain order.
    pub(crate) frontiers: Vec<BlockRef<D>>,
}

/// Promoter configuration.
pub(crate) struct Config<R, T, E, H, V, B>
where
    T: Translator,
    E: Context,
    H: Hasher,
    V: Variant,
    B: Body<H>,
{
    /// Runtime context of the promoter task.
    pub(crate) context: R,
    pub(crate) catalog: catalog::Mailbox<H, V, B>,
    /// The immutable archive and its durable promotion cursor.
    pub(crate) store: PromotionStore<T, E, H, B>,
    /// The receiving half of [`super::channel`].
    pub(crate) mailbox: Receiver<H, B>,
    /// Committed output of the recovered catalog checkpoint.
    pub(crate) committed: Option<OutputIndex>,
    /// Floor of the recovered catalog checkpoint, applied once promotion catches up.
    pub(crate) floor: PendingFloor<H::Digest>,
    pub(crate) bounds: Bounds,
}

/// Copies committed bodies into the immutable archive behind the catalog checkpoint.
pub(crate) struct Actor<R, T, E, H, V, B>
where
    R: Spawner + RuntimeMetrics,
    T: Translator,
    E: Context,
    H: Hasher,
    V: Variant,
    B: Body<H>,
{
    context: ContextCell<R>,
    catalog: catalog::Mailbox<H, V, B>,
    store: PromotionStore<T, E, H, B>,
    mailbox: Receiver<H, B>,
    /// Newest committed output to promote through.
    target: Option<OutputIndex>,
    /// Bodies of the newest publication, by output.
    hot: HashMap<OutputIndex, HotOutput<H, B>>,
    /// The newest floor installation not yet applied.
    pending_floor: Option<PendingFloor<H::Digest>>,
    bounds: Bounds,
    metrics: Metrics,
}

impl<R, T, E, H, V, B> Actor<R, T, E, H, V, B>
where
    R: Spawner + RuntimeMetrics,
    T: Translator,
    E: Context,
    H: Hasher,
    V: Variant,
    B: Body<H>,
{
    pub(crate) fn new(config: Config<R, T, E, H, V, B>) -> Self {
        let Config {
            context,
            catalog,
            store,
            mailbox,
            committed,
            floor,
            bounds,
        } = config;
        Self {
            metrics: Metrics::new(&context),
            context: ContextCell::new(context),
            catalog,
            store,
            mailbox,
            target: committed,
            hot: HashMap::new(),
            pending_floor: Some(floor),
            bounds,
        }
    }

    /// Starts the promoter task.
    pub(crate) fn start(mut self) -> Handle<Result<(), Error>> {
        spawn_cell!(self.context, self.run())
    }

    /// Promotes toward the newest target until the mailbox closes and no work remains.
    ///
    /// Queued messages, lookups among them, run before each promotion step, but at most
    /// [`MESSAGES_PER_STEP`] between two steps while promotion is due. A step promotes one batch
    /// while the cursor trails the target, and otherwise applies the pending floor.
    async fn run(mut self) -> Result<(), Error> {
        self.metrics.progress(self.store.through());
        let mut open = true;
        let mut handled = 0usize;
        select_loop! {
            self.context,
            on_start => {
                let working = self.store.through() < self.target || self.pending_floor.is_some();
                if !open && !working {
                    break;
                }
                let receive = open && (!working || handled < MESSAGES_PER_STEP);
            },
            on_stopped => {},
            message = gated(receive, self.mailbox.recv()) => match message {
                Some(message) => {
                    handled = handled.saturating_add(1);
                    self.handle(message).await?;
                }
                None => open = false,
            },
            () = gated(working, ready(())) => {
                handled = 0;
                self.step().await?;
            },
        }
        Ok(())
    }

    async fn step(&mut self) -> Result<(), Error> {
        if let Some(target) = self
            .target
            .filter(|target| self.store.through() < Some(*target))
        {
            return self.promote(target).await;
        }
        if let Some(PendingFloor {
            generation,
            frontiers,
        }) = self.pending_floor.take()
        {
            let frontiers = self.store.advance_frontiers(generation, frontiers).await?;
            self.catalog.promoted(frontiers).await?;
        }
        Ok(())
    }

    /// Promotes the next batch after the cursor, through at most `target`.
    #[tracing::instrument(
        name = "multimmit.marshal.promoter.promote",
        level = "info",
        skip_all,
        fields(target = target.get())
    )]
    async fn promote(&mut self, target: OutputIndex) -> Result<(), Error> {
        let next = OutputIndex::after(self.store.through())
            .ok_or(Error::Invariant("immutable output index exhausted"))?;
        let available = target
            .get()
            .checked_sub(next.get())
            .and_then(|distance| distance.checked_add(1))
            .and_then(|count| usize::try_from(count).ok())
            .unwrap_or(usize::MAX);
        let max_items = NonZeroUsize::new(self.bounds.max_items.get().min(available))
            .expect("promotion target includes the next output");
        let refs = self
            .catalog
            .output_refs(next, max_items, self.bounds.max_bytes)
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
            // The catalog matched each hot body to its row before handing it off.
            if let Some(hot) = self.hot.remove(&output.index)
                && hot.stored == *output
            {
                hot_count += 1;
                resolved.push(Some(hot.block));
                continue;
            }
            missing.push(output.reference);
            resolved.push(None);
        }
        if !missing.is_empty() {
            let mut read = self.catalog.bodies(missing).await?.into_iter();
            for (slot, output) in resolved
                .iter_mut()
                .zip(&refs)
                .filter(|(slot, _)| slot.is_none())
            {
                let Some(block) = read.next().flatten() else {
                    continue;
                };
                if !output.matches(&block) {
                    return Err(Error::Invariant(
                        "immutable promotion body does not match its output row",
                    ));
                }
                *slot = Some(block);
            }
        }
        let outputs = refs
            .into_iter()
            .zip(resolved)
            .map(|(output, block)| {
                let block = block.ok_or(Error::Missing(output.index))?;
                Ok(PromotedBody {
                    index: output.index,
                    reference: output.reference,
                    block,
                    floor_generation: output.floor_generation,
                })
            })
            .collect::<Result<Vec<_>, Error>>()?;
        let output_count = outputs.len();
        let frontiers = self.store.promote(outputs).await?;
        self.metrics.batch(output_count, encoded_bytes, hot_count);
        self.metrics.progress(self.store.through());
        self.catalog.promoted(frontiers).await?;
        Ok(())
    }

    async fn handle(&mut self, message: Message<H, B>) -> Result<(), Error> {
        match message {
            Message::Published { through, hot } => {
                self.target = self.target.max(Some(through));
                // A publication coalesced under pressure carries no bodies; keep the ones held.
                if !hot.is_empty() {
                    self.hot.clear();
                    self.hot
                        .extend(hot.into_iter().map(|output| (output.stored.index, output)));
                }
            }
            Message::Installed {
                floor_generation,
                through,
                frontiers,
            } => {
                self.target = self.target.max(through);
                if self
                    .pending_floor
                    .as_ref()
                    .is_none_or(|pending| floor_generation >= pending.generation)
                {
                    self.pending_floor = Some(PendingFloor {
                        generation: floor_generation,
                        frontiers,
                    });
                }
                self.hot.clear();
            }
            Message::Lookup { span, lookup } => self.lookup(lookup).instrument(span).await,
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
            Lookup::Block { reference, reply } => {
                let result = self.store.block(reference).await.map_err(Error::from);
                reply.send_lossy(result);
            }
            Lookup::Blocks { references, reply } => {
                let store = &self.store;
                let result = try_join_all(references.into_iter().map(|reference| async move {
                    store.block(reference).await.map_err(Error::from)
                }))
                .await;
                reply.send_lossy(result);
            }
            Lookup::BlockByDigest { digest, reply } => {
                let result = self
                    .store
                    .block_by_digest(digest)
                    .await
                    .map_err(Error::from);
                reply.send_lossy(result);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        super::tests::{Stalled, hot_output, stalled},
        *,
    };
    use commonware_runtime::{Runner as _, deterministic};

    #[test]
    fn publication_without_bodies_keeps_the_held_bodies() {
        deterministic::Runner::default().start(|context| async move {
            let Stalled {
                _catalog,
                mut promoter,
                ..
            } = stalled(&context, "promoter_hot_bodies").await;
            promoter
                .handle(Message::Published {
                    through: OutputIndex::ZERO,
                    hot: vec![hot_output(0)],
                })
                .await
                .unwrap();

            // A publication coalesced under pressure carries no bodies.
            promoter
                .handle(Message::Published {
                    through: OutputIndex::new(1),
                    hot: Vec::new(),
                })
                .await
                .unwrap();
            assert_eq!(promoter.target, Some(OutputIndex::new(1)));
            assert!(promoter.hot.contains_key(&OutputIndex::ZERO));

            promoter
                .handle(Message::Published {
                    through: OutputIndex::new(2),
                    hot: vec![hot_output(2)],
                })
                .await
                .unwrap();
            assert!(!promoter.hot.contains_key(&OutputIndex::ZERO));
            assert!(promoter.hot.contains_key(&OutputIndex::new(2)));
        });
    }
}
